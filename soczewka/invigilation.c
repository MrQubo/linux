/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include <soczewka/invigilation.h>

/**
 * Part of Soczewka (tm) system.
 *
 * User memory invigilation.
 *
 * In this module we could skip invigilation for words for which violation was
 * alredy reported but this would make violating processes run faster than good
 * ones.
 */


/* Returns first occurrence of string [s, s+len) in the range [addr, addr+size)
 * of user memory area. Caller must ensure that whole range is a valid user
 * memory area (as returned by access_ok()).
 */
const void __user *
strnstrn_user(
		const void __user *addr, unsigned long size,
		const char *s, unsigned long len)
{
	const char __user *start;
	const char __user *cur;
	unsigned long idx;
	char c;

	user_access_begin();

	for (start = addr; size >= len; start++, size--) {
		for (cur = addr, idx = 0; idx < len; cur++, idx++) {
			BUG_ON(cur < addr || cur >= addr + size); // TODO: DEBUG
			unsafe_get_user(c, cur, efault);
			if (c != s[idx])
				goto next;
		}
		goto out;
next:;
	}

efault: // or not found
	user_access_end();
	return NULL;

out:
	user_access_end();
	return start;
}


unsigned long
_find_contiguous_end(struct vm_area_struct *vma, unsigned long end)
{
	while (
			vma->vm_next && vma->vm_end < end
			&& vma->vm_next->vm_start == vma->vm_end
	)
		vma = vma->vm_next;

	return min(vma->vm_end, end);
}


/* Look up the first VMA which satisfies addr < vm_end, vma must satisfy this.
 */
struct vm_area_struct *
_find_vma_prev_linear(struct vm_area_struct *vma, unsigned long addr)
{
	while (vma->vm_prev && vma->vm_prev->vm_end > addr)
		vma = vma->vm_prev;

	return vma;
}


#define SOCZEWKA_VIOLATION_MSG \
	"Soczewka (tm) violation: COMM `%s' PID %i UID %u EUID %u GID %u EGID %u WORD `%s'"

void report_violation(
		struct vm_area_struct *vma_found,
		unsigned long start, unsigned long end,
		int wordi, const void __user *found_v, unsigned long found_len)
{
	unsigned long found = (unsigned long)found_v;
	struct soczewka *scz = &current->soczewka;
	struct vm_area_struct *vma;
	unsigned long cur;
	unsigned long p_end;
	u8 c;

	pr_notice(SOCZEWKA_VIOLATION_MSG
			, current->comm
			, task_pid_nr(current)
			, from_kuid_munged(&init_user_ns, current_uid())
			, from_kuid_munged(&init_user_ns, current_euid())
			, from_kgid_munged(&init_user_ns, current_gid())
			, from_kgid_munged(&init_user_ns, current_egid())
			, scz->words[wordi]);

	user_access_begin();

#if CONFIG_SOCZEWKA_BEFORE > 0
	cur = found - CONFIG_SOCZEWKA_BEFORE;
	pr_cont(" before [");
#ifndef CONFIG_SOCZEWKA_ACCESS_NEIGHBOUR
	for (; cur < start; cur++)
		pr_cont(" ??");
#endif
	vma = _find_vma_prev_linear(vma_found, cur);
	while (cur < found) {
		if (cur < vma->vm_start) {
before_invalid_check:
			pr_cont(" xx");
			cur++;
		} else if (cur < vma->vm_end) {
			unsafe_get_user(c, (const unsigned char __user *)cur
					, before_invalid_check);
			pr_cont(" %.2x", (unsigned int)c);
			cur++;
		} else {
			vma = vma->vm_next;
		}
	}
	pr_cont(" ]");
#endif

#if CONFIG_SOCZEWKA_AFTER > 0
	cur = found + found_len;
	vma = vma_found;
	p_end = found + found_len + CONFIG_SOCZEWKA_AFTER;
#ifndef CONFIG_SOCZEWKA_ACCESS_NEIGHBOUR
	p_end = min(p_end, end);
#endif
	pr_cont(" after [");
	while (cur < p_end) {
		if (cur < vma->vm_start) {
after_invalid_check:
			pr_cont(" xx");
			cur++;
		} else if (cur < vma->vm_end) {
			unsafe_get_user(c, (const unsigned char __user *)cur
					, after_invalid_check);
			pr_cont(" %.2x", (unsigned int)c);
			cur++;
		} else {
			vma = vma->vm_next;
		}
	}
#ifndef CONFIG_SOCZEWKA_ACCESS_NEIGHBOUR
	for (; cur < found + found_len + CONFIG_SOCZEWKA_AFTER; cur++)
		pr_cont(" ??");
#endif
	pr_cont(" ]\n");
#else
	pr_cont("\n");
#endif

	/* You weren't a nice task. */
	set_user_nice(current, task_nice(current) + 1);

	user_access_end();
}


void _invigilate_vma(
		struct vm_area_struct *vma,
		unsigned long start, unsigned long end)
{
	struct soczewka *scz = &current->soczewka;
	unsigned long v_start = max(vma->vm_start, start);
	const void __user *addr = (const void __user *)v_start;
	unsigned long v_end;
	unsigned long size;
	unsigned long len;
	const void __user *found;
	int wordi;

	v_end = _find_contiguous_end(vma, end);

	for (wordi = 0; wordi < scz->words_count; wordi++) {
		len = strlen(scz->words[wordi]);
		size = min(v_end - v_start, vma->vm_end + len - 1);
		found = strnstrn_user(addr, size, scz->words[wordi], len);
		if (found && !test_and_set_bit(wordi, scz->words_reported))
			report_violation(vma, start, end, wordi, found, len);
	}
}


int
_invigilate_noncontiguous(unsigned long start, unsigned long end, bool killable)
{
	struct soczewka *scz = &current->soczewka;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	/* if (killable) {
	 *         if (down_read_killable(&mm->mmap_sem))
	 *                 return -EINTR;
	 * } else {
	 *         down_read(&mm->mmap_sem);
	 * } */
	down_read(&mm->mmap_sem);
	scz->_do_user_addr_fault_holds_lock = true;

	for (
			vma = find_vma(current->mm, start);
			vma && end > vma->vm_start;
			vma = vma->vm_next
	)
		_invigilate_vma(vma, start, end);

	scz->_do_user_addr_fault_holds_lock = false;
	up_read(&mm->mmap_sem);
	return 0;
}


bool _do_check(void)
{
	struct soczewka *scz = &current->soczewka;

	/* We have no words to search for. */
	if (!scz->words_count)
		return false;

	/* Check if current task had been granted an immunity. We use
	 * has_capability() instead of capable(), cause we don't want to set
	 * PF_SUPERPRIV flag.
	 */
	if (has_capability(current, CAP_SYS_SOCZEWKA_IMMUNE))
		return false;

	return true;
}


int
_soczewka_invigilate(const void __user *addr, unsigned long size, bool killable)
{
	struct soczewka *scz = &current->soczewka;
	unsigned long start;
	unsigned long end;

	if (!_do_check())
		return 0;

	start = (unsigned long)addr;
	end = start + size;

#ifdef CONFIG_SOCZEWKA_ACCESS_NEIGHBOUR
	if (unlikely(size == 0) && scz->padding == 0)
		return 0;

	start -= scz->padding;
	end +- scz->padding;
#else
	(void)scz;

	if (unlikely(size == 0))
		return 0;
#endif

	return _invigilate_noncontiguous(start, end, killable);
}


/**
 * soczewka_invigilate: invigilate user memory region
 *
 * Invigilates given user memory region. It doesn't need to be contiguously
 * mapped. This function will also pad given memory region to not miss out bad
 * words on boundary of a region. May sleep.
 */
void soczewka_invigilate(const void __user *addr, unsigned long size)
{
	_soczewka_invigilate(addr, size, false);
}
EXPORT_SYMBOL(soczewka_invigilate);


/**
 * soczewka_invigilate_killable: invigilate user memory region
 *
 * Invigilates given user memory region. It doesn't need to be contiguously
 * mapped. This function will also pad given memory region to not miss out bad
 * words on boundary of a region. May sleep.
 */
int soczewka_invigilate_killable(const void __user *addr, unsigned long size)
{
	return _soczewka_invigilate(addr, size, true);
}
EXPORT_SYMBOL(soczewka_invigilate_killable);


/**
 * soczewka_invigilate: invigilate user memory
 *
 * Invigilates whole user memory. May sleep.
 */
void soczewka_invigilate_wholemm(void)
{
	if (!_do_check())
		return;

	_invigilate_noncontiguous(0, LONG_MAX, false);
}
EXPORT_SYMBOL(soczewka_invigilate_wholemm);
