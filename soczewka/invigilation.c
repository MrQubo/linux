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
 * of user memory area.
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
			if (!access_ok(VERIFY_READ, cur, 1))
				goto invalid;
			unsafe_get_user(c, cur, invalid);
			if (c != s[idx])
				goto next;
		}
		goto out;
next:;
	}

invalid: // or not found
	user_access_end();
	return NULL;

out:
	user_access_end();
	return start;
}


void _print_range(unsigned long cur, unsigned long end)
{
	u8 c;

	for (; cur < end; cur++) {
		if (!access_ok(VERIFY_READ, cur, 1))
			goto invalid;
		unsafe_get_user(c, (const unsigned char __user *)cur, invalid);
		pr_cont(" %.2x", (unsigned int)c);
		goto ok;
invalid:
		pr_cont(" xx");
ok:;
	}
}

#define SOCZEWKA_VIOLATION_MSG \
	"Soczewka (tm) violation: COMM `%s' PID %i UID %u EUID %u GID %u EGID %u WORD `%s'"

void report_violation(
		unsigned long start, unsigned long end,
		int wordi, const void __user *found_v, unsigned long found_len)
{
	unsigned long found = (unsigned long)found_v;
	struct soczewka *scz = &current->soczewka;
	unsigned long cur;
	unsigned long p_end;

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
	cur = max(found - CONFIG_SOCZEWKA_BEFORE, start);
	pr_cont(" before [");
	_print_range(cur, found);
	pr_cont(" ]");
#endif

#if CONFIG_SOCZEWKA_AFTER > 0
	cur = found + found_len;
	p_end = min(found + found_len + CONFIG_SOCZEWKA_AFTER, end);
	pr_cont(" after [");
	_print_range(cur, p_end);
	pr_cont(" ]\n");
#else
	pr_cont("\n");
#endif

	user_access_end();

	/* You weren't a nice task. */
	set_user_nice(current, task_nice(current) + 1);
}


void _invigilate_noncontiguous(unsigned long start, unsigned long end)
{
	struct soczewka *scz = &current->soczewka;
	const void __user *addr = (const void __user *)start;
	unsigned long size = end - start;
	unsigned long len;
	const void __user *found;
	int wordi;

	for (wordi = 0; wordi < scz->words_count; wordi++) {
		len = strlen(scz->words[wordi]);
		found = strnstrn_user(addr, size, scz->words[wordi], len);
		if (found && !test_and_set_bit(wordi, scz->words_reported))
			report_violation(start, end, wordi, found, len);
	}
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


void _soczewka_invigilate(const void __user *addr, unsigned long size)
{
	unsigned long start;
	unsigned long end;

	if (!_do_check())
		return 0;

	start = (unsigned long)addr;
	end = start + size;

	if (unlikely(size == 0))
		return 0;

	_invigilate_noncontiguous(start, end);
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
	_soczewka_invigilate(addr, size);
}
EXPORT_SYMBOL(soczewka_invigilate);
