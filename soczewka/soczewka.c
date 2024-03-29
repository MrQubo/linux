/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bitmap.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>

#include <soczewka/soczewka.h>


void soczewka_copy_process(unsigned long clone_flags, struct task_struct *p)
{
	(void)clone_flags;

	p->soczewka._do_user_addr_fault_holds_lock = false;
	p->soczewka.words_count = current->soczewka.words_count;
	p->soczewka.words = current->soczewka.words;
	p->soczewka.padding = current->soczewka.padding;
	bitmap_zero(p->soczewka.words_reported, CONFIG_SOCZEWKA_MAX_WORDS);
}
