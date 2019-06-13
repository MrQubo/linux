/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCZEWKA_SOCZEWKA_H
#define _SOCZEWKA_SOCZEWKA_H

/**
 * Part of Soczewka (tm) system.
 *
 * User memory invigilation.
 */


#ifdef CONFIG_SOCZEWKA

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/sched.h>

struct soczewka {
	bool _do_user_addr_fault_holds_lock;
	unsigned int words_count;
	const char *const *words;
	unsigned long padding;
	DECLARE_BITMAP(words_reported, CONFIG_SOCZEWKA_MAX_WORDS);
} __randomize_layout;

#define INIT_SOCZEWKA { \
	._do_user_addr_fault_holds_lock = false, \
	.words_count = 0, \
	.words = NULL, \
	.padding = 0, \
	.words_reported = { \
		[0 ... BITS_TO_LONGS(CONFIG_SOCZEWKA_MAX_WORDS) - 1] = 0, \
	} \
}

void soczewka_copy_process(unsigned long clone_flags, struct task_struct *dest);

#else

static inline
void soczewka_copy_process(unsigned long clone_flags, struct task_struct *dest)
{
	(void)clone_flags;
	(void)dest;
}

#endif

#endif
