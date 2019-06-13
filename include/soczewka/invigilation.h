/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCZEWKA_INVIGILATE_H
#define _SOCZEWKA_INVIGILATE_H

#include <linux/kernel.h>
#include <linux/mm.h>

/**
 * Part of Soczewka (tm) system.
 *
 * User memory invigilation.
 */


#ifdef CONFIG_SOCZEWKA

void soczewka_invigilate(const void __user *addr, unsigned long size);

#else

static inline
void soczewka_invigilate(const void __user *addr, unsigned long size)
{
	(void)addr;
	(void)size;
}

#endif

#endif
