/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCZEWKA_GLOBALS_H
#define _SOCZEWKA_GLOBALS_H

#include <linux/kernel.h>


#ifdef CONFIG_SOCZEWKA

extern int soczewka_global_words_count;

extern const char * soczewka_global_words[CONFIG_SOCZEWKA_MAX_WORDS];

extern unsigned long soczewka_global_padding;

void __init soczewka_init_globals(void);

#endif

#endif
