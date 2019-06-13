/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#include <soczewka/globals.h>


char *soczewka;
core_param(soczewka, soczewka, charp, 0600);

int soczewka_global_words_count = 0;
EXPORT_SYMBOL(soczewka_global_words_count);

const char * soczewka_global_words[CONFIG_SOCZEWKA_MAX_WORDS] = { NULL };
EXPORT_SYMBOL(soczewka_global_words);


void __init soczewka_init_globals(void)
{
	unsigned long len;
	const char *word;
	char *cur;

	for (cur = soczewka; *cur != '\0';) {
		word = cur;
		len = 0;
		while (*cur != ',' && *cur != '\0') {
			cur++;
			len++;
		}

		if (len == 0) {
			cur++;
			continue;
		}

		if (soczewka_global_words_count == CONFIG_SOCZEWKA_MAX_WORDS) {
			pr_warn("Too many Soczewka (tm) bad words. Ignoring rest of the words.");
			break;
		}

		if (*cur != '\0') {
			*cur = '\0';
			cur++;
		}
		soczewka_global_words[soczewka_global_words_count++] = word;
	}

	init_task.soczewka.words_count = soczewka_global_words_count;
	init_task.soczewka.words = soczewka_global_words;
}
