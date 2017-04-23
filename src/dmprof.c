/*
 *   dmprof - A dinky memory profiler.
 *   Copyright (C) 2017 Siddharth Chandrasekaran
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *     File: dmprof.c
 *   Author: Siddharth Chandrasekaran
 *    Email: siddharth@embedjournal.com
 *     Date: 23 April 2017
 *
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include "dmprof.h"

#undef malloc
#undef realloc
#undef free
#undef strdup
#undef calloc

#define DMPROF_LOC_FMT "%s:%d func:%s() "
#define DMPROF_LOC_ARGS(X) X->file, X->line, X->func

#define DMPROF_MEM_FMT "type:%s persist:%d addr:%p size:%li "
#define DMPROF_MEM_ARGS(X) alloc_types[X->type], X->persist, X->addr, X->size

#define dmprof_bind_error(fmt, ...)  do { \
	fprintf(stderr, "dmprof: Error, AT " DMPROF_LOC_FMT fmt, \
			file, line, func, __VA_ARGS__); } while (0)

enum {
	TYPE_UNKNOWN,
	TYPE_STRDUP,
	TYPE_MALLOC,
	TYPE_CALLOC,
	TYPE_REALLOC,
	TYPE_SENTINEL
};

const char *alloc_types[TYPE_SENTINEL] = {
	[TYPE_UNKNOWN] = "unknown",
	[TYPE_STRDUP]  = "strdup",
	[TYPE_MALLOC]  = "malloc",
	[TYPE_CALLOC]  = "calloc",
	[TYPE_REALLOC] = "realloc"
};

struct dmprof_chunk {
	void *next;
	int type;
	size_t size;
	void *addr;
	int persist;
	const char *file;
	int line;
	unsigned int uuid;
	const char *func;
};

struct {
	long mem_occupied;
	long mem_persistent;
	int alloc_count;
	int free_count;
} dmprof_stats;

FILE *log_file = NULL;
struct dmprof_chunk *g_alloc_list;

unsigned reverse(unsigned int x) {
	x = ((x & 0x55555555) <<  1) | ((x >>  1) & 0x55555555);
	x = ((x & 0x33333333) <<  2) | ((x >>  2) & 0x33333333);
	x = ((x & 0x0F0F0F0F) <<  4) | ((x >>  4) & 0x0F0F0F0F);
	x = (x << 24) | ((x & 0xFF00) << 8) |
		((x >> 8) & 0xFF00) | (x >> 24);
	return x;
}

unsigned int crc32(unsigned char *message) {
	int i, j;
	unsigned int byte, crc;

	i = 0;
	crc = 0xFFFFFFFF;
	while (message[i] != 0) {
		byte = message[i];            // Get next byte.
		byte = reverse(byte);         // 32-bit reversal.
		for (j = 0; j <= 7; j++) {    // Do eight times.
			if ((int)(crc ^ byte) < 0)
				crc = (crc << 1) ^ 0x04C11DB7;
			else crc = crc << 1;
			byte = byte << 1;     // Ready next msg bit.
		}
		i = i + 1;
	}
	return reverse(~crc);
}

void dmprof_event_log(const char *tag, struct dmprof_chunk *c)
{
	fprintf(log_file, "EVENT: %s " DMPROF_MEM_FMT "\tAT " DMPROF_LOC_FMT "\n",
		tag, DMPROF_MEM_ARGS(c), DMPROF_LOC_ARGS(c));
	fflush(log_file);
}

void dmprof_log_status()
{
	fprintf(log_file, "STATUS: OCC:%li PER:%li FLT: %li AC:%d FC:%d",
			dmprof_stats.mem_occupied,
			dmprof_stats.mem_persistent,
			dmprof_stats.mem_occupied - dmprof_stats.mem_persistent,
			dmprof_stats.alloc_count,
			dmprof_stats.free_count);
	fflush(log_file);
}

void dmprof_print_chunk(struct dmprof_chunk *c)
{
	fprintf(stderr, "\t" DMPROF_MEM_FMT " ALLOC FROM " DMPROF_LOC_FMT "\n",
		DMPROF_MEM_ARGS(c), DMPROF_LOC_ARGS(c));
}

void dmprof_add(struct dmprof_chunk *item)
{
	struct dmprof_chunk *t;

	if (item == NULL)
		return;

	for (	t = g_alloc_list;
		t && t->next;
		t = t->next	);

	item->next   = NULL;
	if (t == NULL)
		g_alloc_list = item;
	else
		t->next    = item;
}

int dmprof_remove(struct dmprof_chunk *c)
{
	struct dmprof_chunk *t, *prev=NULL;

	if (c == NULL)
		return -1;

	for (	prev = t = g_alloc_list;
		t && (t != c);
		prev=t, t = t->next	);

	if (t == NULL || prev == NULL)
		return -1;

	prev->next = t->next;
	return 0;
}

struct dmprof_chunk* dmprof_find_chunk(void *p) {
	struct dmprof_chunk *t;

	if (p == NULL)
		return NULL;

	for (t = g_alloc_list; t && (t->addr != p); t = t->next);

	if (t == NULL)
		return NULL;

	return t;
}

/*
 * Returns: malloc allocated pointer or null. 
 *          Must be free-ed by caller.
 */
struct dmprof_chunk *dmprof_chunk_new()
{
	struct dmprof_chunk* chunk;
	chunk = malloc(sizeof(struct dmprof_chunk));
	if (chunk == NULL) {
		dmprof_bind_error("Failed to malloc %li bytes\n", size);
		return NULL;
	}
	chunk->type = TYPE_UNKNOWN;
	chunk->persist = 0;
	chunk->addr = NULL;
	chunk->size = 0;
	chunk->line = 0;
	chunk->file = "\0";
	chunk->func = "\0";
	return chunk;
}

void dmprof_chunk_set_uuid(struct dmprof_chunk *c)
{
	char buf[1024] = {0};

	snprintf(buf, 1024, "%li:%s:%s:%d:%s()", c->size,
		alloc_types[c->type], c->file, c->line, c->func);

	c->uuid = crc32((unsigned char *)buf);
}

void dmprof_init(const char *name, const char *file)
{
	time_t timer;
	char time_str[26];
	struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);

	strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	log_file = fopen(file, "a+");
	if (log_file == NULL) {
		perror("Unable to open file for logging");
		return;
	}


	fprintf(log_file, "\n\n");
	fprintf(log_file, "----------------------------------------\n");
	fprintf(log_file, "name: %s\n", name);
	fprintf(log_file, "time: %s\n", time_str);
	fprintf(log_file, "----------------------------------------\n");
	fprintf(log_file, "\n\n");
	fflush(log_file);
}

void dmprof_app_init_done()
{
	struct dmprof_chunk *t;
	for (	t = g_alloc_list; t != NULL; t = t->next)
		t->persist = 1;
	dmprof_stats.mem_persistent = dmprof_stats.mem_occupied;
}

/*****************************************************************************/
/* Application program bindings                                              */
/*****************************************************************************/

void *dmprof_bind_malloc(size_t size, const char *file, int line,
		const char *func)
{
	struct dmprof_chunk* c;
	void *p = malloc(size);
	if (p == NULL) {
		dmprof_error("Failed to malloc %li bytes\n", size);
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		free(p);
		return NULL;
	}
	c->type = TYPE_MALLOC;
	c->addr = p;
	c->size = size;
	c->line = line;
	c->file = file;
	c->func = func;

	dmprof_event_log("ALLOC", c);
	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_add(c);
	return p;
}

void *dmprof_bind_calloc(size_t nmemb, size_t size, const char *file,
		int line, const char *func)
{
	struct dmprof_chunk* c;
	void *p = calloc(nmemb, size);
	if (p == NULL) {
		dmprof_error("Failed to calloc %li bytes\n", size);
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		free(p);
		return NULL;
	}
	c->type = TYPE_MALLOC;
	c->addr = p;
	c->size = size * nmemb;
	c->line = line;
	c->file = file;
	c->func = func;

	dmprof_event_log("ALLOC", c);
	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_add(c);
	return p;
}

char *dmprof_bind_strdup(const char *str, const char *file,  int line,
		const char *func)
{
	struct dmprof_chunk *c;
	char *p = strdup(str);
	if (p == NULL) {
		dmprof_bind_error("Failed to calloc %li bytes\n", size);
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		free(p);
		return NULL;
	}
	c->type = TYPE_STRDUP;
	c->addr = p;
	c->size = strlen(str) + 1;
	c->line = line;
	c->file = file;
	c->func = func;

	dmprof_event_log("ALLOC", c);
	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_add(c);
	return p;
}

void dmprof_bind_free(void *p, const char* file, int line, const char *func)
{
	struct dmprof_chunk *c = dmprof_find_chunk(p);
	if (c == NULL) {
		dmprof_bind_error("Free unalloc %p\n", p);
		free(p);
		return;
	}
	if (dmprof_remove(c)) {
		dmprof_bind_error("Remove failed on chunk:\n");
		dmprof_print_chunk(c);
	}
	if (c->persist) {
		dmprof_bind_error("Free on persistent chunk:\n");
		dmprof_print_chunk(c);
	}
	dmprof_event_log("FREE", c);
	dmprof_stats.free_count++;
	dmprof_stats.mem_occupied -= c->size;
	free(c);
	free(p);
}

