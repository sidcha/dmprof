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
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include "dmprof.h"

#undef malloc
#undef realloc
#undef free
#undef strdup
#undef calloc

#define MAX(a,b) ({ __typeof__ (a) _a = (a); \
	           __typeof__ (b) _b = (b); \
	         _a > _b ? _a : _b; })

#define MIN(a,b) ({ __typeof__ (a) _a = (a); \
	           __typeof__ (b) _b = (b); \
	         _a > _b ? _b : _a; })

#define DMPROF_LOC_FMT "%s:%d %s() "
#define DMPROF_LOC_ARGS(X) X->file, X->line, X->func

#define DMPROF_MEM_FMT "T:%s UUID:0x%08x ALID:%010u %p[%04li] "
#define DMPROF_MEM_ARGS(X) alloc_types[X->type], X->uuid, \
		X->alloc_id, X->addr, X->size

enum {
	TYPE_UNKNOWN,
	TYPE_STRDUP,
	TYPE_MALLOC,
	TYPE_CALLOC,
	TYPE_REALLOC,
	TYPE_SENTINEL
};

enum {
	DMPLOG_DEBUG,
	DMPLOG_EVENT,
	DMPLOG_INFO,
	DMPLOG_WARN,
	DMPLOG_ERROR,
	DMPLOG_ALERT,
	DMPLOG_PANIC,
	DMPLOG_SENTINEL
};

const char *log_tags[DMPLOG_SENTINEL] = {
	[DMPLOG_DEBUG] = "DEBUG",
	[DMPLOG_EVENT] = "EVENT",
	[DMPLOG_INFO]  = "INFO",
	[DMPLOG_WARN]  = "WARN",
	[DMPLOG_ERROR] = "ERROR",
	[DMPLOG_ALERT] = "ALERT",
	[DMPLOG_PANIC] = "PANIC"
};

const char *alloc_types[TYPE_SENTINEL] = {
	[TYPE_UNKNOWN] = "unknown",
	[TYPE_STRDUP]  = "strdup ",
	[TYPE_MALLOC]  = "malloc ",
	[TYPE_CALLOC]  = "calloc ",
	[TYPE_REALLOC] = "realloc"
};

struct dmprof_chunk {
	void *next;
	int type;
	size_t size;
	void *addr;
	const char *file;
	int line;
	unsigned int uuid;
	unsigned int alloc_id;
	const char *func;
};

struct {
	char *log_file;
	long mem_occupied;
	long mem_persistent;
	unsigned int alloc_count;
	unsigned int free_count;
} dmprof_stats;

struct dmprof_chunk *g_alloc_list;
int dmprof_log_level = DMPLOG_INFO;

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

void dmprof_log(int log_level, const char *fmt, ...)
{
	if (log_level < dmprof_log_level     ||
		log_level >= DMPLOG_SENTINEL ||
		log_level < DMPLOG_DEBUG)
		return;

	FILE *fd = fopen(dmprof_stats.log_file, "a+");
	if (fd == NULL) {
		perror("Unable to open file for logging");
		return;
	}
	fprintf(fd, "%6s: ", log_tags[log_level]);
	va_list argptr;
	va_start(argptr, fmt);
	vfprintf(fd, fmt, argptr);
	va_end(argptr);
	fflush(fd);
	fclose(fd);
}

void dmprof_log_event(const char *tag, struct dmprof_chunk *c)
{
	char buf[512];
	snprintf(buf, 512, "%s" DMPROF_MEM_FMT "\tat " DMPROF_LOC_FMT "\n",
		tag, DMPROF_MEM_ARGS(c), DMPROF_LOC_ARGS(c));
	buf[511]=0;
	dmprof_log(DMPLOG_EVENT, buf);
}

void dmprof_log_status()
{
	char buf[512];
	snprintf(buf, 512, "MEM_STAT O:%li P:%li F:%li AC:%d FC:%d\n",
			dmprof_stats.mem_occupied,
			dmprof_stats.mem_persistent,
			dmprof_stats.mem_occupied - dmprof_stats.mem_persistent,
			dmprof_stats.alloc_count,
			dmprof_stats.free_count);
	buf[511]=0;
	dmprof_log(DMPLOG_INFO, buf);
}

void dmprof_log_chunk(struct dmprof_chunk *c)
{
	char buf[512];
	snprintf(buf, 512, "   |-> " DMPROF_MEM_FMT "\tALLOC from " DMPROF_LOC_FMT "\n",
		DMPROF_MEM_ARGS(c), DMPROF_LOC_ARGS(c));
	buf[512]=0;
	dmprof_log(DMPLOG_INFO, buf);
}

void dmprof_log_floating()
{
	struct dmprof_chunk *t;

	dmprof_log(DMPLOG_INFO, "Logging current allocations:\n");

	for (t=g_alloc_list; t; t=t->next) {
		dmprof_log_chunk(t);
	}
}

void dmprof_add_chunk(struct dmprof_chunk *item)
{
	struct dmprof_chunk *t;

	if (item == NULL) {
		dmprof_log(DMPLOG_ERROR, "Unable to add item to list\n");
		return;
	}

	for (	t = g_alloc_list;
		t && t->next;
		t = t->next	);

	item->next   = NULL;
	if (t == NULL)
		g_alloc_list = item;
	else
		t->next    = item;
}

int dmprof_remove_chunk(struct dmprof_chunk *c)
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
	if (prev == t) {
		g_alloc_list = prev->next;
	}
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
		dmprof_log(DMPLOG_PANIC, "New chunk, failed at malloc!\n");
		return NULL;
	}
	chunk->type = TYPE_UNKNOWN;
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

	snprintf(buf, 1024, "DMPROF:%li:%u:%s:%s:%d:%s", c->size, c->alloc_id,
		alloc_types[c->type], c->file, c->line, c->func);
	buf[1023]=0;
	c->uuid = crc32((unsigned char *)buf);
}

void dmprof_init(const char *name, const char *log_file)
{
	time_t timer;
	char time_str[26];
	struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);

	strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	dmprof_stats.log_file = strdup(log_file);
	FILE *fp = fopen(dmprof_stats.log_file, "a+");
	if (fp == NULL) {
		perror("Unable to open file for logging");
		return;
	}

	fprintf(fp, "\n\n");
	fprintf(fp, "----------------------------------------\n");
	fprintf(fp, "name: %s\n", name);
	fprintf(fp, "time: %s\n", time_str);
	fprintf(fp, "----------------------------------------\n");
	fprintf(fp, "\n\n");
	fflush(fp);
	fclose(fp);
}

void *dmprof_bind_malloc(size_t size, const char *file, int line,
		const char *func)
{
	struct dmprof_chunk* c;
	void *p = malloc(size);
	if (p == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to malloc %li bytes\n", size);
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to create dmprof_chunk."
				" new returned %p\n", c);
		free(p);
		return NULL;
	}
	c->type = TYPE_MALLOC;
	c->addr = p;
	c->size = size;
	c->line = line;
	c->file = file;
	c->func = func;
	c->alloc_id = dmprof_stats.alloc_count;

	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_chunk_set_uuid(c);
	dmprof_add_chunk(c);
	dmprof_log_event("ALLOC", c);
	return p;
}

void *dmprof_bind_calloc(size_t nmemb, size_t size, const char *file,
		int line, const char *func)
{
	struct dmprof_chunk* c;
	void *p = calloc(nmemb, size);
	if (p == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to calloc %li bytes\n", size);
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to create dmprof_chunk."
				" new returned %p\n", c);
		free(p);
		return NULL;
	}
	c->type = TYPE_MALLOC;
	c->addr = p;
	c->size = size * nmemb;
	c->line = line;
	c->file = file;
	c->func = func;
	c->alloc_id = dmprof_stats.alloc_count;


	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_chunk_set_uuid(c);
	dmprof_add_chunk(c);
	dmprof_log_event("ALLOC", c);
	return p;
}

char *dmprof_bind_strdup(const char *str, const char *file,  int line,
		const char *func)
{
	struct dmprof_chunk *c;
	char *p = strdup(str);
	if (p == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to calloc %zu bytes\n",
				strlen(str));
		return NULL;
	}
	c = dmprof_chunk_new();
	if (c == NULL) {
		dmprof_log(DMPLOG_ERROR, "Failed to create dmprof_chunk."
				" new returned %p\n", c);
		free(p);
		return NULL;
	}
	c->type = TYPE_STRDUP;
	c->addr = p;
	c->size = strlen(str) + 1;
	c->line = line;
	c->file = file;
	c->func = func;
	c->alloc_id = dmprof_stats.alloc_count;

	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += c->size;
	dmprof_chunk_set_uuid(c);
	dmprof_add_chunk(c);
	dmprof_log_event("ALLOC", c);
	return p;
}



void *dmprof_bind_realloc(void *ptr, size_t size, const char *file,
		int line, const char *func)
{
	struct dmprof_chunk *old=NULL, *new=NULL;
	size_t new_size = size;

	if (ptr != NULL) {
		old = dmprof_find_chunk(ptr);
		if (old == NULL) {
			dmprof_log(DMPLOG_ERROR, "realloc called on non alloc'd"
					" pointer %p", ptr);
			return NULL;
		}
		if (size == 0) {
			dmprof_bind_free(old->addr, __FILE__, __LINE__, __FUNCTION__);
			return NULL;
		}
		new_size = MIN(size, old->size);
	}

	void *new_ptr = malloc(new_size);
	if (new_ptr == NULL) {
		dmprof_log(DMPLOG_ERROR, "realloc failed to malloc again!"
				" asked for %lu bytes\n", new_size);
		return NULL;
	}

	if (ptr != NULL) {
		memcpy(new_ptr, old->addr, new_size);
		// Call a bind_free so the logs indicate this free.
		dmprof_bind_free(old->addr, __FILE__, __LINE__, __FUNCTION__);
	}

	new = dmprof_chunk_new();

	new->type = TYPE_REALLOC;
	new->addr = new_ptr;
	new->size = new_size;
	new->line = line;
	new->file = file;
	new->func = func;
	new->alloc_id = dmprof_stats.alloc_count;

	dmprof_stats.alloc_count++;
	dmprof_stats.mem_occupied += new->size;
	dmprof_chunk_set_uuid(new);
	dmprof_add_chunk(new);
	dmprof_log_event("ALLOC", new);
	return new_ptr;
}

void dmprof_bind_free(void *p, const char* file, int line, const char *func)
{
	struct dmprof_chunk *c = dmprof_find_chunk(p);
	if (c == NULL) {
		dmprof_log(DMPLOG_ERROR, "Free unalloc %p AT " DMPROF_LOC_FMT
				"\n", p, file, line, func);
		return;
	}
	if (dmprof_remove_chunk(c)) {
		dmprof_log(DMPLOG_ERROR, "Remove failed C:%p P:%p At "
				DMPROF_LOC_FMT "\n", c, p, file, line, func);
		dmprof_log_chunk(c);
	} 
	dmprof_stats.free_count++;
	dmprof_stats.mem_occupied -= c->size;
	dmprof_log(DMPLOG_EVENT, "FREE  " DMPROF_MEM_FMT "\tat " DMPROF_LOC_FMT
			"\n", DMPROF_MEM_ARGS(c), file, line, func);
	free(c);
}

