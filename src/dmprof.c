#include <stdio.h>
#include <malloc.h>
#include "dmprof.h"

#undef malloc
#undef realloc
#undef free
#undef strdup
#undef calloc

#define DMPROF_LOC_FMT "%s:%d func:%s()"
#define DMPROF_LOC_ARGS(X) X->file, X->line, X->func

#define DMPROF_MEM_FMT "type:%s persist:%d addr:%p size:%li"
#define DMPROF_MEM_ARGS(X) alloc_types[X->type], X->persist, X->addr, X->size

#define dmprof_bind_error(fmt, ...)  do { \
	fprintf(stderr, "dmprof: Error, %s AT " DMPROF_LOC_FMT \
	fmt, file, line, func, __VA_ARGS__); } while (0)


typedef struct list_s list_t;
struct list_s {
	list_t *next;
};

enum {
	TYPE_UNKNOWN,
	TYPE_STRDUP,
	TYPE_MALLOC,
	TYPE_CALLOC,
	TYPE_REALLOC,
	TYPE_SENTINEL
};

const char *alloc_types[TYPE_SENTINEL] = {
	[TYPE_NONE]    = "unknown",
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
	const char *function;
}

struct dmprof_stat {
	long mem_occupied;
	long mem_persistent;
	int alloc_count;
	int free_count;
};

struct dmprof_chunk *g_alloc_list;

void dmprof_event_log(const char *tag, struct dmprof_chunk *c)
{
	printf("EVENT: %s " DMPROF_MEM_FMT "\tAT " DMPROF_LOC_FMT "\n",
		tag, DMPROF_MEM_ARGS(c), DMPROF_LOC_ARGS(c));
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

	if (item == NULL)
		return -1;

	for (	prev = t = g_alloc_list;
		t && (t != item);
		prev=t, t = t->next	);

	if (t == NULL || prev == NULL)
		return -1;

	prev->next = t->next;
	return 0;
}

struct dmprof_chunk* dmprof_find_chunk(void *p) {
	struct dmprof_chunk *t, *prev=NULL;

	if (p == NULL)
		return NULL;

	for (t = g_alloc_list; t && (t->addr != p); t = t->next);

	if (t == NULL)
		return NULL;

	return t;
}

void dmprof_mark_all_persist()
{
	struct dmprof_chunk *t;
	for (	t = g_alloc_list; t != NULL; t = t->next)
		t->persist = 1;
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
		dmprof_error("Failed to malloc %li bytes\n", size);
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

void dmprof_init(const char *log_file)
{
	// open log file and hold FD globally.
}

void dmprof_app_init_done()
{
	dmprof_mark_all_persist();
}

/*****************************************************************************/
/* Dinky Memory Profiler - application bindings                              */
/*****************************************************************************/

void *dmprof_bind_malloc(size_t size, const char *file, int line,
		const char *func)
{
	struct dmprof_chunk* chunk;
	void *p = malloc(size);
	if (p == NULL) {
		dmprof_error("Failed to malloc %li bytes\n", size);
		return NULL;
	}
	chunk = dmprof_chunk_new();
	if (chunk == NULL) {
		free(p);
		return NULL;
	}
	chunk->type = TYPE_MALLOC;
	chunk->addr = p;
	chunk->size = size;
	chunk->line = line;
	chunk->file = file;
	chunk->func = func;
	dmprof_event_log("ALLOC", chunk);
	dmprof_add(chunk);
	return p;
}

void *dmprof_bind_calloc(size_t nmemb, size_t size, const char *file,
		int line, const char *func)
{
	struct dmprof_chunk* chunk;
	void *p = calloc(nmemb, size);
	if (p == NULL) {
		dmprof_error("Failed to calloc %li bytes\n", size);
		return NULL;
	}
	chunk = dmprof_chunk_new();
	if (chunk == NULL) {
		free(p);
		return NULL;
	}
	chunk->type = TYPE_MALLOC;
	chunk->addr = p;
	chunk->size = size * nmemb;
	chunk->line = line;
	chunk->file = file;
	chunk->func = func;
	dmprof_event_log("ALLOC", chunk);
	dmprof_add(chunk);
	return p;
}

char *dmprof_bind_strdup(const char *str, const char *file,  int line,
		const char *func)
{
	char *p = strdup(str);
	if (p == NULL) {
		dmprof_bind_error("Failed to calloc %li bytes\n", size);
		return NULL;
	}
	chunk = dmprof_chunk_new();
	if (chunk == NULL) {
		free(p);
		return NULL;
	}
	chunk->type = TYPE_STRDUP;
	chunk->addr = p;
	chunk->size = strlen(str) + 1;
	chunk->line = line;
	chunk->file = file;
	chunk->func = func;
	dmprof_event_log("ALLOC", chunk);
	dmprof_add(chunk);
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
	dmprof_event_log("FREE", chunk);
	free(c);
	free(p);
}

