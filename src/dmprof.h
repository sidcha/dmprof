#ifndef __DMPROF_H_
#define __DMPROF_H_

#define malloc(X) dmprof_bind_malloc( X, __FILE__, __LINE__, __FUNCTION__)
#define calloc(X,Y) dmprof_bind_calloc( X, Y, __FILE__, __LINE__, __FUNCTION__)
#define strdup(X) dmprof_bind_strdup( X, __FILE__, __LINE__, __FUNCTION__)
#define realloc(X,Y) dmprof_bind_realloc( X, Y, __FILE__, __LINE__, __FUNCTION__)
#define free(X) dmprof_bind_free(X, __FILE__, __LINE__, __FUNCTION__)

void dmprof_bind_free(void *p, const char* file, int line, const char *func);
void *dmprof_bind_malloc(size_t size, const char *file, int line, const char *func);
void *dmprof_bind_calloc(size_t nmemb, size_t size, const char *file, int line, const char *func);
char *dmprof_bind_strdup(const char *str, const char *file,  int line, const char *func);

#endif
