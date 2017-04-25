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
 *     File: dmprof.h
 *   Author: Siddharth Chandrasekaran
 *    Email: siddharth@embedjournal.com
 *     Date: 23 April 2017
 *
 */

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
void *dmprof_bind_realloc(void *ptr, size_t size, const char *file, int line, const char *func);

void dmprof_init(const char *name, const char *file);
void dmprof_app_init_done();
void dmprof_log_status();
void dmprof_log_floating();

#endif
