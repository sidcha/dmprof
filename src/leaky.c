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
 *     File: leaky.c
 *   Author: Siddharth Chandrasekaran
 *    Email: siddharth@embedjournal.com
 *     Date: 24 April 2017
 *
 */

#include <stdio.h>
#include <unistd.h>
#include "dmprof.h"

struct my_struct {
	int num;
	float data;
	char *str;
};

struct my_struct* make_struct(const char *st)
{
	struct my_struct *s = malloc(sizeof(struct my_struct));
	if (s == NULL)
		return NULL;
	s->str = strdup(st);
	s->num = 133;
	s->data = 22/7;
	return s;
}

void free_struct(struct my_struct * volatile s)
{
	free(s);
	// strdup lost!
}

int main()
{
	int i;
	struct my_struct * s[10];

	dmprof_init("Leak Test", "leaky.dmprof");

	int *a = malloc(sizeof(int));
	int *b = malloc(sizeof(int));

	dmprof_app_init_done();

	*b = 0;
	*a = 10;
	dmprof_log_status();
	while(*b < *a) {
		printf("Loop Count: %d\n", *b);
		s[*b] = make_struct("Hello");
		(*b)++;
	}
	dmprof_log_floating();
	free(a);
	free(b);
	free(b);
	dmprof_log_status();

	s[4] = realloc(s[4], 100);

	dmprof_log_status();

	for (i=0; i<9; i++) {
		free_struct(s[i]);
	}
	// s[9] not free'd
	dmprof_log_status();
	return 0;
}
