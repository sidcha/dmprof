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

void free_struct(struct my_struct *s)
{
	free(s);
	// strdup lost!
}

int main()
{
	dmprof_init("Leak Test", "leaky.dmprof");

	int *a = malloc(sizeof(int));
	int *b = malloc(sizeof(int));
	int *b = malloc(sizeof(int));

	dmprof_init_done();

	*a = 10;
	while(*a) {
		struct my_struct *s = make_struct("Hello");
		free_struct(s);
		sleep(1);
		*a--;
		dmprof_log_status();
	}
	return 0;
}
