CC       := gcc
CC_FLAGS := -Wall

all: dirs dmprof

dirs:
	@mkdir -p obj

dmprof: obj/dmprof.o obj/leaky.o
	@$(CC) $(CC_FLAGS) -o $@ $^

obj/%.o: src/%.c
	@echo "Compiling $<"
	@$(CC) $(CC_FLAGS) -o "$@" -c "$<"
	
clean:
	@rm -rf obj
	@rm -f dmprof *.dmprof

.PHONY: dmprof clean dirs all
