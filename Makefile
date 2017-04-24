CC       := gcc
CC_FLAGS := -Wall

all: dirs dmprof

dirs:
	@mkdir -p bin obj

dmprof: obj/dmprof.o obj/leaky.o
	@$(CC) $(CC_FLAGS) -o $@ $^

obj/%.o: src/%.c
	@echo "Compiling $<"
	@$(CC) $(CC_FLAGS) -o "$@" -c "$<"
	
clean:
	@rm -rf bin obj
	@rm -f dmprof

.PHONY: dmprof clean dirs all
