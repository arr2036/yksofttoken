yksoft: yksoft.c
	@cc -g3 -Wall -L /usr/local/lib -lyubikey -I /usr/local/include/ $< -o $@

all: yksoft

.PHONY: clean
clean:
	@rm -f yksoft

