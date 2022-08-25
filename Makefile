uname_s := $(shell uname -s)
ifeq ($(uname_s),Linux)
  libprefix=$(dir $(shell ldconfig -p | grep libyubikey.so | tr ' ' '\n' | grep / | head -n1))
  incprefix=/usr/include
  arc4lib=-lbsd
endif
ifeq ($(uname_s),Darwin)
  libprefix=/usr/local/lib
  incprefix=/usr/local/include
  arc4lib=
endif

yksoft: yksoft.c
	@cc -g3 -Wall -I$(incprefix) -L$(libprefix) -o $@ $< -lyubikey $(arc4lib)

all: yksoft

.PHONY: clean
clean:
	@rm -f yksoft
