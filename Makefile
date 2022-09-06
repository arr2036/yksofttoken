uname_s := $(shell uname -s)
ifeq ($(uname_s),Linux)
  libprefix=$(dir $(shell ldconfig -p | grep libyubikey.so | tr ' ' '\n' | grep / | head -n1))
  incprefix=/usr/include
  arc4lib=-lbsd
endif
ifeq ($(uname_s),Darwin)
  libprefix=$(shell brew --prefix)/lib
  incprefix=$(shell brew --prefix)/include
  arc4lib=
endif

#
#	Build a debian package
#
.PHONY: deb
deb:
	@if ! which fakeroot; then \
		if ! which apt-get; then \
		  echo "'make deb' only works on debian systems" ; \
		  exit 1; \
		fi ; \
		echo "Please run 'apt-get install build-essentials' "; \
		exit 1; \
	fi
	fakeroot debian/rules debian/control #clean
	fakeroot dpkg-buildpackage -b -uc


yksoft: yksoft.c
	@cc -g3 -Wall -I$(incprefix) -L$(libprefix) -o $@ $< -lyubikey $(arc4lib)

all: yksoft

.PHONY: clean
clean:
	@rm -f yksoft
