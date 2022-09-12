uname_s := $(shell uname -s)
ifeq ($(uname_s),Linux)
  libprefix=$(dir $(shell ldconfig -p | grep libyubikey.so | tr ' ' '\n' | grep / | head -n1))
  incprefix=/usr/include
endif
ifeq ($(uname_s),Darwin)
  libprefix=$(shell brew --prefix)/lib
  incprefix=$(shell brew --prefix)/include
endif

yksoft: yksoft.c
	@cc -g3 -Wall -I$(incprefix) -L$(libprefix) -o $@ $< -lyubikey

all: yksoft

.PHONY: clean
clean:
	@rm -f yksoft

#
#	Build a debian package
#
.PHONY: deb
deb:
	@if ! which fakeroot > /dev/null; then \
		if ! which apt-get > /dev/null; then \
		  echo "'make deb' only works on debian systems" ; \
		  exit 1; \
		fi ; \
		echo "Please run 'apt-get install build-essential' "; \
		exit 1; \
	fi
	fakeroot debian/rules debian/control #clean
	fakeroot dpkg-buildpackage -b -uc
