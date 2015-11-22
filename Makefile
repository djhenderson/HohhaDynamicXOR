# Makefile

IMAGE_SRC ?= ./images

HohhaDynamicXOR:
	gcc -Wall -Werror -D IMAGE_SRC=$(abspath $(IMAGE_SRC)) -o HohhaDynamicXOR HohhaDynamicXOR.c

clean:
	rm -f HohhaDynamicXOR.exe
	rm -f images/*_enc*.*
