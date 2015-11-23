# Makefile

IMAGE_SRC ?= ./images

all: HohhaDynamicXOR VisualTest Benchmarks Tests

cencoder.o:	cencoder.h cencoder.c
	gcc -Wall -Werror -c cencoder.c

HohhaDynamicXOR:	HohhaDynamicXOR.h HohhaDynamicXOR.c
	gcc -Wall -Werror -DIMAGE_SRC=\"$(abspath $(IMAGE_SRC))\" \
		-DNO_VISUAL -DNO_BENCH -DNO_TESTS \
		-o HohhaDynamicXOR HohhaDynamicXOR.c

VisualTest:	HohhaDynamicXOR.h HohhaDynamicXOR.c VisualTest.c cencoder.h cencoder.o
	gcc -Wall -Werror -DIMAGE_SRC=\"$(abspath $(IMAGE_SRC))\" \
		-DNO_MAIN -DNO_VISUAL -DNO_BENCH -DNO_TESTS \
		-o VisualTest HohhaDynamicXOR.c VisualTest.c cencoder.o

Benchmarks:	HohhaDynamicXOR.h HohhaDynamicXOR.c Benchmarks.c
	gcc -Wall -Werror -DIMAGE_SRC=\"$(abspath $(IMAGE_SRC))\" \
		-DNO_MAIN -DNO_VISUAL -DNO_BENCH -DNO_TESTS \
		-o Benchmarks HohhaDynamicXOR.c Benchmarks.c

Tests:	HohhaDynamicXOR.h HohhaDynamicXOR.c Tests.c cencoder.h cencoder.o
	gcc -Wall -Werror -DIMAGE_SRC=\"$(abspath $(IMAGE_SRC))\" \
		-DNO_MAIN -DNO_VISUAL -DNO_BENCH -DNO_TESTS \
		-o Tests HohhaDynamicXOR.c Tests.c cencoder.o

clean:
	rm -f *.exe *.o
	rm -f images/*_enc*.*
