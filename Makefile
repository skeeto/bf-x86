CFLAGS = -std=c99 -Wall -Wextra -Wno-missing-field-initializers -g3 \
  -O3 -fomit-frame-pointer -fPIC

programs = bf-x86 samples/hanoi samples/mandelbrot samples/hello

all : $(programs)

bf-x86 : bf-x86.c

samples/hanoi : samples/hanoi.bf  bf-x86
samples/mandelbrot : samples/mandelbrot.bf  bf-x86
samples/hello : samples/hello.bf bf-x86

.PHONY : all clean

clean :
	$(RM) $(programs)

% : %.bf
	./$(word 2,$^) -o $@  $<
