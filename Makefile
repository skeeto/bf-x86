CFLAGS = -std=c11 -Wall -Wextra -O3 -fomit-frame-pointer

bf-x86 : bf-x86.c

.PHONY : clean

clean :
	$(RM) bf-x86
