# x86_64 Brainfuck Compiler

`bf-x86` compiles [brainfuck][bf] programs directly into tiny,
position-independent x86_64 Linux ELF programs. The resulting ELF
doesn't link to any standard libraries, instead making raw syscalls.
It can optionally execute the compiled program directly in memory like
a [JIT-compiler][jit].

The optimizer nothing more than a simple instruction compression stage
to accumulate multiple brainfuck instructions into single x86_64
instructions.

## Usage

    $ bf-x86 -o hello hello.bf
    $ ./hello
    Hello, world!

[bf]: https://esolangs.org/wiki/Brainfuck
[jit]: http://nullprogram.com/blog/2015/03/19/
