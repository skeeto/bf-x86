# x86_64 Brainfuck Compiler

`bf-x86` compiles [brainfuck][bf] programs directly into tiny,
position-independent x86_64 Linux ELF programs. The resulting ELF
doesn't link to any standard libraries, instead making raw syscalls.
It can optionally execute the compiled program directly in memory like
a [JIT-compiler][jit].

The compiler employs a [peephole optimizer][peep] to produce compiled
programs that run quickly and efficiently.

## Usage

    $ bf-x86 -o hello hello.bf
    $ ./hello
    Hello, world!

## Additional Resources

* [some brainfuck fluff](http://www.hevanet.com/cristofd/brainfuck/)
* [Fast Brainfuck interpreter bff4.c](http://mazonka.com/brainf/)
* [brain------------------------------------------------------fuck.com](http://www.brain------------------------------------------------------fuck.com/)
* [Esoland Brainfuck](https://esolangs.org/wiki/Brainfuck)
* [The Brainf\*ck CPU](http://www.clifford.at/bfcpu/)
* [Přemysl Eric Janouch's compiler with IR and DWARF debugging][janouch]

[bf]: https://esolangs.org/wiki/Brainfuck
[janouch]: https://git.janouch.name/p/bfc
[jit]: http://nullprogram.com/blog/2015/03/19/
[peep]: http://en.wikipedia.org/wiki/Peephole_optimization
