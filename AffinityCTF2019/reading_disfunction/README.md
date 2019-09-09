<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->

# Affinity CTF 2019 - Reading Disfunction

* **Category:** Misc
* **Points:** 150

## Challenge

### Description
> nc 165.22.22.11 9999

## Solution

After connecting, the following text was printed, and the program waited for user input.

```
andrew@WOPR /tmp % nc 165.22.22.11 9999
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++++.------------.-------.+++++++++++++++++++.<<++.>>+++.---------------.-------.+++++++++++++++++++.<<.>>-------------------.+++++++++++++++++.-------------.<<.>>++++++++++++++++++++.----------.++++++.<<.>>---------.+++..----.--.+++++.-------.<<.>>-.+++++++++.+++.<<.>>---------.++++++++++.<<.>>----------.+++++.<<.>>-----------.++.+++++++..<<.>------------------.----.<+.
```

I recognized this to be the esoteric programming language [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck).  There are many different browser-based emulators online for running and inspecting Brainfuck code, but I quite like [this one](http://fatiherikli.github.io/brainfuck-visualizer/).

When run, the code printed the text: `that what are you looking for is in cell 40!`.  I theorized that the program now expected me to enter my own Brainfuck code.  Cell 40 should be reachable with 41 `>` characters (indexes start at 0, so index 40 is the 41st cell).  We can then print the data in that cell with the `.` character.  Running this produced a single `A`.

```
andrew@WOPR /tmp % python2 -c 'print ">"*41 + ".";' | nc 165.22.22.11 9999
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++++.------------.-------.+++++++++++++++++++.<<++.>>+++.---------------.-------.+++++++++++++++++++.<<.>>-------------------.+++++++++++++++++.-------------.<<.>>++++++++++++++++++++.----------.++++++.<<.>>---------.+++..----.--.+++++.-------.<<.>>-.+++++++++.+++.<<.>>---------.++++++++++.<<.>>----------.+++++.<<.>>-----------.++.+++++++..<<.>------------------.----.<+.
A
andrew@WOPR /tmp % 
```

Since the flag format was `AFFCTF{...}` I guessed that the rest of the flag could be found in the subsequent cells.  We can move to the next cell with another `>` character, and again, print the cell with a `.` character.  I wasn't sure how long it would be, but 100 characters should be plenty.  This printed the flag!

```
andrew@WOPR /tmp % python2 -c 'print ">"*41 + ".>"*100;' | nc 165.22.22.11 9999
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++++.------------.-------.+++++++++++++++++++.<<++.>>+++.---------------.-------.+++++++++++++++++++.<<.>>-------------------.+++++++++++++++++.-------------.<<.>>++++++++++++++++++++.----------.++++++.<<.>>---------.+++..----.--.+++++.-------.<<.>>-.+++++++++.+++.<<.>>---------.++++++++++.<<.>>----------.+++++.<<.>>-----------.++.+++++++..<<.>------------------.----.<+.
AFFCTF{!s_th!s_th3_r3@l_l!f3__or__!s_th!s_just_f@nt@sy___}
andrew@WOPR /tmp % 
```

### Flag

```
AFFCTF{!s_th!s_th3_r3@l_l!f3__or__!s_th!s_just_f@nt@sy___}
```
