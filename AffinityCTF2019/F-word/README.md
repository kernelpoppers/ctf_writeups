<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->

# Affinity CTF 2019 - F-word

* **Category:** Misc
* **Points:** 200

## Challenge

### Description
```
^^^^!^^^^-A?--&-----&&^^^&^!^^^-A?^&!^^^^^-A?
--&^^!^^-----A?&-!^^^^^-A?^^&^!^^^^^-A?&^!^^^-A?
^^&!^^^-A?---&-!^---A?&^!^------A?&---!^--A?&--
!^-----A?&^^!^^^--A?&^^^^^^^^^^^^&^^^&^!^^^-A?^^
^&-------------&-!^^^--A?--&^^^!^^^^^-A?^&---!^
---A?--&--------&-----&^!^---A?^&^!^^^--A?^&^!^^
^^^--A?^&^!--^^^A?^&!^^^^^-A?--&^^^^^^^^^^^^^^&^
^^^^&-!^---A?-&&&^^!^^---A?*&
```

## Solution

When I looked at this, immediately I thought of the esoteric programming language [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck).
I knew that this had to be encoded somehow, so I began to substitute specific characters for characters in BrainFuck.

I figured this out by going to this [encoder](https://copy.sh/brainfuck/text.html) and typing the beginning of the flag AFFCTF{

The output given was:

```
----[---->+<]>++.+++++..---.>-[--->+<]>-.[----->+<]>++.>--[-->+++++<]>.
```

This matched:

```
^^^^!^^^^-A?--&-----&&^^^&^!^^^-A?^&!^^^^^-A?--&^^!^^-----A?&
```

Using substitution, I learned what each character corresponded to:

```
^ = -
! = [
- = +
? = ]>
A = <
& = .
```
NOTE: The * at the end notifies that it is the end of the flag.

Decoding the little portion above resulted in:

```
----[----+<]>++.+++++..---.-[---+<]>-.[-----+<]>++.--[--+++++<]>.
```

Notice that the ouput does not match exactly, but that is because I did not know the syntax of Brainfuck. Every time there is a switch going from `+` to `-` or `-` to `+`, there must be a `>` in between. Also, another case was putting a `>` after `.` sometimes before `[`.
I never did understand why the second case was needed, but trial and error proved to be a success.

So using the [bf_encoder](https://copy.sh/brainfuck/text.html) and [bf_emulator](https://copy.sh/brainfuck/) to run the code, I was able to come up with this decoded text after some trial and error.

```
----[---->+<]>++.+++++..---.>-[--->+<]>-.[----->+<]>++.>--
[-->+++++<]>.+[----->+<]>--.-[----->+<]>.>-[--->+<]>--.[--->+<]
>+++.+[->+++<]>.-[->++++++<]>.+++[->++<]>.++[->+++++<]>.--
[--->++<]>.------------.---.>-[--->+<]>---.+++++++++++++.+
[--->++<]>++.---[----->+<]>-.+++[->+++<]>++.++++++++.+++++.-
[->+++<]>-.-[--->++<]>-.-[----->++<]>-.-[++>---<]>-.[----->+<]
>++.--------------.-----.+[->+++<]>+...>--[-->+++<]>.
```

Run this in the [bf_emulator](https://copy.sh/brainfuck/)


### Flag

```
AFFCTF{JuSt_4n0theR_BrainF-w0rd_!!!}
```
