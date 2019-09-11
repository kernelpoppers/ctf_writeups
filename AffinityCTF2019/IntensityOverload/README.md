<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->
# Affinity CTF 2019 – Intensity Overload

* **Category:** Stego
* **Points:** 700

## Challenge

###Description
https://www.youtube.com/watch?v=7xxgRUyzgs0

### Files

[IntensityOverload.png](IntensityOverload.png)

## Solution

Youtube video brings you to a video of the band 'Living Colour's' song 'Cult of Personality'. So there is no easy way to approach this challenge. The way I was able to get this challenge so fast was that I had seen a version similar to this before and recognized it immediately. So I trusted my gut and tried it out, the solution here is that every color's hex value corresponds to a character. Going through you will get:

5f 63 75 6c 74 5f 30 66 5f 70 34 72 73 30 6e 40 6c 21 74 79
or converted from hex
'_cult_0f_p4rs0n@l!ty'

Then after some testing all you have to do is remove the first underscore



### Flag
```
AFFCTF{cult_0f_p4rs0n@l!ty}
```
