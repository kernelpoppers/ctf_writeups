<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->
# CTF Name – Breaking Bad

* **Category:** Crypto
* **Points:** 150

## Challenge 

### Description

> HoRfSbMtInMcLvFlAcAmInMcAmTeErFmInHoLvDbRnMd 


## Solution

The title is "Breaking Bad" referring to the show, which involves chemistry. Because of this, chemistry deals with the [Periodic Table](https://sciencenotes.org/periodic-table-charges-118-elements/). Each of the symbols above correspond to a symbol in the table. Each element corresponds to a number within the table as well. We can take those numbers and put them in a list like this:

```
67 104 51 109 49 115 116 114 89 95 49 115 95 52 68 100 49 67 116 105 86 101
```

My first thought of what these numbers represented was decimal in the [ASCII Table](http://www.asciitable.com). Using the table, I was able to decode the flag.


## Flag

```
AFFCTF{Ch3m1strY_1s_4Dd1ctiVe}
```
