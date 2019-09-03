#!/bin/bash

#neko meow.n flag_enc.png flag_dec0.png

for ((i = 1 ; i < 10000 ; i++)); do
  let k=$i-1
  neko meow.n flag_dec$k.png flag_dec$i.png
done

