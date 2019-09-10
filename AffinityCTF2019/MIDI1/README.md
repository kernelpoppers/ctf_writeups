<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->
# Affinity CTF 2019 – MIDI1

* **Category:** MISC
* **Points:** 50

## Challenge

### Description

plaintext plaintext everywhere....

### Files

midi.pcap

## Solution

Open the midi.pcap file with [Wireshark](https://www.wireshark.org). Go to `packet 6`. Within the details of the packet, expand `Transport Layer Security` > `TLSv1.2 - Certificate` > `Handshake Protocol: certificate` > `Certificates` > `Certificate Data`, and within the data, the flag is there in plaintext.


### Flag
```
AFFCTF{s3lf_sign3d_is_good_3nough}
```
