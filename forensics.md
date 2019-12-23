## ► forensics
### Initial checks

- xxd
- file
- strings
- binwalk
- foremost
- johntheripper
- [cryptograms](https://quipqiup.com/)

### Steganography

- exiftool
- strings
- steghide (try blank password)
- stegcracker
- stegdetect (JPG)
- zbarimg/zbarcam (QR-codes)
- stegoveritas
- stegsnow

- pngcheck
- Stegsolve
- jsteg (JPG LSB)
- zsteg (PNG LSB)
- tweakpng
- lsb.py

reverse image serach: http://www.tineye.com, then ```compare chall.png maxresdefault.jpg  -compose src diff.png```

some string-fu:

- ```strings chall.png```
- ```strings -el chall.png```
- ```strings chall.jpeg | awk 'length($0)>15' | sort -u```


### Audio

- audacity
- deepsound
- sonic visualizer
- [morse code](https://morsecode.scphillips.com/translator.html)

### Filesystems

- mount
- testdisk
- volatility
- extundelete

### PCAP

- wireshark
- packettotal
