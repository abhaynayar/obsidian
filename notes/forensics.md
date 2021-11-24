# ► forensics
## Resources

- https://github.com/stuxnet999/MemLabs
- https://stuxnet999.github.io/
- https://www.13cubed.com/

## Initial checks

- mediainfo
- xxd
- file
- strings
- binwalk
- foremost
- johntheripper
- [cryptograms](https://quipqiup.com/)

## Steganography

- exiftool
- strings
- steghide (try blank password) `$ steghide --extract -sf matryoshka.png`
- stegcracker
- stegdetect (JPG)
- zbarimg/zbarcam (QR-codes)
- stegoveritas
- stegsnow
- pngcheck
- Stegsolve
- tweakpng

### LSB steganography

- lsb.py
- jsteg (JPG LSB)
- zsteg (PNG LSB)
- <https://stylesuxx.github.io/steganography/>
- NaCTF Phuzzy Photo

```
from PIL import Image

ip = Image.open('The_phuzzy_photo.png')
op = Image.new('RGB', (ip.size[0], ip.size[1]))
op.putdata(list(ip.getdata())[::6])
op.show()
```

Reverse image search: http://www.tineye.com, then `compare chall.png maxresdefault.jpg  -compose src diff.png`

Some string-fu:

- `strings chall.png`
- `strings -el chall.png`
- `strings chall.jpeg | awk 'length($0)>15' | sort -u`

## Audio

- audacity
- deepsound
- sonic visualizer
- [morse code](https://morsecode.scphillips.com/translator.html)

## Filesystems

- fsck
- foremost `animals.dd`
- mount
- testdisk
- volatility
- extundelete

## PCAP

- wireshark
- packettotal

## Tips

- Somtimes you can get the flag by `$ strings file.pcap | grep picoCTF`
- When you have a deep tree of sub-directories `riceteacatpanda19.treeeeeeee`
- `find ~/Downloads/ -type f -print0 | xargs -0 mv -t ~/Videos`
