---
title: "Cookie Arena"
date: 2023-11-15T01:19:58+07:00
description: "Solution for Forensics and Stegano of CookieArena challenge"
tags: [writeup, forensics, cookie-arena]
categories: ["ctf"]
author : [1]
---
<!--more-->

## 1.0x0

- Download and open the initial file, which is a regular image named "legit.png".


  ![pic1](/assets/posts/Cookie-Arena/legit.png)


- I tried using binwalk to check, and it seems there are some hidden files within it:


  ![pic2](/assets/posts/Cookie-Arena/image.png)


- Attempted to use binwalk and foremost to extract, but it seems unfeasible. I used zsteg:


  ![pic3](/assets/posts/Cookie-Arena/offset.png)


- Spent quite some time here trying to find a way to extract that data. After a while, I found a way using the 'dd' command. I used the following command to extract the data: `dd if=legit.png bs=1 skip=$((0x96ef4)) of=out`.

- Upon extraction, I noticed it was a PNG file. I removed the excess parts at the beginning, but it didn't open correctly. Used: `pngcheck -vv out`.


  ![pic4](/assets/posts/Cookie-Arena/pngcheck.png)


- Got a 0x0 error. I searched for this error online and found a post by requroku / POCKekers, solving the CTF Killer Queen 2021. It seems the height and width of the image were changed to zero. Used the following Python code to find the correct height and width:

    ```python
    from pwn import p32
    from zlib import crc32
    required_crc = 0x41305C20
    max_dimension = 4000
    for width in range(0, max_dimension):
        for height in range(0, max_dimension):
            ihdr = b'\x49\x48\x44\x52' + p32(width, endian='big') + p32(height, endian='big') + b'\x08\x06\x00\x00\x00'
            if height % 100 == 0:
                print('ihdr:', ihdr.hex())
            crc = crc32(ihdr)
            if crc == required_crc:
                print('FOUND!')
                print(width, height)
                exit()
    ```

and we found:


  ![pic5](/assets/posts/Cookie-Arena/value.png)


- Convert the values to hex and fix:


  ![pic6](/assets/posts/Cookie-Arena/changehex.png)


- Open the image again:


  ![pic7](/assets/posts/Cookie-Arena/donepng.png)


- Following the post mentioned earlier, I thought the next step was to use the stegsolve tool. Used it to check different color planes, and in the blue plane 1, we see:


  ![pic8](/assets/posts/Cookie-Arena/flag.png)


- Scanned the QR code and received the flag:   
    -> *CHH{Im4g3_1n_1m@gE_1s_n1c3!!}*
