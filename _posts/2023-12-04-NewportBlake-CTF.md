---
title: "NewportBlake CTF 2023"
date: 2023-12-04T02:16:50+07:00
# description: "Solution for NBCTF 2023 challenges" 
tags: [misc, osint]
categories: [ctf]
author: [1]
image: https://ctftime.org/media/cache/c4/f9/c4f96272360aeafabf3eb30370379c8f.png
---

CTF tournaments usually on weekends shorten my sleep time. But they're worth staying up late, aren't they? NewportBlake takes place at 7 AM on Dec 2, 2023 — ending at the same time Dec 4,2023 (ICT). I didn't do much, there were only two and they were pretty easy.

# Solution

## 1. Miscellnous/Do-you-hear-that ?

- Use `binwalk` to check the image file. Realizing that there is 1 TIFF file, I used `zsteg` to check further, it is 1 WAVE audio file. 
- Use `foremost` to extract the file. Next, use `audacity` to view sound waves in spectrogram form. Get the flag :

    ![Smile](/assets/posts/NBCTF2023/Miscellanous/Do-you-hear-that/flag.png)

FLAG: *nbctf{y0u_h4v3_s0m3_g00d_34rs}* 

## 2. Osint/Webcam
- This is my first time doing 1 OSINT challenge. The challenge gives us 3 photos (see at Github). 

- I was juggling between Japanese and Korean, so I decided to ask my girlfriend (most of the text in the picture is translated by her haha). It's Korean, in the second photo, the most notable thing is 1 dental hospital, and it's located in Seoul. I used the phrase " 김내과의원 " - Kim Internal Medicine Clinic to search on FB and found 1 clear photo of it (I originally searched on the web but it looks like it's another address).

    ![Smile](/assets/posts/NBCTF2023/Osint/fb-images.jpg)
- I looked up it phones number on the web and saw [this website](https://www.saeob.com/%EC%84%9C%EC%9A%B8%EC%B9%98%EA%B3%BC_9V-031-542-6600#google_vignette) and specific address. 

    ![Smile](/assets/posts/NBCTF2023/Osint/clinic.png)
- Then use GG map to check the location. Really the position on the photo. I tapped the first photo and realized it was a phone number. Search the web and I found [this site](https://tel.nett.kr/%EC%97%85%EC%B2%B4%EC%A0%95%EB%B3%B4/173484/%EB%8A%98%EB%B0%A9%EC%95%97%EA%B0%84/) :

    ![Smile](/assets/posts/NBCTF2023/Osint/first-web.png)
- Include the address, search on gg map and compare with Kim Internal Medicine Clinic's address and get the coordinates : 

FLAG: *nbctf{37.827_127.145}*

- There is 1 other way that I used Bing AI. Unexpectedly, he had read the address from the photo. I asked him for the same address and it took me to 1 website of that store([it here](https://www.bizno.net/article/1270398469)), which had both the address,phone number, photo... Just search for it on the map and get the coordinates.

    ![Smile](/assets/posts/NBCTF2023/Osint/location.png)