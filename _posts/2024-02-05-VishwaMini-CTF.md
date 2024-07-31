---
title: "VishwaMini CTF 2024"
date: 2024-02-05T00:20:50+07:00
# description: "Solution for VishwaMini CTF 2024 challenges" 
tags: [osint, forensics]
categories: [ctf]
author : [1]
image: https://th.bing.com/th/id/OIP.XsnIyQnnE0Ja3DuT2oJx1AHaHa?rs=1&pid=ImgDetMain
---

I've been waiting a long time to participate in a CTF tournament since IrisCTF in January. The days passed without CTF slowly like "waiting for the fish to take the bait" haha. Anyway, it's time for me to look back at myself. In this tournament, I only did 2 challenges, the rest were thanks to the reveal at the end of the tournament. Thank you for reading.

# Solution

## 1. Osint/Announcement
- Challenge : 

    ![Smile](/assets/posts/VishwaCTF/Announcement/Announcement.png)

- I searched for "CyberCell VIIT announces VishwaCTF 2024 Mini" and in an [Instagram post](https://www.instagram.com/reel/C2txmkqLVJn/), i got the flag . 
    
    ![Smile](/assets/posts/VishwaCTF/Announcement/flag1.png)

FLAG: *VishwaCTF{m1n1_i5_h3r3_l3t_th3_c0untd0wn_b3g1n}*

## 2. Stegano/Area96
- Challenge : 

    ![Smile](/assets/posts/VishwaCTF/Area96/Area96.png)
- This is the most confusing challenge because the organizers initially gave 3 files including 1 wav file and 2 zip files. I was about to give up, but after the organizers changed the topic, I didn't understand what the remaining 3 files were for, because the flag was only in 1 file. I used `stegseek` to extract hidden files in the image and got the flag right away. It's hard to understand!

FLAG: *VishwaCTF{BeepBoop_Jaadu}*

### 3. Osint/Murder Mystery
- Challenge:

    ![Smile](/assets/posts/VishwaCTF/MurderMistery/Murder-Mistery.png)
- In the received letter we see a part that looks like a barcode. After searching I found out it was *IMb barcode*. You can see the explanation below : 

    ![Smile](/assets/posts/VishwaCTF/MurderMistery/IMb-Barcode.png)
- I did it by hand and got this string: `ATTTFTADAFFTDTTAADTDTTATDAFDDDATATDDDDTADFAFADFATATFDFADDFFAFATDT `. 
After decoding by this web,I have this but I couldn't think about anything else. 
    ![Smile](/assets/posts/VishwaCTF/MurderMistery/IMb-decode.png)
- After the tournament ended, I known that I needed to combine all the numbers given by the barcode and convert them to ASCII. The string I get after merging: `101 118 105 108 95 115 104 97 100 111 119` . And after conversion we get the flag:

FLAG: *VishwaCTF{evil_shadow}*

## 4. Osint/I'm a Peaky Blinder
- Challenge : 

    ![Smile](/assets/posts/VishwaCTF/PeakyBlinder/Peaky-Blinder.png)
- I tried copying the entire introduction and realized it was part of a song from the recent famous movie 'Peaky Blinder'. The film's popularity cannot be disputed.
Back to the challenge, the last part of the introduction is an Insta account. For each photo we will receive a portion of a [Facebook account](https://www.facebook.com/profile.php?id=61554610571803&mibextid=hIlR13). Which takes us to that page, at the bottom of the page is another Insta account. 
    ![Smile](/assets/posts/VishwaCTF/PeakyBlinder/PB-Insta.png)
- In the new insta page just received,look carefully at each photo and see that there is a question there. The flag we receive is the answer to the question.

    ![Smile](/assets/posts/VishwaCTF/PeakyBlinder/flag4.png)

FLAG: *VishwaCTF{The_Garrison}*
