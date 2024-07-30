---
title: "Cyber Cooperative 2023"
date: 2023-12-19T07:42:50+07:00
description: "Solution for Cyber Cooperative 2023 challenges" 
tags: [network, forensics]
categories: [ctf]
author : [1]
draft: true
---
<!--more-->

# Overview

- Cyber Coopearative takes place over 3 days, from 12:00 noon on December 15, 2023 to 12:00 on December 18, 2023 according to ICT. My stamina had been depleted 2 days before because of MetaRed and the test.
- *All file challs in folder : chall_file*
# Solution

## 1. Dread Pirate (Networking)
- `Wireshark` + `strings` check only give me a text : "5can you check out one of the flagged messages for me?" and no more. So maybe flag out of wireshark check, use `binwalk` i see many jpeg file . Extract all them and check one by one file. See flag from 1 image.
    
    -> *flag{knock_knock_open_up_its_the_fbi}* 

<br>

## 2. Funding Secure (Forensics)

- Use `zsteg` to check and i see a file txt hidden. To extract, use `zsteg -E 'b1,rgb,lsb,xy' filename > outfile`. Strings it to see flag.txt in it, and use `foremost` or `binwalk` to extract and got flag.

    -> *flag{what_came_first_the_stego_or_the_watermark}*
