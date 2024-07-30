--- 
title: "Writeup for Osint/Ocean_Enigma - ShaktiCTF 2024"
date: 2024-03-11T22:50:00+07:00
description: "Writeup for Osint/Ocean_Enigma - ShaktiCTF 2024"
tags: [osint]
categories: [ctf]
author : [1]
---
<!--more-->

## Overview

- ShaktiCTF and PearlCTF happened around the same time I had my exams, so I couldn't focus too much on either of them. This was the only Osint challenge I did in the tournament. I transferred some files on my computer and deleted the question part of the challenge even though I solved it during the time it took place. I took all the questions of the challenge from the [article of Mr. Berlian Gabriel of team Fidethus](https://berliangabriel.github.io/post/shakti-ctf-2024-foren/). Sincerely thank you so much! 

### Writeup 

- This is 4 questions of challenge :

    ![Smile](/assets/posts/ShaktiOsint/Question-part.png)
- And we have a image (same picture in tournament) : 

    ![Smile](/assets/posts/ShaktiOsint/MeryCeleste.jpeg)

-Trying using GG image, I get the result of the ship's name: ```Mary Celeste```. Starting with the first question, I searched with the keyword: ```mary celeste crew name``` and got 
[this website](https://www.maryceleste.net/crew.htm).

![Smile](/assets/posts/ShaktiOsint/Crew.png)

- From here we can get the names of 2 friends, but I prioritize the first person because it is mentioned in the challenge example. So we have the first part:
```(1) Albert_G_Richardson ```

- As for the second part, we just need to search for Mary Celeste and we can get the result: (2) David_Morehouse

    *Fact: David Morehouse was also the captain of the Dei Gratia, the ship that discovered the Mary Celeste while it was drifting*
- Third part, search with ship name and in Wikipedia, we get it : ```(3) Santa_Maria``` .

    ![Smile](/assets/posts/ShaktiOsint/3th-part.png)
- On the same page, we get the result of the 4th question: ``` (4) Amazon```

    ![Smile](/assets/posts/ShaktiOsint/4th-part.png)

- Summing up, we have the full flag: 

    -> flag : <b>*shaktictf{Albert_G_Richardson:David_Morehouse:Santa_Maria:Amazon}* </b>