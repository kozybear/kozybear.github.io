--- 
title: "TexsawCTF 2024"
date: 2024-03-25T17:31:00+07:00
# description: "Writeup for TexsawCTF 2024 challenges"
tags: [forensics, osint]
categories: [ctf]
author : [1]
---

Although the challenges of the tournament look simple, they are actually quite difficult and my way of doing things is also very stupid lol. Some challenges I even did manually. It takes several hours for them. Really had a sleepless night with my team - [Huntik](https://ctftime.org/team/127635). Anyway, thanks for reading and have a great day!

# Solution 

## 1. Osint/Geo-Location 
- Challenge :

    ![pic1](/assets/posts/TexsawCTF%202024/Geo-location/Chall.png)
- PNG file: 

    ![pic2](/assets/posts/TexsawCTF%202024/Geo-location/picture.jpg)
- Using GG image and focusing on the large building in the photo, we can see a number of matching images.

    ![pic3](/assets/posts/TexsawCTF%202024/Geo-location/CheckGGimg.png)
-  I later identified it as the ```TCC Legacy Kincaid building```. Check GG map and you will see it matches the image. It is located on Legacy Street,Texas.

FLAG: *texsaw{LEGACY_DRIVE}*

## 2. Forensics/The Forked Cave
- Challenge:

    ![pic4](/assets/posts/TexsawCTF%202024/The%20Forked%20Cave/Chall.png)
- The challenge gives us a git directory. Because I've done a similar challenge before, I used ```git log``` to check:

    ![pic5](/assets/posts/TexsawCTF%202024/The%20Forked%20Cave/GitLog.png)
- And using command : ```git diff 02589c89210a9718a03992eec1a7da85e15c7c7d 9c6d7b5d77ba2f73fca83d026de1fe7904ce6e0b```, we get the flag:

    ![pic6](/assets/posts/TexsawCTF%202024/The%20Forked%20Cave/GitDiff.png)

FLAG: *texsaw{git_g00d_or_git_d3ath}*

## 3. Forensics/PS2 games 
- Challenge : 

    ![pic7](/assets/posts/TexsawCTF%202024/PS2%20games/Chall.png)
- My initial idea was to use code to filter out all games between ```2000-2009```, then check their ```platform-id```. But after solving the challenge that way, I tried ```Workbench``` and it was much simpler. Just with the following SQL code:

```sql
SELECT COUNT(DISTINCT Games.game_id) AS num_games
FROM Games
JOIN GamePlatforms ON Games.game_id = GamePlatforms.game_id
JOIN Platforms ON GamePlatforms.platform_id = Platforms.platform_id
WHERE Platforms.platform_name = 'Playstation'
AND YEAR(Games.release_date) BETWEEN 2000 AND 2009;
```

FLAG: *texsaw{42}*

## 4. Crypto/Freaky Flags
- Challenge :

    ![pic8](/assets/posts/TexsawCTF%202024/Freaky%20Flags/chall.png)
- PNG file:

    ![pic9](/assets/posts/TexsawCTF%202024/Freaky%20Flags/freakyFlags.png)
- Luckily, I had just learned HTML and used [Color Identity](https://redketchup.io/color-picker) to determine the color of an image, so I immediately thought of trying it out. Each color will have 3 RGB values and I try to put them into ASCII decode. It works and I get the flag.

    ![pic10](/assets/posts/TexsawCTF%202024/Freaky%20Flags/Decode.png)

FLAG: *texsaw{the_flag_is_the_flag!}*

## 5. Osint/TrickyTree
- A challenge that I initially thought I would give up on. But when there were about 5-6 hours left in the competition, I tried again. And this time thanks to the predecessors of the challenge, I have [this link](https://www.familytreenow.com/trees/715273) :

    ![pic11](/assets/posts/TexsawCTF%202024/TrickyTree/Link.png)
- But guess what, of course it's not that easy. I tried using a wayback machine but it didn't work very well. Suddenly I thought of a website I used from the ```0xL4ugh tournament```, which is ```Archive.Today```. I tried copying the link I just received and got the results:

    ![pic12](/assets/posts/TexsawCTF%202024/TrickyTree/ArchiveToday.png)
- Click to see and we will see his father's name. View profile and get date of birth.Thank all players who went first.

    ![pic13](/assets/posts/TexsawCTF%202024/TrickyTree/FatherDOB.png)

FLAG: *texsaw{09_02_1985}*

## 6. Forensics/Market Data
- Challenge :

    ![pic14](/assets/posts/TexsawCTF%202024/Marked%20Data/Chall.png)
- I use the following SQL code to filter and get the correct results:

    ```sql
    SELECT 
        SUM(revenue) AS total_revenue
    FROM (
        SELECT 
            od.game_id,
            SUM(od.quantity * od.subtotal) AS revenue,
            ROW_NUMBER() OVER (ORDER BY SUM(od.quantity * od.subtotal) DESC) AS revenue_rank
        FROM 
            OrderDetails od
        JOIN 
            Games g ON od.game_id = g.game_id
        JOIN 
            Genres ge ON g.genre_id = ge.genre_id
        JOIN 
            Orders o ON od.order_id = o.order_id
        WHERE 
            ge.genre_name = 'Action' -- Filter by Action genre
            AND YEAR(o.order_date) = 2023 -- Filter orders from 2023
        GROUP BY 
            od.game_id
    ) AS revenue_by_game
    WHERE 
        revenue_rank = 5; -- Select the 5th ranked game's revenue
    ```

FLAG: *texsaw{247.16}*