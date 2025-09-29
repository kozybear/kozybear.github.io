---
title:  Spooky CTF 2024
published: 2024-10-28
tags: [Forensics]
category: Write-Up
image: ./images/banner.png
draft: false
---

# 1. For/Event code hunt
## Challenge Description
Maya Elmer managed to seize one of The Consortium's computers, but when she tried to access a critical file, a sudden blue box flashed across her screen, and the file was instantly encrypted. Now, with the clock ticking, participants must step in to decrypt the file and uncover the hidden contents. The Consortium's encryption is tough to crack, and only the most determined will succeed in revealing the secrets locked away within.

> Author: Trent

> Type: Medium

## Solution
Thử thách cung cấp các file như sau:

```txt
╰─ tree
.
├── Application.evtx
├── encrypt_flag.txt
├── PowershellOP.evtx
├── Security.evtx
├── System.evtx
└── Windows_Powershell.evtx
```
Mình kiểm tra file Windows_Powershell.evtx nhưng không có gì. Đến file PowershellOP.evtx, ở 1 trong các EID `4104 - Execute a remote command`, mình thấy 1 dòng như sau: 
```
Creating Scriptblock text (1 of 1):
"import sys`n`ndef process_data(input_bytes, key):`n    key_bytes = key.encode('utf-8')`n    return bytearray([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(input_bytes)])`n`ndef main():`n    if len(sys.argv) != 4:`n        print('Usage: python script.py <input_file> <output_file> <key>')`n        return`n    input_file = sys.argv[1]`n    output_file = sys.argv[2]`n    key = sys.argv[3]`n`n    with open(input_file, 'rb') as f:`n        input_data = f.read()`n`n    result_data = process_data(input_data, key)`n`n    with open(output_file, 'wb') as f:`n        f.write(result_data)`n`nif __name__ == '__main__':`n    main()" | Set-Content -Path "C:\Users\johndoe\Documents\Chrome.py"; Get-Content "C:\Users\johndoe\Documents\Chrome.py"
```
và một dòng EID 4104 khác: 
```
python3 .\Documents\Chrome.py .\Documents\flag.txt .\Documents\encrypt_flag.txt I_Like_Big_Bytes_And_I_cannot_Lie!
```
Đại khái là dòng đầu tiên sẽ tạo và lưu một đoạn mã Python vào 1 file có tên `Chrome.py` với chức năng XOR từng byte của file đầu vào với các byte của 1 key và lưu ra file `encrypt_flag.txt` mà ta được cho ban đầu. Dòng thứ hai sẽ chạy file đó với đủ 3 tham số là file đầu vào, tên file đầu ra và 1 key. Để giải mã thì ta chỉ cần XOR ngược lại các byte là được. 
```python
def xor_decrypt(encrypted_data, key):
    key_bytes = key.encode('utf-8')
    decrypted_data = bytearray([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_data)])
    return decrypted_data

def main():
    input_file = './encrypt_flag.txt'  
    output_file = './decrypted_flag.txt' 
    key = 'I_Like_Big_Bytes_And_I_cannot_Lie!' 
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = xor_decrypt(encrypted_data, key)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

if __name__ == '__main__':
    main()
```

FLAG: `NICC{Maya_Elmer_D3t3cts_Mal1c10us_P4yl04d_1n_3v3ntL0gs}`

# 2. For/memory puzzle
## Challenge Description
The Consortium has concealed a critical file within a memory dump, protected by layers of digital obfuscation. Led by Simon Letti, participants must sift through the volatile memory landscape to locate a plaintext key that unlocks the encrypted file. Time is of the essence, as Roko's Basilisk threatens to distort the data with each passing moment. Can you unravel the puzzle before the Basilisk intervenes?
"Basilisk's whisper will not wait" echos through your mind as you enter the file.
(Note: If you choose to use volatility2.6, use profile Win10x64_19041)

> Author : Trent

> Type: Medium

## Solution
Bài cung cấp 1 file dump và 1 file `flag.enc`. Hướng làm của dạng bài này thường là tìm loại mã hóa để giải mã. Mình dùng plugin `pslist` để xem các tiến trình:

```bash
...
8400    848     PhoneExperienc  0xb1084157b300  18      -       1       False   2024-10-18 06:42:44.000000 UTC  N/A    Disabled
8568    848     RuntimeBroker.  0xb1084137b080  18      -       1       False   2024-10-18 06:42:47.000000 UTC  N/A    Disabled
8692    848     smartscreen.ex  0xb1083f75b080  8       -       1       False   2024-10-18 06:42:49.000000 UTC  N/A    Disabled
8748    4976    SecurityHealth  0xb10841990080  7       -       1       False   2024-10-18 06:42:49.000000 UTC  N/A    Disabled
8784    716     SecurityHealth  0xb1084137c080  15      -       0       False   2024-10-18 06:42:49.000000 UTC  N/A    Disabled
8864    4976    VBoxTray.exe    0xb1084184c080  12      -       1       False   2024-10-18 06:42:50.000000 UTC  N/A    Disabled
8936    4976    OneDrive.exe    0xb1084184f080  24      -       1       False   2024-10-18 06:42:50.000000 UTC  N/A    Disabled
9040    8936    Microsoft.Shar  0xb10841a5a080  0       -       1       False   2024-10-18 06:42:51.000000 UTC  2024-10-18 06:43:01.000000 UTC  Disabled
7912    716     svchost.exe     0xb10841664080  7       -       0       False   2024-10-18 06:42:57.000000 UTC  N/A    Disabled
7256    848     FileCoAuth.exe  0xb10841a57080  4       -       1       False   2024-10-18 06:43:08.000000 UTC  N/A    Disabled
3848    848     UserOOBEBroker  0xb108420020c0  5       -       1       False   2024-10-18 06:43:16.000000 UTC  N/A    Disabled
7436    716     svchost.exe     0xb10841744080  15      -       1       False   2024-10-18 06:43:18.000000 UTC  N/A    Disabled
1148    848     dllhost.exe     0xb10841820080  6       -       1       False   2024-10-18 06:43:35.000000 UTC  N/A    Disabled
1980    4976    notepad.exe     0xb1084122e080  5       -       1       False   2024-10-18 06:43:38.000000 UTC  N/A    Disabled
2504    3984    SearchProtocol  0xb1083fe2a080  6       -       1       False   2024-10-18 06:43:38.000000 UTC  N/A    Disabled
800     848     SystemSettings  0xb10840a2e080  20      -       1       False   2024-10-18 06:43:53.000000 UTC  N/A    Disabled
3468    848     ApplicationFra  0xb108402102c0  9       -       1       False   2024-10-18 06:43:53.000000 UTC  N/A    Disabled
6184    848     TextInputHost.  0xb10841122080  13      -       1       False   2024-10-18 06:43:57.000000 UTC  N/A    Disabled
2292    848     dllhost.exe     0xb1084200a180  12      -       1       False   2024-10-18 06:43:57.000000 UTC  N/A    Disabled
2172    716     svchost.exe     0xb108414d2080  4       -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
6024    2496    audiodg.exe     0xb1084202c340  5       -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
2656    716     svchost.exe     0xb10840bbb080  11      -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
3372    848     WmiPrvSE.exe    0xb1084200e0c0  7       -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
7564    716     svchost.exe     0xb108417490c0  11      -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
6016    716     SgrmBroker.exe  0xb108420440c0  7       -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
6324    716     svchost.exe     0xb1084172e080  14      -       0       False   2024-10-18 06:44:07.000000 UTC  N/A    Disabled
3348    4976    DumpIt.exe      0xb108415b0080  3       -       1       True    2024-10-18 06:44:58.000000 UTC  N/A    Disabled
7660    3348    conhost.exe     0xb10840d1c080  7       -       1       False   2024-10-18 06:44:58.000000 UTC  N/A    Disabled
2148    1328    taskhostw.exe   0xb10840ce6080  10      -       0       False   2024-10-18 06:45:05.000000 UTC  N/A    Disabled
3772    848     MoUsoCoreWorke  0xb1084057f080  12      -       0       False   2024-10-18 06:45:05.000000 UTC  N/A    Disabled
9092    0               0xb1084128d080  1093195368      -       N/A     False   N/A     N/A     Disabled

```
Mình để ý tiến trình `notepad.exe`. Dùng plugin `notepad` để xem có gì. 

```txt
ExternalObjectOwner C:\Users\johndoe\Desktop\system_update.py /C:/Users/johndoe/Desktop/system_update.py C:\Windows\SYSTEM32\policymanager.dll .dll C:\Windows\system32\msvcp110_win.dll 0 C:\Users\johndoe\Desktop\system_update.py     0 /C:/Users/johndoe/Desktop/system_update.py     C:\Users\johndoe\Desktop\system_update.py     Users ` ` L -m \BaseNamedObjects ) ) = 2 '. > ) E A ) 5 = ) (   INE @ dummy://url/   Notepad   S S \BaseNamedObjects\[CoreUI]-PID(4604)-TID(4708) 26a16690-4734-41d4-9d35-3ade6a325bf6 7 \BaseNamedObjects\[CoreUI]-PID(1980)-TID(1972) e3218ed0-2332-4807-ac53-d5faec65b993 ` ` 8 8 8 8 Consolas nsole ` ` # Basilisk's whisper will not wait import time from Crypto.Cipher import AES from Crypto.Util.Padding import pad import os def main():     key = b'SuperSecretKey12'     print(f"Key length: {len(key)} bytes")     with open('flag.txt', 'rb') as f:         plaintext = f.read()     iv = b'\x00' * 16     cipher = AES.new(key, AES.MODE_CBC, iv=iv)     ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))     with open('flag.enc', 'wb') as f:         f.write(ciphertext)     time.sleep(10) if __name__ == '__main__':     main() ` Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository $ 8
```
Để ý sẽ thấy đoạn mã Python với file có tên `system_update.py`, sử dụng mã hóa AES với iv là 16 byte `0x00` và key là `SuperSecretKey12`. Vứt vào Cyberchef cho nó làm phần còn lại.

  ![image](/src/content/posts/2024-SpookyCTF/images/memory%20puzzle/memory_1.png)

FLAG: `NICC{S1m0n_Tr4v3rses_T1m3}`

# 3. For/Wont somebody think of the children
## Challenge Description
If Loab is back, we might need the council to help us out. The problem is that Anna sent Maya looking for them but she still hasn't come back. This is her last known location... Maybe you can help find her.
I'd go, but I really don't want to be around those spooky ghost orphans.

> Author: CyborgSwOrd

> Type: Medium

## Solution
Bài cung cấp 1 file SVG. Mình check `virustotal` thì không có gì nên yên tâm mở lên thì thấy 1 file ảnh khá to. Ở đây mình thu nhỏ lại cho có cái nhìn toàn cảnh:

  ![image](/src/content/posts/2024-SpookyCTF/images/Wont%20somebody%20think%20of%20the%20children/Think_1.png)

Mình thử strings nó thì thấy nó được tạo thành từ hơn 30 tấm ảnh khác nhau với cách thức decode base64. Mình sử dụng đoạn mã sau để decode cho từng tấm 1:

```python
import base64
import re

def extract_and_save_images(input_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    image_count = 0

    base64_pattern = r'href="data:image/png;base64,([^"]+)"'

    for line in lines:
        matches = re.findall(base64_pattern, line)

        for match in matches:
            image_data = base64.b64decode(match)

            image_count += 1
            output_file = f'image_{image_count}.png'

            with open(output_file, 'wb') as img_file:
                img_file.write(image_data)

            print(f'Saved: {output_file}')

extract_and_save_images('copy.txt')
```
Mở lên và thấy cờ ở tấm thứ 5:
  ![image](/src/content/posts/2024-SpookyCTF/images/Wont%20somebody%20think%20of%20the%20children/Think_2.png)

FLAG: `NICC{H3ck_th3m_kids_what_@bout_the_council?}`

# 4. For/Sandy hook river
## Challenge Description
While lost in time, returning from Puerto Rico, sailing through a sandy-hook river, Simon Letti found a floating bottle with some weird-looking paper inside, which turned out to be a poem. He's still trying to figure out though, what he can do with that:
`Whispers` wound 'round rocks, rivers writhe, Meandering murk in the moon's muted might, Threads of thrumming, thistle-thought streams, Glimpsed through the gloom, gone unseen.
Banks bend backward, breaking `breath`, Currents carve cryptic creases; death Is a distant drift, dashed and drawn Into eddies of echoes where none belong.
Silver-silt serpents `sigh`, then die, Sluggish susurrations slip and fly. Yet within the wandering wake, Lies a language, languid and `opaque`.
Fluvial fragments fade, Scrawled on surfaces smeared in the shade, Speak in `stutters`, sharp as `stones`, But what they whisper remains unknown.
Beneath the brine, shadows stir, The Sandy Hook Sea Serpent's blur- A glimmer of scales, a ghost in the tide, A legend where dark secrets hide.
In `Loch Ness`, whispers flow, Where the ancient beast with grace does grow, In waters where dreams intertwine, An echo of history in its shadowy line.
In swamps, lizard men roam, Eyes aglow, far from home, A cryptid in murk, slippery and sly, A flicker beneath the night sky.
The `Chupacabra` prowls in shadow cast, Its hunger is a hymn, a threat that lasts, In the hush of night, it waits, A specter stalking through silent fates.
It coils through currents, a tale confined, Figures of myth, glimpsed and dreamed, In the whispers of waters, forever `esteemed`.


> Author: malanka

> Type: Medium

## Solution
Thử thách cho ta 1 file rar. Extract nó ra mình chỉ thấy 1 file txt. Sau đó mình biết được ở đây nó sử dụng ADS. Mình dùng `ADS Scanner` và nó phát hiện file rar. View stream, mình thấy như sau: 

  ![image](/src/content/posts/2024-SpookyCTF/images/Sandy%20hook%20river/Hook_1.png)

Vứt vào Cyberchef, ta được tiếp 1 file rar. Mình nghĩ nó là file rar ban đầu nhưng cứ thử mở thì thấy nó hỏi pass. Giờ mình mới nhớ lại các từ được bôi đậm trong đề bài, ghép chúng lại, mình được pass là: `WhisperbreathsighopaquestuttersstonesLoch NessChupacabraesteemed`. Việc còn lại là mở lên và lụm cờ thôi.

  ![image](/src/content/posts/2024-SpookyCTF/images/Sandy%20hook%20river/Hook_2.png)

FLAG: `NICC{AD$_$treamS_4re_$o_P0werfUlL}`