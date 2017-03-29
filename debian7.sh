#!/bin/bash

if [[ $USER != 'root' ]]; then
	echo "Sorry.. Need root access for launch this script."
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [ "$ether" = "" ]; then
        ether=eth0
fi

# go to root
cd

# check registered ip
# change http://localhost/ipAddress.txt with your ip address link
wget -q -O "IP" "http://pastebin.com/raw/7qafRrhz"
if ! grep -w -q $MYIP IP; then
	echo "Sorry, your ip is not registered for launch this script."
	echo "Contact the admin or seller to use this script."
	rm -f /root/IP
	exit
fi

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -O /etc/apt/sources.list "http://srv70.putdrive.com/putstorage/DownloadFileHash/233203DD3A5A4A5QQWE2090698EWQS/sources.list.debian7"
wget "http://www.dotdeb.org/dotdeb.gpg"
# wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
# cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
#apt-get -y autoremove;

# update
apt-get update;apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
#apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i $ether
service vnstat restart

# install screenfetch
cd
wget 'http://srv70.putdrive.com/putstorage/DownloadFileHash/5064DF5B3A5A4A5QQWE2090696EWQS/screenfetch-dev'
mv screenfetch-dev /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "http://srv70.putdrive.com/putstorage/DownloadFileHash/A737B8AA3A5A4A5QQWE2090694EWQS/nginx.conf"
mkdir -p /home/vps/public_html

#required change ++++++
wget -O /home/vps/public_html/index.html "http://srv70.putdrive.com/putstorage/DownloadFileHash/E0EBDE523A5A4A5QQWE2090718EWQS/coba.html"
# +++++

echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "http://srv70.putdrive.com/putstorage/DownloadFileHash/BCFD03393A5A4A5QQWE2090702EWQS/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

PASS=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
useradd -M -s /bin/false randomuser
echo "randomuser:$PASS" | chpasswd
echo "randomuser" >> pass.txt
echo "$PASS" >> pass.txt
cp pass.txt /home/vps/public_html/
rm -f /root/pass.txt
cd

# install badvpn
wget -O /usr/bin/badvpn-udpgw "http://srv70.putdrive.com/putstorage/DownloadFileHash/583865C23A5A4A5QQWE2090686EWQS/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "http://srv70.putdrive.com/putstorage/DownloadFileHash/6AAA129C3A5A4A5QQWE2090687EWQS/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
#apt-get update;apt-get -y install snmpd;
wget -O /etc/snmp/snmpd.conf "http://srv70.putdrive.com/putstorage/DownloadFileHash/59C40AA63A5A4A5QQWE2090697EWQS/snmpd.conf"
wget -O /root/mrtg-mem "http://srv70.putdrive.com/putstorage/DownloadFileHash/35D1968F3A5A4A5QQWE2090693EWQS/mrtg-mem.sh"
chmod +x /root/mrtg-mem
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "http://srv70.putdrive.com/putstorage/DownloadFileHash/99B5DBB63A5A4A5QQWE2090692EWQS/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 80' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
#apt-get -y update
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# upgrade dropbear 2014
apt-get install zlib1g-dev
wget http://srv70.putdrive.com/putstorage/DownloadFileHash/62BD283D3A5A4A5QQWE2090691EWQS/dropbear-2014.66.tar.bz2
bzip2 -cd dropbear-2014.66.tar.bz2  | tar xvf -
cd dropbear-2014.66
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# install vnstat gui
cd /home/vps/public_html/
wget http://srv70.putdrive.com/putstorage/DownloadFileHash/68B7779D3A5A4A5QQWE2090701EWQS/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/$ether/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array($ether);/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# install fail2ban
apt-get -y install fail2ban;service fail2ban restart;

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "http://srv70.putdrive.com/putstorage/DownloadFileHash/E60E3A073A5A4A5QQWE2090700EWQS/squid3.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
#wget -O webmin-current.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.760_all.deb
wget -O webmin-current.deb http://ufpr.dl.sourceforge.net/project/webadmin/webmin/1.801/webmin_1.801_all.deb
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
#sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
service webmin restart
service vnstat restart

# install pptp vpn
wget http://srv70.putdrive.com/putstorage/DownloadFileHash/097FFEBA3A5A4A5QQWE2090710EWQS/pptp.sh
chmod +x pptp.sh
./pptp.sh

# download script
cd
wget -O /usr/bin/benchmark "http://srv70.putdrive.com/putstorage/DownloadFileHash/E4A508213A5A4A5QQWE2090690EWQS/benchmark.sh"
wget -O /usr/bin/speedtest "http://srv70.putdrive.com/putstorage/DownloadFileHash/D0914C703A5A4A5QQWE2090699EWQS/speedtest_cli.py"
wget -O /usr/bin/ps-mem "http://srv70.putdrive.com/putstorage/DownloadFileHash/2735A9F53A5A4A5QQWE2090695EWQS/ps_mem.py"
wget -O /etc/issue.net "http://srv70.putdrive.com/putstorage/DownloadFileHash/D5D181D63A5A4A5QQWE2090688EWQS/banner"

# encrypted script
wget -O /usr/bin/dropmon "http://srv70.putdrive.com/putstorage/DownloadFileHash/6F3FAA343A5A4A5QQWE2090708EWQS/dropmon"
wget -O /usr/bin/menu "http://srv70.putdrive.com/putstorage/DownloadFileHash/80EE56DD3A5A4A5QQWE2090709EWQS/menu"
wget -O /usr/bin/user-add "http://srv70.putdrive.com/putstorage/DownloadFileHash/39FCA95B3A5A4A5QQWE2090711EWQS/user-add"
wget -O /usr/bin/user-add-pptp "http://srv70.putdrive.com/putstorage/DownloadFileHash/7F13B20D3A5A4A5QQWE2090712EWQS/user-add-pptp"
wget -O /usr/bin/user-expire "http://srv70.putdrive.com/putstorage/DownloadFileHash/CEEDFBD53A5A4A5QQWE2090713EWQS/user-expire"
wget -O /usr/bin/user-gen "http://srv70.putdrive.com/putstorage/DownloadFileHash/0AAD51B93A5A4A5QQWE2090714EWQS/user-gen"
wget -O /usr/bin/user-limit "http://srv70.putdrive.com/putstorage/DownloadFileHash/B43CB5823A5A4A5QQWE2090715EWQS/user-limit"
wget -O /usr/bin/user-list "http://srv70.putdrive.com/putstorage/DownloadFileHash/01A67FF73A5A4A5QQWE2090716EWQS/user-list"
wget -O /usr/bin/user-login "http://srv70.putdrive.com/putstorage/DownloadFileHash/D3F3C52A3A5A4A5QQWE2090717EWQS/user-login"

chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-expire
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/user-limit
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login

echo "00 1 * * * root /usr/bin/user-expire" > /etc/cron.d/user-expire
#echo "@reboot root /usr/bin/user-limit" > /etc/cron.d/user-limit
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
echo "* * * * * root service dropbear restart" > /etc/cron.d/dropbear
#echo "@reboot root /usr/bin/autokill" > /etc/cron.d/autokill
#sed -i '$ i\screen -AmdS check /root/autokill' /etc/rc.local

# finishing
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service php5-fpm start
service vnstat restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Autoscript Include:" | tee log-install.txt
echo "=======================================================" | tee -a log-install.txt
echo "Service :" | tee -a log-install.txt
echo "---------" | tee -a log-install.txt
echo "OpenSSH  : 22, 143" | tee -a log-install.txt
echo "Dropbear : 443, 110, 109" | tee -a log-install.txt
echo "Squid3   : 80, 8000, 8080, 3128 (limit to IP $MYIP)" | tee -a log-install.txt
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)" | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt
echo "PPTP VPN : TCP 1723" | tee -a log-install.txt
echo "nginx    : 81" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Tools :" | tee -a log-install.txt
echo "-------" | tee -a log-install.txt
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Script :" | tee -a log-install.txt
echo "--------" | tee -a log-install.txt
echo "screenfetch" | tee -a log-install.txt
echo "menu (Menu Script VPS via Putty) :" | tee -a log-install.txt
echo "  - Create account SSH/OpenVPN (user-add)" | tee -a log-install.txt
echo "  - Generate account SSH/OpenVPN (user-gen)" | tee -a log-install.txt
echo "  - Create account PPTP VPN (user-add-pptp)" | tee -a log-install.txt
echo "  - Remote Dropbear (dropmon [PORT])" | tee -a log-install.txt
echo "  - Check login Dropbear, OpenSSH, PPTP VPN dan OpenVPN (user-login)" | tee -a log-install.txt
echo "  - Kill Multi Login Manual (1-2 Login) (user-limit [x])" | tee -a log-install.txt
echo "  - List account and Expire Date (user-list)" | tee -a log-install.txt
echo "  - Memory Usage (ps-mem)" | tee -a log-install.txt
echo "  - Speedtest (speedtest --share)" | tee -a log-install.txt
echo "  - Benchmark (benchmark)" | tee -a log-install.txt
echo "  - Reboot Server" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Other feature :" | tee -a log-install.txt
echo "------------" | tee -a log-install.txt
echo "Webmin   : http://$MYIP:10000/" | tee -a log-install.txt
echo "vnstat   : http://$MYIP:81/vnstat/ (Cek Bandwith)" | tee -a log-install.txt
echo "MRTG     : http://$MYIP:81/mrtg/" | tee -a log-install.txt
echo "Timezone : Asia/Jakarta (GMT +7)" | tee -a log-install.txt
echo "Fail2Ban : [on]" | tee -a log-install.txt
echo "IPv6     : [off]" | tee -a log-install.txt
#echo "Autolimit 2 bitvise per IP to all port (port 22, 143, 109, 110, 443, 1194, 7300 TCP/UDP)" | tee -a log-install.txt
echo "Auto Lock User Expire every 00:00 hours" | tee -a log-install.txt
echo "VPS AUTO REBOOT EVERY 12 HOURS" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Thanks to Original Creator Kang Arie & Mikodemos" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Log --> /root/log-install.txt" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Reboot your vps now using command : reboot !" | tee -a log-install.txt
echo "=======================================================" | tee -a log-install.txt
cd ~/
rm -f /root/debian7.sh
rm -f /root/pptp.sh
rm -f /root/dropbear-2014.66.tar.bz2
rm -rf /root/dropbear-2014.66
rm -f /root/IP
