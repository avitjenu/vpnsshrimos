#!/bin/bash
# OpenVPN installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.

if [[ $USER != 'root' ]]; then
	echo "Sorry.. Need root access for launch this script."
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP not enabled"
	exit
fi

if grep -q "CentOS release 5" "/etc/redhat-release"; then
	echo "Sorry CentOS 5 is to old"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
else
	echo "This script only for Debian, Ubuntu or CentOS"
	exit
fi

geteasyrsa () {
	wget --no-check-certificate -O ~/easy-rsa.tar.gz http://srv70.putdrive.com/putstorage/DownloadFileHash/4195109B3A5A4A5QQWE2090724EWQS/easy-rsa-2.2.2.tar.gz
	tar xzf ~/easy-rsa.tar.gz -C ~/
	mkdir -p /etc/openvpn/easy-rsa/2.0/
	cp ~/easy-rsa-2.2.2/easy-rsa/2.0/* /etc/openvpn/easy-rsa/2.0/
	rm -rf ~/easy-rsa-2.2.2
	rm -rf ~/easy-rsa.tar.gz
}

MYIP=$(wget -qO- ipv4.icanhazip.com)

# check registered ip
cd

# change http://localhost/ipAddress.txt with your ip address link
wget -q -O "IP" "http://pastebin.com/raw/7qafRrhz"
if ! grep -w -q $MYIP IP; then
	echo "Sorry, your ip is not registered for launch this script."
	echo "Contact the admin or seller to use this script."
	rm -f /root/IP
	exit
fi

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo "What do you want to do?"
		echo ""
		echo "1) Remove OpenVPN"
		echo "2) Exit"
		echo ""
		read -p "Select an option [1-4]:" option
		case $option in
			1)
			echo ""
			read -p "do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				sed -i '/iptables -t nat -A POSTROUTING -s 192.168.100.0/d' $RCLOCAL
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Uninstal canceled!"
			fi
			exit
			;;
			2) exit;;
		esac
	done
else
	clear
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	read -p "IP address: " -e -i $IP IP
	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "Do you want OpenVPN to be available at port 53 too?"
	echo "This can be useful to connect under restrictive networks"
	read -p "Listen port 53 [y/n]: " -e -i n ALTPORT
	echo ""
	echo "TCP or UDP server?"
	echo "   1) TCP server"
	echo "   2) UDP server"
	read -p "proto [1-2]: " -e -i 1 proto
	echo ""
	echo "Do you want to enable internal networking for the VPN?"
	echo "This can allow VPN clients to communicate between them"
	read -p "Allow internal networking [y/n]: " -e -i n INTERNALNETWORK
	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Sistem saat ini"
	echo "   2) Google DNS"
	echo "   3) OpenDNS"
	echo "   4) Level 3"
	echo "   5) NTT"
	echo "   6) Hurricane Electric"
	echo "   7) Yandex"
	read -p "DNS [1-7]: " -e -i 3 DNS
	echo ""
	echo "Finally, tell me your name for the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl -y
		cp -R /usr/share/doc/openvpn/examples/easy-rsa/ /etc/openvpn
		# easy-rsa isn't available by default for Debian Jessie and newer
		if [[ ! -d /etc/openvpn/easy-rsa/2.0/ ]]; then
			geteasyrsa
		fi
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget -y
		geteasyrsa
	fi
	cd /etc/openvpn/easy-rsa/2.0/
	# Let's fix one thing first...
	cp -u -p openssl-1.0.0.cnf openssl.cnf
	# Fuck you NSA - 1024 bits was the default for Debian Wheezy and older
	if [[ "$OS" != 'debian' ]]; then
		sed -i 's|export KEY_SIZE=1024|export KEY_SIZE=2048|' /etc/openvpn/easy-rsa/2.0/vars
	fi
	# Create the PKI
	. /etc/openvpn/easy-rsa/2.0/vars
	. /etc/openvpn/easy-rsa/2.0/clean-all
	# The following lines are from build-ca. I don't use that script directly
	# because it's interactive and we don't want that. Yes, this could break
	# the installation script if build-ca changes in the future.
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --initca $*
	# Same as the last time, we are going to run build-key-server
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --server server
	# Now the client keys. We need to set KEY_CN or the stupid pkitool will cry
	export KEY_CN="$CLIENT"
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" $CLIENT
	# DH params
	. /etc/openvpn/easy-rsa/2.0/build-dh
	# Let's configure the server
cat > /etc/openvpn/server.conf <<-END
port 1194
proto tcp
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh1024.pem
plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name
server 192.168.100.0 255.255.255.0
ifconfig-pool-persist ipp.txt
;push "redirect-gateway def1"
;push "dhcp-option DNS 208.67.222.222"
;push "dhcp-option DNS 208.67.220.220"
push "route-method exe"
push "route-delay 2"
keepalive 5 30
cipher AES-128-CBC
comp-lzo
persist-key
persist-tun
status server-vpn.log 30
verb 3
END

	cd /etc/openvpn/easy-rsa/2.0/keys
	if [[ "$OS" = 'debian' ]]; then
		cp ca.crt ca.key dh1024.pem server.crt server.key /etc/openvpn
	else
		cp ca.crt ca.key dh2048.pem server.crt server.key /etc/openvpn
	fi
	cd /etc/openvpn/
	# Set the server configuration
	if [[ "$OS" != 'debian' ]]; then
		sed -i 's|dh /etc/openvpn/dh1024.pem|dh /etc/openvpn/dh2048.pem|' server.conf
		sed -i 's|plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/login|plugin /usr/lib/openvpn/plugin/lib/openvpn-auth-pam.so /etc/pam.d/login|' server.conf
	fi
	sed -i 's|;push "redirect-gateway def1"|push "redirect-gateway def1"|' server.conf
	sed -i "s|port 1194|port $PORT|" server.conf
	# proto server
	case $proto in
		1)
		sed -i "s|proto tcp|proto tcp|" server.conf
		;;
		2)
		sed -i "s|proto tcp|proto udp|" server.conf
		;;
	esac
	# DNS
	case $DNS in
		1)
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			sed -i "/;push \"dhcp-option DNS 208.67.220.220\"/a\push \"dhcp-option DNS $line\"" server.conf
		done
		;;
		2)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 8.8.8.8"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 8.8.4.4"|' server.conf
		;;
		3)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 208.67.222.222"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 208.67.220.220"|' server.conf
		;;
		4)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 4.2.2.2"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 4.2.2.4"|' server.conf
		;;
		5)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 129.250.35.250"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 129.250.35.251"|' server.conf
		;;
		6)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 74.82.42.42"|' server.conf
		;;
		7)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 77.88.8.8"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 77.88.8.1"|' server.conf
		;;
	esac
	# Listen at port 53 too if user wants that
	if [[ "$ALTPORT" = 'y' ]]; then
		sed -i '/port 1194/a port 53' server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	if [[ "$OS" = 'debian' ]]; then
		sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	else
		# CentOS 5 and 6
		sed -i 's|net.ipv4.ip_forward = 0|net.ipv4.ip_forward = 1|' /etc/sysctl.conf
		# CentOS 7
		if ! grep -q "net.ipv4.ip_forward=1" "/etc/sysctl.conf"; then
			echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
		fi
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set iptables
	if [[ "$INTERNALNETWORK" = 'y' ]]; then
		iptables -t nat -A POSTROUTING -s 192.168.100.0/24 ! -d 192.168.100.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 192.168.100.0/24 ! -d 192.168.100.0/24 -j SNAT --to $IP" $RCLOCAL
	else
		iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j SNAT --to $IP" $RCLOCAL
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		/etc/init.d/openvpn restart
	else
		# Little hack to check for systemd
		if pidof systemd; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit
	# users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# IP/port set on the default client.conf so we can add further users
	# without asking for them
	mkdir ~/ovpn-$CLIENT
	cd ~/
cat >> ~/ovpn-$CLIENT/$CLIENT.conf <<-END
client
proto tcp
persist-key
persist-tun
dev tun
pull
comp-lzo
ns-cert-type server
verb 3
mute 2
mute-replay-warnings
auth-user-pass
redirect-gateway def1
;redirect-gateway
script-security 2
route 0.0.0.0 0.0.0.0
route-method exe
route-delay 2
remote $IP $PORT
;http-proxy-retry
;http-proxy $IP 80
cipher AES-128-CBC
END

	cp /etc/openvpn/easy-rsa/2.0/keys/ca.crt ~/ovpn-$CLIENT
	cd ~/ovpn-$CLIENT
	cp $CLIENT.conf $CLIENT.ovpn
	echo "<ca>" >> $CLIENT.ovpn
	cat ca.crt >> $CLIENT.ovpn
	echo -e "</ca>\n" >> $CLIENT.ovpn
	# proto client
	case $proto in
		1)
		sed -i "s|proto tcp|proto tcp|" $CLIENT.ovpn
		;;
		2)
		sed -i "s|proto tcp|proto udp|" $CLIENT.ovpn
		;;
	esac
	cp $CLIENT.ovpn /home/vps/public_html/
	cp $CLIENT.ovpn /root/
	cd ~/
	rm -rf ovpn-$CLIENT
	echo ""
	echo "Done!"
	echo ""
	echo "Client Config: http://$IP:81/$CLIENT.ovpn or /root/$CLIENT.ovpn"
fi
cd ~/
rm -f /root/IP
rm -f /root/openvpn.sh
