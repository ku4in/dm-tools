#!/usr/bin/env bash

VNC_PORT=59000
SSH_PORT=62222
DELAY_ONLINE=200     # Time in secs since latest handshake the client is considered online
MAX_CLIENTS=65534
DOWNLOAD_PERIOD=5    # Period in mins the download link will be valid

CONFIG_DIR=/etc/dm
WG_CONF_DIR=$CONFIG_DIR/wg
DB_FILE_NAME=$CONFIG_DIR/clients.db
SMB_CONF_FILE=/etc/samba/smb.conf
NGINX_CONF_FILE=/etc/nginx/sites-enabled/default
NGINX_SHARE=/var/www/share
NGINX_SECRET=pV8TttBJzob8UtmX3RiF
SHARE_NAME=share
SHARE_DIR=/var/$SHARE_NAME

WIN_INSTALL_DIR=C:\\games\\type\\new
WIN_CONF_DIR=$CONFIG_DIR/win
PUBLIC_URL="https://raw.githubusercontent.com/ku4in/dm-tools/main"

# WG default parameters
: ${ip_prefix:=10.10}
: ${ip_mask:=16}
: ${start_ip:=1}
: ${server_ip:=255.254}
: ${wg_port:=51820}
: ${wg_name:=wg0}
: ${allowedips:=10.10.0.0/16}


re_num='^[0-9]+$'

# Color output functions
RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLE='\033[1;34m'
NCL='\033[0m'

echo_red    () { echo -e ${RED}$1${NCL}; }
echo_green  () { echo -e ${GRN}$1${NCL}; }
echo_yellow () { echo -e ${YLW}$1${NCL}; }
echo_blue   () { echo -e ${BLE}$1${NCL}; }


banner  () { figlet dm-script; }

install () {
	# apt update -y && apt upgrade -y
	apt install -y curl net-tools iputils-ping dnsutils zip python3 python3-pip figlet qrencode
	apt install -y sqlite3 wireguard-tools samba nftables
	apt install -y nginx-light nginx-extras

	# Use PTR record for WG host
	# It may be useful when migrate to another server
	wg_pub_ip=`curl -s -4 ifconfig.me`
	wg_host=`dig +short -x $wg_pub_ip`
	if [ "${#wg_host}" = "0" ]; then wg_host=$wg_pub_ip; else wg_host=${wg_host:0:-1}; fi 

	# Create config directories
	mkdir -p $CONFIG_DIR
	mkdir -p $WG_CONF_DIR
	mkdir -p $SHARE_DIR
	mkdir -p $WIN_CONF_DIR
	mkdir -p $NGINX_SHARE
	mv       $SMB_CONF_FILE $SMB_CONF_FILE.orig

	wget $PUBLIC_URL/vncpwd.py -O $CONFIG_DIR/vncpwd.py
	chmod +x $CONFIG_DIR/vncpwd.py
	pip install --break-system-packages pyDes
	pip install pyDes

	# Create DB
	echo "CREATE TABLE clients (
	id         INTEGER     PRIMARY KEY AUTOINCREMENT,
	name       VARCHAR(32) NOT NULL,
	ip         VARCHAR(16) NOT NULL,
	privkey    VARCHAR(48) NOT NULL,
	pubkey     VARCHAR(48) NOT NULL,
	smb_passwd VARCHAR(12) NOT NULL,
	vnc_passwd VARCHAR(8)  NOT NULL,
	master     INTEGER     DEFAULT 0,
	hub        INTEGER     DEFAULT 0,
	date       TEXT        DEFAULT CURRENT_TIMESTAMP,
	comment    TEXT);" | sqlite3 $DB_FILE_NAME

	echo "CREATE TABLE server (
	id         INTEGER     PRIMARY KEY AUTOINCREMENT,
	hostname   TEXT,
	ip         VARCHAR(16) NOT NULL,
	privkey    VARCHAR(48) NOT NULL,
	pubkey     VARCHAR(48) NOT NULL);" | sqlite3 $DB_FILE_NAME

	echo "CREATE TABLE hubs (
	hub_id     INTEGER,
	client_id  INTEGER);" | sqlite3 $DB_FILE_NAME

	# Fill server table
	: ${wg_privkey:=`wg genkey`}
	wg_pubkey=`wg pubkey <<< $wg_privkey`
	echo "INSERT INTO server (hostname, ip, privkey, pubkey) VALUES ('$wg_host', '$ip_prefix.$server_ip', '$wg_privkey', '$wg_pubkey');" | sqlite3 $DB_FILE_NAME

	# Generate configs for WG and SMB servers
	wg_gen_config
	smb_gen_config

	# Set up Nginx
	openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 7300 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
	cat > /etc/nginx/dhparam.pem << EOF
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAkmdGeX3G8qETrSyDL/47W4Aby3jGSLSUp0ECd5/uHLhrzWzAujk5
1dYzB2p5PVgIjMrLN7R/1MaiDVxEYDH5LU533TL03YhRW+HaHcXbt4kb4qrdpsAH
m09wZCb0lRumpWvOJBUPTQJj+6r9jCMxG1IjFbjM3RMQnw0Q1cA7uNFWnodXsnne
6AEW77A8jhylY4cNnx5bW1KQ0/f2vpfzh6jaz65qxnFbFPZoEcyhOwMWxp98zr4R
lKGLxNftguSJULzeru/S0c531+fMMmAypuEhHiEzIhsKVQGskSZWQPcw7GupzRZ5
M0p639em0nvWvrfsziohga/3esIyfBbnZOUdZQ0ExBaUD30ff3zy+5BfK9CAZpWX
OX/yEuN0Py64iYc7h2xEqdM7MfSXmxeuO+0LXcBT0D0yknXFpt9qghfqxI0B814w
GvBAMnHTpyim+Tz23lvr1A1GKJIL7b1akbnXvKwPnwhM681uwjuWoJTr/2YH0wPo
6rZBSecrLNg0zT4ki11dQIGArUdMh1JLq6buDkOeQ5rUDyaz8g+AUdReqKrjaudA
9UuejeNa48oz5GVg07EiJ0gsEJhOa6cQwyv8r+gZjaUHFMWvGbAlBhZHpg3mKjED
Mm3q94fEX++HA8lMFzanzcqi0bDo1ZuIMxK8GkcVBIoLqHuWQuL61Q8CAQI=
-----END DH PARAMETERS-----
EOF

	cat > /etc/nginx/snippets/self-signed.conf << EOF
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
EOF

	cat > /etc/nginx/snippets/ssl-params.conf << EOF
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem; 
ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable strict transport security for now. You can uncomment the following
# line if you understand the implications.
#add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
EOF
	cat > $NGINX_CONF_FILE << EOF
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;
	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

	location /share {
		root /var/www/;
		secure_link $arg_md5,$arg_expires;
		secure_link_md5 "$secure_link_expires$uri $NGINX_SECRET";

		if ($secure_link = "")  { return 403; }
		if ($secure_link = "0") { return 410; }

		try_files $uri $uri/ =404;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	include snippets/self-signed.conf;
	include snippets/ssl-params.conf;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;
	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}

	location /share {
		root /var/www/;
		secure_link $arg_md5,$arg_expires;
		secure_link_md5 "$secure_link_expires$uri $NGINX_SECRET";

		if ($secure_link = "")  { return 403; }
		if ($secure_link = "0") { return 410; }

		try_files $uri $uri/ =404;
	}
}
EOF
	# Generate SSH key
	ssh-keygen -q -t ed25519 -N '' -f $HOME/.ssh/id_ed25519 <<<y >/dev/null 2>&1

	# Enable forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward
	sed -i '/net.ipv4.ip_forward=1/s/#//' /etc/sysctl.conf

	# TODO set up firewall

	# Enable and start WG and Samba, disable Nginx on boot time
	# systemctl daemon-reload
	systemctl enable  wg-quick@$wg_name.service
	systemctl start   wg-quick@$wg_name.service
	systemctl disable nginx.service
	systemctl restart nginx.service

	# Copy self to directore in PATH
	cp $0 /usr/local/bin/dm

	# TODO enable Samba after reboot
	# systemctl enable smb.service
	# systemctl start  smb.service
	# systemctl enable samba.service
	# systemctl start  samba.service

	# Info
	echo_green "INSTALLATION COMPLETED SUCCESSFULLY!"
	echo
}


wg_gen_config () {

	wg_ip=`     echo "SELECT ip      FROM server WHERE id = 1;" | sqlite3 $DB_FILE_NAME`
	wg_privkey=`echo "SELECT privkey FROM server WHERE id = 1;" | sqlite3 $DB_FILE_NAME`
	
	server_conf_file=/etc/wireguard/$wg_name.conf
	# Generate server config
	echo "[Interface]" > $server_conf_file
	echo "Address = $wg_ip/$ip_mask" >> $server_conf_file
	echo "ListenPort = $wg_port" >> $server_conf_file
	echo "PrivateKey = $wg_privkey" >> $server_conf_file
	echo >> $server_conf_file

	# Add clients to server config file
	while IFS='|' read -r pubkey ip; do
		echo "[Peer]" >> $server_conf_file
		echo "PublicKey = $pubkey" >> $server_conf_file
		echo "AllowedIPs = $ip/32" >> $server_conf_file
		echo >> $server_conf_file
	done < <(echo "SELECT pubkey, ip FROM clients;" | sqlite3 $DB_FILE_NAME)

	wg_host=`  echo "SELECT hostname FROM server WHERE id = 1;" | sqlite3 $DB_FILE_NAME`
	wg_pubkey=`echo "SELECT pubkey   FROM server WHERE id = 1;" | sqlite3 $DB_FILE_NAME`

	# Generate client configs
	while IFS='|' read -r name privkey ip; do
		if [ -f $WG_CONF_DIR/$name.conf ]; then continue; else client_conf_file=$WG_CONF_DIR/$name.conf; fi
		echo "[Interface]" > $client_conf_file
		echo "PrivateKey = $privkey" >> $client_conf_file
		echo "Address = $ip/$ip_mask" >> $client_conf_file
		echo >> $client_conf_file
		echo "[Peer]" >> $client_conf_file
		echo "AllowedIPs = $allowedips" >> $client_conf_file
		echo "PublicKey = $wg_pubkey" >> $client_conf_file
		echo "Endpoint = $wg_host:$wg_port" >> $client_conf_file
		echo "PersistentKeepalive = 25" >> $client_conf_file
	done < <(echo "SELECT name, privkey, ip FROM clients;" | sqlite3 $DB_FILE_NAME)
}


smb_gen_config () {

	masters=`echo "SELECT name FROM clients WHERE master = 1;" | sqlite3 $DB_FILE_NAME`
	if [ "$masters" = "" ]; then masters=root; fi
	masters=`echo $masters | sed 's/ /, /g'`

	cat > $SMB_CONF_FILE << EOF
[global]
   workgroup = WORKGROUP
   server string = %h server (Samba, Ubuntu)
   interfaces = 127.0.0.0/8 $wg_name
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d
   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[$SHARE_NAME]
   comment = Common shared folder
   path = /var/share
   valid users = $masters
   browseable = no
   read only = no
   guest ok = no
   create mask = 0755

EOF
	while IFS='|' read -r name is_master; do
	if [ "$is_master" -eq 1 ]; then continue; fi
	cat >> $SMB_CONF_FILE << EOF
[$name]
   comment = $name shared folder
   path = $SHARE_DIR/$name
   valid users = $name
   browseable = no
   read only = no
   guest ok = no
   create mask = 0755

EOF
	done < <(echo "SELECT name, master FROM clients;" | sqlite3 $DB_FILE_NAME)
}


add_client () {
	echo "Input name of new client (one word, lowercase). The rest of the input will be used as a comment."
	read -p "Client name: " client_comment 
	echo
	# prevent SQL injection
	client_comment=`echo $client_comment | tr -d "\'\"\0\b\n\r\t\Z\\\%"`
	client_name=`echo $client_comment | cut -f1 -d ' ' | tr '[:upper:]' '[:lower:]'`
	comment=`echo $client_comment | cut -s -f2- -d ' ' | tr -d "'"`
	read -p "Is master? [y/N]: " option
	if [ "$option" == "y" -o "$option" == "Y" ]; then is_master=1; else is_master=0; fi
	read -p "Is hub? [y/N]: "    option
	if [ "$option" == "y" -o "$option" == "Y" ]; then is_hub=1; else is_hub=0; fi

	# Check user exists
	if id $client_name >/dev/null 2>&1;  then echo; echo_red "CLIENT EXISTS!"; return 1; fi

	wg_privkey=`wg genkey`
	wg_pubkey=`wg pubkey <<< $wg_privkey`

	smb_passwd=`< /dev/urandom tr -dc _A-Za-z0-9- | head -c12`
	vnc_passwd=`< /dev/urandom tr -dc _A-Za-z0-9- | head -c8`

	# Add user to DB with fake ip
	echo "INSERT INTO clients (
	                           name,
			           ip,
			           privkey,
			           pubkey,
			           smb_passwd,
			           vnc_passwd,
			           master,
			           hub,
			           comment)
			  values ('$client_name',
				  '0.0.0.0',
			          '$wg_privkey',
				  '$wg_pubkey',
				  '$smb_passwd',
				  '$vnc_passwd',
			 	   $is_master,
				   $is_hub,
				  '$comment');"  | sqlite3 $DB_FILE_NAME

	id=`echo "SELECT MAX(id) FROM clients;"  | sqlite3 $DB_FILE_NAME`
	low_byte=$((id%256))
	hi_byte=$((id/256%256))
	client_ip=$ip_prefix.$hi_byte.$low_byte

	# Check IP is taken
	taken1=`echo "SELECT COUNT(*) FROM clients WHERE ip = '$client_ip';" | sqlite3 $DB_FILE_NAME`
	taken2=`echo "SELECT COUNT(*) FROM server  WHERE ip = '$client_ip';" | sqlite3 $DB_FILE_NAME`
	taken=$((taken1 + taken2))
	if [ "$taken" -gt 0 ]; then client_ip=`find_free_ip`; fi
	if [ "$client_ip" = "0.0.0.0" ];then echo_red "ALL $MAX_CLIENTS IP ADDRESSES ARE TAKEN!"; echo return 1; fi
	# Set actual ip to client
	echo "UPDATE clients SET ip='$client_ip' WHERE id=$id;" | sqlite3 $DB_FILE_NAME

	# Generate WG and Samba configs for new clients
	wg_gen_config
	smb_gen_config

	mkdir -p $SHARE_DIR/$client_name
	chmod go+w $SHARE_DIR/$client_name
	adduser --quiet --gecos $client_name --no-create-home --disabled-password --disabled-login $client_name 1>/dev/null 2>&1
	(echo "$smb_passwd"; echo "$smb_passwd") | smbpasswd -s -a $client_name 1>/dev/null 2>&1

	# Gen windows config
	win_gen_config

	# Restart all
	systemctl daemon-reload
	systemctl restart wg-quick@$wg_name.service
	systemctl restart smb.service
	systemctl restart samba.service

	# Info
	echo
	echo_green "The client \"$client_name\" has been successfully added!"
}


find_free_ip () {
	echo "Looking for free IP address. Please wait..."
	for ((hi_byte=0; hi_byte < 256; hi_byte++)); do
		for ((low_byte=0; low_byte < 256; low_byte++)); do
			if [ $((low_byte + hi_byte)) -eq 0 ]; then continue; fi
			client_ip=$ip_prefix.$hi_byte.$low_byte
			taken1=`echo "SELECT COUNT(*) FROM clients WHERE ip = '$client_ip';" | sqlite3 $DB_FILE_NAME`
			taken2=`echo "SELECT COUNT(*) FROM server  WHERE ip = '$client_ip';" | sqlite3 $DB_FILE_NAME`
			taken=$((taken1 + taken2))
			if [ "$taken" -eq 0 ]; then echo $client_ip; return 0; fi
		done
	done
	echo '0.0.0.0'
}


del_client () {
	show_clients --short
	echo
	read -p "Chose client to delete: " client_id
	if ! [[ $client_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
	exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$client_id);" | sqlite3 $DB_FILE_NAME`
	if [ "$exists" -eq 0 ]; then echo_red "NO SUCH CLIENT!"; return 1; fi
	client_name=`echo "SELECT name FROM clients WHERE id = $client_id;" | sqlite3 $DB_FILE_NAME`
	echo "DELETE FROM clients WHERE id = $client_id;" | sqlite3 $DB_FILE_NAME
	echo "DELETE FROM hubs WHERE hub_id=$client_id;"  | sqlite3 $DB_FILE_NAME
	deluser --quiet $client_name 1>/dev/null 2>&1
	rm -rf $WG_CONF_DIR/$client_name.conf
	# Delete Windows configs
	rm -f $WIN_CONF_DIR/install_$client_name.bat
	rm -f $WIN_CONF_DIR/connect_$client_name.bat
	# Delete share folder
	rm -rf $SHARE_DIR/$client_name

	wg_gen_config
	smb_gen_config
	distribute_configs
	restart_all

	# Info
	echo_green "The client \"$client_name\" has been successfully removed!"
	echo
}


show_clients () {
	is_hub=0
	short=false
	is_client=1
	while [[ "$#" -gt 0 ]]; do
		case $1 in
			-h|--hub|--hubs) is_hub=1   ;;
			-s|--short)      short=true ;;
			-e|--endpoints)  is_client=0       ;;
			*) echo "Unknown parameter passed: $1"; return 1 ;;
		esac
		shift
	done
	# Show clients in short formant
	if $short; then
		echo -e ".separator ') ' \nSELECT id, name FROM clients WHERE hub>=$is_hub AND hub<=$is_client;" | \
		sqlite3 $DB_FILE_NAME
		echo
		return 0
	fi
	# Check online and offline clients
	cur_time=`date +%s`
	time_to_be_online=$((cur_time - $DELAY_ONLINE))

	# WG latest handshakes table
	echo pubkey,status > /tmp/wg-latest-handshakes
	while read pk lh;
		do (( lh > time_to_be_online )) && status=ONLINE || status=OFFLINE
		echo $pk,$status >> /tmp/wg-latest-handshakes
	done < <(wg show $wg_name latest-handshakes)

	# WG endpoints table
	echo pubkey,ep > /tmp/wg-endpoints
	while read pk ep;
		do ep=`echo $ep | cut -f1 -d ':'`
		echo $pk,$ep >> /tmp/wg-endpoints
	done < <(wg show $wg_name endpoints)

	# Print joined table with clients info
	echo -e "
.import --csv --schema temp /tmp/wg-latest-handshakes wglh
.import --csv --schema temp /tmp/wg-endpoints wgep
.mode table
SELECT
id,
name         AS 'Name',
wglh.status  AS 'Status',
master       AS 'M',
hub          AS 'H',
ip           AS 'Wireguard IP',
wgep.ep      AS 'Endpoint IP',
date         AS 'Creation date',
comment      AS 'Comment',
smb_passwd   AS 'Samba passwd',
vnc_passwd   AS 'VNC passwd'
FROM clients LEFT JOIN wglh ON clients.pubkey = wglh.pubkey LEFT JOIN wgep ON clients.pubkey = wgep.pubkey WHERE hub>=$is_hub AND hub<=$is_client;" | \
	sqlite3 $DB_FILE_NAME | \
	sed -e $'s/ONLINE/\e[1;32monline\e[0m/; s/OFFLINE/\e[1;31moffline\e[0m/'
}


hub_setup () {
	echo_blue "All hubs:"
	show_clients --hubs --short
	read -p "Chose hub to setup: " hub_id
	echo
	if ! [[ $hub_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
	exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$hub_id AND hub=1);" | sqlite3 $DB_FILE_NAME`
	if [ "$exists" -eq 0 ]; then echo_red "NO SUCH HUB!"; return 1; fi
	hub_name=`echo "SELECT name FROM clients WHERE id = $hub_id;" | sqlite3 $DB_FILE_NAME`
while :; do
	echo    "Chose option for hub \"$hub_name\":"
	echo -e "S) ${RED}S${NCL}how hub clients"
	echo -e "A) ${RED}A${NCL}dd client to hub"
	echo -e "D) ${RED}D${NCL}elete client from hub"
	echo -e "B) ${RED}B${NCL}ack"
	echo 
	read -p "Your choice: " option

	case $option in
		s|S) #echo "SELECT name FROM clients WHERE id IN (SELECT client_id from hubs WHERE hub_id=$hub_id)" | sqlite3 $DB_FILE_NAME
		     echo_blue "Clients of hub \"$hub_name\":"
		     echo -e "
.import --csv --schema temp /tmp/wg-latest-handshakes wglh
.import --csv --schema temp /tmp/wg-endpoints wgep
.mode table
SELECT
id,
name         AS 'Name',
wglh.status  AS 'Status',
master       AS 'M',
hub          AS 'H',
ip           AS 'Wireguard IP',
wgep.ep      AS 'Endpoint IP',
date         AS 'Creation date',
comment      AS 'Comment',
smb_passwd   AS 'Samba passwd',
vnc_passwd   AS 'VNC passwd'
FROM clients LEFT JOIN wglh ON clients.pubkey = wglh.pubkey LEFT JOIN wgep ON clients.pubkey = wgep.pubkey \
WHERE id in (SELECT client_id from hubs WHERE hub_id=$hub_id);" | \
		     sqlite3 $DB_FILE_NAME | \
		     sed -e $'s/ONLINE/\e[1;32monline\e[0m/; s/OFFLINE/\e[1;31moffline\e[0m/'
		     echo
		     ;;
		a|A)
		     show_clients --endpoints --short
		     read -p "Chose client to add: " client_id
		     if ! [[ $client_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
		     exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$client_id AND hub=0);" | sqlite3 $DB_FILE_NAME`
		     if [ "$exists" -eq 0 ]; then echo_red "NO SUCH ENDPOINT!"; return 1; fi
		     # Delete client from current hub
		     echo "DELETE FROM hubs WHERE client_id=$client_id AND hub_id=$hub_id;" | sqlite3 $DB_FILE_NAME
		     # Count client in other hubs
		     num_client=`echo "SELECT count(*) FROM hubs WHERE client_id = $client_id;" | sqlite3 $DB_FILE_NAME`
		     if [ "$num_client" -gt 0 ]; then
		     	read -p "Delete client from other hubs? [Y/n]: " option
		     	if [ "$option" != "n" -a "$option" != "N" ]; then
		     		echo "DELETE FROM hubs WHERE client_id=$client_id;" | sqlite3 $DB_FILE_NAME
		     	fi
		     fi
		     echo "INSERT INTO hubs (hub_id, client_id) VALUES ($hub_id, $client_id);" | sqlite3 $DB_FILE_NAME
		     # Info
		     client_name=`echo "SELECT name from clients where id=$client_id" | sqlite3 $DB_FILE_NAME`
		     echo
		     echo_green "The client \"$client_name\" has been added to hub \"$hub_name\""
		     echo
		     ;;
		d|D)
		     echo -e ".separator ') ' \nSELECT id, name FROM clients WHERE id IN (SELECT client_id FROM hubs WHERE hub_id=$hub_id);" | sqlite3 $DB_FILE_NAME
		     echo
		     read -p "Chose client to delete: " client_id
		     if ! [[ $client_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
		     exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$client_id AND hub=0);" | sqlite3 $DB_FILE_NAME`
		     if [ "$exists" -eq 0 ]; then echo_red "NO SUCH ENDPOINT!"; return 1; fi
		     echo "DELETE FROM hubs WHERE hub_id=$hub_id AND client_id=$client_id;" | sqlite3 $DB_FILE_NAME
		     # Info
		     client_name=`echo "SELECT name from clients where id=$client_id" | sqlite3 $DB_FILE_NAME`
		     echo
		     echo_green "The client \"$client_name\" has been removed from hub \"$hub_name\""
		     echo
		     ;;
	        b|B)
		     echo_blue Back
		     break
		     ;;
		*)
		     echo_red "Wrong choice!"
		     break
		     ;;
	esac
done
	distribute_configs
}


distribute_configs () {
	# Delete all .bat files from share dirs
	rm -rf $SHARE_DIR/**/*.bat
	# while IFS='|' read -r hub_id client_id; do
	# 	hub_name=`   echo "SELECT name FROM clients WHERE id = $hub_id;"    | sqlite3 $DB_FILE_NAME`
	# 	client_name=`echo "SELECT name FROM clients WHERE id = $client_id;" | sqlite3 $DB_FILE_NAME`
	# 	cp $WIN_CONF_DIR/connect_$client_name.bat $SHARE_DIR/$hub_name
	# done < <(echo "select hub_id, client_id from hubs;" | sqlite3 $DB_FILE_NAME)
	while IFS='|' read -r hub_name client_name; do
		cp $WIN_CONF_DIR/connect_$client_name.bat $SHARE_DIR/$hub_name
	done < <(echo "SELECT hub_name.name, client_name.name FROM hubs JOIN clients AS hub_name ON hubs.hub_id = hub_name.id \
		JOIN clients as client_name ON hubs.client_id = client_name.id;" | sqlite3 $DB_FILE_NAME)
}


get_config () {
	systemctl start nginx.service
while :; do
	echo    "Chose option:"
	echo -e "O) Download ${RED}O${NCL}ne config"
	echo -e "A) Download ${RED}A${NCL}ll configs"
	echo -e "Q) Get ${RED}Q${NCL}R code"
	echo -e "B) ${RED}B${NCL}ack"
	echo 
	read -p "Your choice: " option

	case $option in
		o)
		show_clients --short
		read -p "Chose client: " client_id
		if ! [[ $client_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
			exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$client_id);" | sqlite3 $DB_FILE_NAME`
				if [ "$exists" -eq 0 ]; then echo_red "NO SUCH CLIENT!"; return 1; fi
		client_name=`echo "SELECT name FROM clients WHERE id = $client_id;" | sqlite3 $DB_FILE_NAME`
		download_config $client_name
		;;
		a)
		download_config
		;;
		q)
		show_clients --short
		read -p "Chose client: " client_id
		if ! [[ $client_id =~ $re_num ]]; then echo_red "Wrong input!"; return 1; fi
			exists=`echo "SELECT EXISTS(SELECT * FROM clients WHERE id=$client_id);" | sqlite3 $DB_FILE_NAME`
				if [ "$exists" -eq 0 ]; then echo_red "NO SUCH CLIENT!"; return 1; fi
		client_name=`echo "SELECT name FROM clients WHERE id = $client_id;" | sqlite3 $DB_FILE_NAME`
		qrencode -t ansiutf8 < $WG_CONF_DIR/$client_name.conf
		;;
		b)
		echo_blue Back
		break
		;;
		*)
		echo
		echo_red "Wrong choice!"
		break
		;;
	esac
done
}


download_config () {

	# Get server hostname or IP
	pub_ip=`curl -s -4 ifconfig.me`
	hostname=`dig +short -x $pub_ip`
	if [ "${#hostname}" = "0" ]; then hostname=$pub_ip; else hostname=${hostname:0:-1}; fi 

	echo "Links will be valid for $DOWNLOAD_PERIOD minutes!"
	client_name=$1
	if [ -z "$client_name" ]; then
		cd $WIN_CONF_DIR
		zip -q all_clients.zip *
		cd $WG_CONF_DIR
		zip -q -g $WIN_CONF_DIR/all_clients.zip *
		mv $WIN_CONF_DIR/all_clients.zip $NGINX_SHARE
		expires=`date +%s --date="today + $DOWNLOAD_PERIOD min"`
		md5=`echo -n "$expires/share/all_clients.zip $NGINX_SECRET" | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =`
		link="https://$hostname/share/all_clients.zip?md5=$md5&expires=$expires"
		echo $link

	else
		cp $WIN_CONF_DIR/install_$client_name.bat $NGINX_SHARE
		cp $WIN_CONF_DIR/connect_$client_name.bat $NGINX_SHARE
		cp $WG_CONF_DIR/$client_name.conf         $NGINX_SHARE

		expires=`date +%s --date="today + $DOWNLOAD_PERIOD min"`
		md5_install=`echo -n "$expires/share/install_$client_name.bat $NGINX_SECRET" | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =`
		md5_connect=`echo -n "$expires/share/connect_$client_name.bat $NGINX_SECRET" | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =`
		md5_config=` echo -n "$expires/share/$client_name.conf $NGINX_SECRET"        | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =`
		link_install="https://$hostname/share/install_$client_name.bat?md5=$md5_install&expires=$expires"
		link_connect="https://$hostname/share/connect_$client_name.bat?md5=$md5_connect&expires=$expires"
		link_config="https://$hostname/share/$client_name.conf?md5=$md5_config&expires=$expires"
		echo $link_install
		echo $link_connect
		echo $link_config
		echo
	fi
}


win_gen_config () {
	for client_name in `echo "SELECT name FROM clients;" | sqlite3 $DB_FILE_NAME`; do

	install_bat_name=$WIN_CONF_DIR/install_$client_name.bat
	connect_bat_name=$WIN_CONF_DIR/connect_$client_name.bat

	if [ -f $install_bat_name -a -f $connect_bat_name ]; then continue; fi

	# Get parameters for WG and Samba configs
	IFS='|' read -r privkey ip < <(echo "SELECT privkey, ip FROM clients WHERE name='$client_name' LIMIT 1;" | sqlite3 $DB_FILE_NAME)
	IFS='|' read -r vnc_passwd smb_passwd is_master < <(echo "SELECT vnc_passwd, smb_passwd, master FROM clients WHERE name='$client_name' LIMIT 1;" | sqlite3 $DB_FILE_NAME)
	server_ip=`echo "SELECT ip FROM server WHERE id=1;" | sqlite3 $DB_FILE_NAME`
	vnc_hash=`echo "$vnc_passwd" | $CONFIG_DIR/vncpwd.py`
	vnc_port=`printf "0x%x\n" $VNC_PORT`
	if [ "$is_master" -eq 1 ]; then share_name=share; else share_name=$client_name; fi

	cat > $install_bat_name << EOF
@echo off
:: Check root
net session >nul 2>&1
if not %errorlevel% equ 0 (
echo:
echo You need admin rights to run this script!
timeout 60
exit
)

if exist $WIN_INSTALL_DIR\dm.exe (
    cd $WIN_INSTALL_DIR
    for %%f in (*.conf) do (
        dm.exe /uninstalltunnelservice %%~nf
        net user /delete %%~nf
        del %%f
    )
powershell.exe Stop-Service sshd
)

mkdir $WIN_INSTALL_DIR

curl $PUBLIC_URL/dm.exe -o $WIN_INSTALL_DIR\dm.exe
curl $PUBLIC_URL/family.exe -o $WIN_INSTALL_DIR\family.exe
curl $PUBLIC_URL/familyv.exe -o $WIN_INSTALL_DIR\familyv.exe
curl $PUBLIC_URL/screenhooks64.dll -o $WIN_INSTALL_DIR\screenhooks64.dll

echo [Interface] > $WIN_INSTALL_DIR\\$client_name.conf
echo PrivateKey = $privkey >> $WIN_INSTALL_DIR\\$client_name.conf
echo Address = $ip/$ip_mask >> $WIN_INSTALL_DIR\\$client_name.conf
echo:  >> $WIN_INSTALL_DIR\\$client_name.conf
echo [Peer] >> $WIN_INSTALL_DIR\\$client_name.conf
echo AllowedIPs = $allowedips >> $WIN_INSTALL_DIR\\$client_name.conf
echo PublicKey = $wg_pubkey >> $WIN_INSTALL_DIR\\$client_name.conf
echo Endpoint = $wg_host:$wg_port >> $WIN_INSTALL_DIR\\$client_name.conf
echo PersistentKeepalive = 25 >> $WIN_INSTALL_DIR\\$client_name.conf

$WIN_INSTALL_DIR\dm.exe /installtunnelservice $WIN_INSTALL_DIR\\$client_name.conf

$WIN_INSTALL_DIR\family.exe -install -silent
netsh advfirewall firewall add rule name="FAMILY" dir=in action=allow protocol=TCP localport=59000 remoteip=$ip_prefix.0.0/$ip_mask

:: Change password
reg add "HKLM\SOFTWARE\TightVNC\Server" /v Password /t REG_BINARY /d $vnc_hash /f
reg add "HKLM\SOFTWARE\TightVNC\Server" /v UseVncAuthentication /t REG_DWORD /d 0x1 /f
reg add "HKLM\SOFTWARE\TightVNC\Server" /v RunControlInterface /t REG_DWORD /d 0x0 /f
reg add "HKLM\SOFTWARE\TightVNC\Server" /v RemoveWallpaper /t REG_DWORD /d 0x0 /f
reg add "HKLM\SOFTWARE\TightVNC\Server" /v RfbPort /t REG_DWORD /d $vnc_port /f
timeout 2 > NUL

$WIN_INSTALL_DIR\family.exe -start -silent

:: Shared folder
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLinkedConnections /t REG_DWORD /d 0x1 /f

net use z: \\\\$server_ip\\$share_name /user:$client_name $smb_passwd
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##$server_ip#$share_name /v _LabelFromReg /t REG_SZ /d "SHARE" /f

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Share" /t REG_SZ /d "\"$WIN_INSTALL_DIR\share.bat\"" /f
echo @echo off > $WIN_INSTALL_DIR\share.bat
echo echo Try to mount Share. Please wait! >> $WIN_INSTALL_DIR\share.bat
echo :loop >> $WIN_INSTALL_DIR\share.bat
echo echo Waiting for VPN ready ... >> $WIN_INSTALL_DIR\share.bat
echo timeout 1 ^> NUL >> $WIN_INSTALL_DIR\share.bat
echo ipconfig ^| findstr $ip >> $WIN_INSTALL_DIR\share.bat
echo if %%errorlevel%% equ 1 goto loop >> $WIN_INSTALL_DIR\share.bat
echo net use z: \\\\$server_ip\\$share_name /user:$client_name $smb_passwd >> $WIN_INSTALL_DIR\share.bat
echo echo Share is ready! >> $WIN_INSTALL_DIR\share.bat

:: Add SSH
powershell.exe Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
echo $(cat $HOME/.ssh/id_ed25519.pub) > %ProgramData%\ssh\administrators_authorized_keys
icacls.exe "%ProgramData%\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" /grant ""SYSTEM:F"
powershell.exe "(Get-Content "$env:PROGRAMDATA\ssh\sshd_config") -replace '#Port 22', 'Port $SSH_PORT' | Set-Content "$env:PROGRAMDATA\ssh\sshd_config""
powershell.exe Set-Service sshd -StartupType Automatic
net user /add $client_name $smb_passwd
net localgroup administrators $client_name /add || chcp 65001 && net localgroup Администраторы $client_name /add
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v $client_name /t REG_DWORD /d 0x0 /f
netsh advfirewall firewall add rule name="SSH" dir=in action=allow protocol=TCP localport=$SSH_PORT remoteip=$ip_prefix.0.0/$ip_mask
powershell.exe Start-Service sshd
EOF

cat > $connect_bat_name << EOF
start $WIN_INSTALL_DIR\familyv.exe $ip
EOF
	done
}


rebuild_configs () {
	rm -f  $WIN_CONF_DIR/*
	rm -f  $WG_CONF_DIR/*
	rm -f  $NGINX_SHARE/*
	rm -rf $SHARE_DIR/**/*.bat

	wg_gen_config
	smb_gen_config
	win_gen_config
	distribute_configs
	restart_all

	echo
	echo_green "CONFIGS HAVE BEEN SUCCESSFULLY REBUIT!"
}


restart_all () {
	systemctl daemon-reload
	systemctl restart wg-quick@$wg_name.service
	systemctl restart smb.service
	systemctl restart samba.service
}


cleanup () {
	echo
	echo_green "GOODBYE!"
	echo
	systemctl stop nginx.service
	rm -f $NGINX_SHARE/*
}

#############
# MAIN LOOP #
#############

# Check if this is the first run
if [[ ! -d /etc/wireguard/ ]];
	then
		install
		banner
	else    banner
	fi

trap "cleanup" EXIT

# Show main menu
while :; do
echo 
echo "Chose what you want:"
echo -e $"A) Show ${RED}A${NCL}ll clients"
echo -e $"H) Show ${RED}H${NCL}hubs"
echo -e $"E) Show ${RED}E${NCL}ndpoints"
echo -e $"N) Add ${RED}N${NCL}EW client"
echo -e $"D) ${RED}D${NCL}elete client"
echo -e $"S) Hub ${RED}S${NCL}etup"
echo -e $"G) ${RED}G${NCL}et config"
echo -e $"R) ${RED}R${NCL}ebuild configs (devel)"
echo -e $"Q) ${RED}Q${NCL}uit scrip"
echo 
read -p "your choice: " option
case $option in
        n|N) add_client                     ;;
        a|A) echo_blue "ALL CLIENTS INFO:"
	     show_clients                   ;; 
        d|D) del_client                     ;;
        g|G) get_config                     ;;
        s|S) hub_setup                      ;;
        e|E) echo_blue "ENDPOINTS INFO:"
	     show_clients --endpoints       ;;
	h|H) echo_blue "HUBS INFO:"
	     show_clients --hubs            ;;
        r|R) rebuild_configs                ;;
	q|Q) break                          ;;
        *)   echo_red "Wrong choice!"
	     break                          ;;
esac
done
