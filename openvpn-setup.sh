#!/bin/bash
#easy openvpn server setup for ubuntu

read -p "port (1-65535): " PORT
read -p "protocol (udp or tcp): " PROTOCOL
read -p "encrypt (y or n): " ENCRYPT
read -p "hmac (y or n): " HMAC
read -p "xor scramble (y or n): " SCRAMBLE
read -p "compress (y or n): " COMPRESS_YN
read -p "network number (0-255): " NETWORK_NUM
read -p "service name affix (no special chars): " SERVICE_AFFIX

if [ "$COMPRESS_YN" == y ]; then
  COMPRESS=lz4
fi

if [ "$ENCRYPT" == y ]; then
  CIPHER=aes-128-cbc
else
  CIPHER=none
fi

if [ "$HMAC" == y ]; then
  AUTH=sha256
else
  AUTH=none
fi

if [ "$SCRAMBLE" == y ]; then
  SCRAMBLE_LINE="scramble xormask $(hexdump -n 8 -e '4/4 "%08x" 1 "\n"' /dev/urandom)"
fi

if [ -z "$(command -v openvpn)" ]; then
  OPENVPN_VERSION=2.4.6
  echo "installing openvpn from source"
  sudo apt install -y gcc make libssl-dev liblz4-dev liblzo2-dev libpam-dev
  echo "download openvpn $OPENVPN_VERSION"
  wget --quiet "https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.xz" -O- | tar xfJ -
  cd "openvpn-$OPENVPN_VERSION"
  for PATCH in 02-tunnelblick-openvpn_xorpatch-a 03-tunnelblick-openvpn_xorpatch-b 04-tunnelblick-openvpn_xorpatch-c 05-tunnelblick-openvpn_xorpatch-d 06-tunnelblick-openvpn_xorpatch-e; do
    echo "downloading patch $PATCH"
    wget --quiet "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-${OPENVPN_VERSION}/patches/${PATCH}.diff"
    patch -Np1 -i "$PATCH.diff"
  done
  ./configure
  make
  sudo make install
  cd ..
  rm -rf "openvpn-$OPENVPN_VERSION"
fi

EASYRSA_VERSION=3.0.5
if [ ! -d "EasyRSA-$EASYRSA_VERSION" ]; then
  echo "downloading easyrsa"
  wget --quiet "https://github.com/OpenVPN/easy-rsa/releases/download/v$EASYRSA_VERSION/EasyRSA-nix-$EASYRSA_VERSION.tgz" -O- | tar xfz -
fi

if [ ! -d "pki" ]; then
  echo "generating keys"
  easyrsa="EasyRSA-$EASYRSA_VERSION/easyrsa"
  $easyrsa init-pki
  $easyrsa --batch build-ca nopass
  $easyrsa gen-dh
  EASYRSA_CERT_EXPIRE=3650 $easyrsa build-server-full server nopass
  EASYRSA_CERT_EXPIRE=3650 $easyrsa build-client-full client nopass
  EASYRSA_CRL_DAYS=3650 $easyrsa gen-crl
  openvpn --genkey --secret tc.key
fi

#network configuration
cat > run-openvpn.sh << EOF
#!/bin/bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
IP=\$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [ -z "\$(sudo iptables -t nat -L POSTROUTING -n | grep -F 10.$NETWORK_NUM.0.0/24)" ]; then
  echo "adding iptables rule"
  sudo iptables -t nat -A POSTROUTING -s 10.$NETWORK_NUM.0.0/24 ! -d 10.$NETWORK_NUM.0.0/24 -j SNAT --to \$IP
fi
EOF

chmod +x run-openvpn.sh

#run-openvpn only contains routing rules so far
source run-openvpn.sh

echo 'cd "$(dirname "$BASH_SOURCE")"
exec sudo openvpn --config server.ovpn' >> run-openvpn.sh

SERVICE_NAME="openvpn-server-$SERVICE_AFFIX"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
if [ ! -f "$SERVICE_FILE" ]; then
  echo "installing systemd service"
  echo "[Unit]
Description=$SERVICE_NAME
After=network.target
After=systemd-user-sessions.service
After=network-online.target

[Service]
ExecStart='$(readlink -f run-openvpn.sh)'

[Install]
WantedBy=multi-user.target" | sudo tee "$SERVICE_FILE" > /dev/null
  sudo systemctl daemon-reload
  echo "installed systemd service, run sudo systemctl start|enable $SERVICE_NAME to use"
fi

#generate server configuration
echo "port $PORT
proto $PROTOCOL
sndbuf 0
rcvbuf 0
compress $COMPRESS
dev tun
ca pki/ca.crt
cert pki/issued/server.crt
key pki/private/server.key
dh pki/dh.pem
auth $AUTH
tls-crypt tc.key
topology subnet
duplicate-cn
server 10.$NETWORK_NUM.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 128.52.130.209\"
keepalive 10 60
cipher $CIPHER
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify pki/crl.pem
$SCRAMBLE_LINE" > server.ovpn

#generate client.conf
echo "finding public ip address"
PUB_IP=`curl -s4 https://checkip.amazonaws.com/`
echo "client
compress $COMPRESS
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $PUB_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth $AUTH
cipher $CIPHER
setenv opt block-outside-dns
verb 3
<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(cat pki/issued/client.crt)
</cert>
<key>
$(cat pki/private/client.key)
</key>
<tls-crypt>
$(cat tc.key)
</tls-crypt>
$SCRAMBLE_LINE" > client.ovpn

echo "done - client config in client.ovpn"
