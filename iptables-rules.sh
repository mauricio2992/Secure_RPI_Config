#!/bin/sh

#Configuracion de interfaces de red
ILAN="eth1" #interfaz de red LAN
IWAN="eth0" #interfaz de red WAN

#Configuracion de red
LO="127.0.0.1"
RPI="192.168.92.1" #direccion ip de la raspberry
LAN="192.168.92.0/24"
WAN="0.0.0.0/0"

#habilitar enrutamiento
sudo echo "1" > /proc/sys/net/ipv4/ip_forward

#Flush de reglas
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

#Politicas por defecto
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#habilitar conexiones locales
iptables -A INPUT -s $LO -d $LO -i lo -j ACCEPT
iptables -A OUTPUT -d $LO -s $LO -o lo -j ACCEPT

#permitir ping desde red LAN y saliente unicamente a los DNS 8.8.8.8 y 9.9.9.9
iptables -A INPUT -i $ILAN  -s $LAN -p ICMP -j ACCEPT
iptables -A OUTPUT -o $ILAN -p ICMP -s $LAN -j ACCEPT
iptables -A OUTPUT -o $IWAN -p ICMP -s $WAN -j ACCEPT
iptables -A INPUT -i $IWAN  -s 9.9.9.9,8.8.8.8 -d $WAN -p ICMP -j ACCEPT

#politicas de aceptacion de conexiones establecidas
iptables -A FORWARD -s $LAN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -d $LAN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -s $LAN -d $RPI -i $ILAN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d $LAN -s $RPI -o $ILAN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -d $WAN -i $IWAN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -s $WAN -o $IWAN -m state --state ESTABLISHED,RELATED -j ACCEPT

#politicas de aceptacion de conexion ssh unicamente desde LAN
iptables -A INPUT -p tcp --dport 1122 -s $LAN -d $RPI -i $ILAN -m state --state NEW  -j ACCEPT

#politicas de conexiones desde la RPI para navegacion web
iptables -A INPUT -p tcp --dport 8080 -s $LAN -d $RPI -i $ILAN -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p udp -s $WAN -o $IWAN --dport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp -s $WAN -o $IWAN --dport 80 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp -s $WAN -o $IWAN --dport 443 -m state --state NEW -j ACCEPT

#permitir enrutamiento de nuevas conexiones http
iptables -A FORWARD -p tcp -s $LAN --dport 80 -m state --state NEW -j ACCEPT

#permitir enrutamiento de nuevas conexiones https
iptables -A FORWARD -p tcp -s $LAN --dport 443 -m state --state NEW -j ACCEPT

#permitir enrutamiento de nuevas conexiones dns
iptables -A FORWARD -p udp -s $LAN --dport 53 -m state --state NEW  -j ACCEPT

#permitir enrutamiento de nuevas conexiones POP
iptables -A FORWARD -p tcp -s $LAN --dport 110 -m state --state NEW  -j ACCEPT

#permitir enrutamiento de nuevas conexiones IMAP
iptables -A FORWARD -p tcp -s $LAN --dport 143 -m state --state NEW  -j ACCEPT

#permitir enrutamiento de nuevas conexiones POP SSL
iptables -A FORWARD -p tcp -s $LAN --dport 995 -m state --state NEW  -j ACCEPT
 
#permitir enrutamiento de nuevas conexiones IMAP SSL
iptables -A FORWARD -p tcp -s $LAN --dport 993 -m state --state NEW  -j ACCEPT

#permitir enrutamiento de nuevas conexiones SMTP
iptables -A FORWARD -p tcp -s $LAN --dport 25 -m state --state NEW  -j ACCEPT

#enmascaramiento del trafico de la red interna
iptables -t nat -A POSTROUTING -s $LAN -o $IWAN -j MASQUERADE
