# Secure_RPI_Config

Secure_RPI_Config es un script creado por mauricio2992 en Python para facilitar la implementación de seguridad perimetral a través de una Raspberry Pi en MIPYMES y el hogar.

Para el buen funcionamiento del mismo es necesario tener instalado Snort, Squid, Sarg, Squidview, w3m y SELinux en el sistema operativo Raspbian e instalar una segunda interfaz de red por uno de los puertos USB, preferiblemente gigabit. Además, se requiere la instalación y configuración de ISC-DHCP-Server con una red local 192.168.92.0/24, asignando a la Raspberry Pi la dirección ip 192.168.92.1 por la interfaz eth1, la eth0 se la reserva para conectarse a la red WAN.

En el archivo /etc/rc.local es necesario agregar la ejecución de iptables-rules.sh con privilegios de root, para que las reglas de iptables queden de forma persistente y se carguen en el inicio del sistema operativo. 

Este script trabaja con las reglas de iptables, como firewall de red, con Squid como servidor proxy web y Snort como sistema de detección de intrusos.

En este repositorio se encuentran los archivos de configuración de Snort y Squid, junto con las reglas de Snort desarrolladas por la comunidad.

Se recomienda ubicar el directorio Secure_RPI_Config en /home/pi/, y cambiar el puerto de escucha del servicio SSH por el 1122.
