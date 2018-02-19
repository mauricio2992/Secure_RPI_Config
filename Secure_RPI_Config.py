#Aplicacion de configuracion de reglas del firewall iptables y proxy Squid
#Version 0.1
#Creado por mauricio2992

import sys
import os
import netifaces

def logo():
	print "................................................................................................................"
	print ".....____________________.....ooooooooooooo......ooooooooooooo.....oooooooooooooo......____________________....."
	print ".....| ---------------- |.....oooooooooooooo.....oooooooooooooo....oooooooooooooo......| ---------------- |....."
	print ".....|| *   *    *   * ||.....oooo      ooooo....oooo      ooooo........oooo...........|| *   *    *   * ||....."
	print ".....||                ||.....oooo        oooo...oooo        oooo.......oooo...........||                ||....."
	print ".....|| *            * ||.....oooo        oooo...oooo        oooo.......oooo...........|| *            * ||....."
	print ".....||                ||.....oooo      ooooo....oooo      ooooo........oooo...........||                ||....."
	print ".....|| *            * ||.....ooooooooooooo......oooooooooooooo.........oooo...........|| *            * ||....."
	print ".....||                ||.....oooooooooooo.......ooooooooooooo..........oooo...........||                ||....."
	print "......\\\  *        *  //......oooo   oooo........oooo...................oooo............\\\  *        *  //......"
	print ".........\\\        //.........oooo    oooo.......oooo...................oooo...............\\\        //........."
	print "............\\\  //............oooo     oooo......oooo..............oooooooooooooo.............\\\  //............"
	print "..............\/..............oooo      oooo.....oooo..............oooooooooooooo...............\/.............."
	print "................................................................................................................"
	print ".........................................#Secure RPI Config v 0.1#.............................................."
	print "................................................................................................................"

def menuInicial():
	os.system("clear")
	logo()
	print chr(27)+"[0;92m"
	print "\n\t\tMENU INICIO\n"
	print "\t1. Configuracion de firewall"
	print "\t2. Configuracion de proxy"
	print "\t3. Configuracion de IDS"
	print "\t4. Configuracion de SELinux"
	print "\t5. Salir"
	print chr(27)+"[0m"

def menuIptables():
	os.system("clear")
	logo()
	print chr(27)+"[0;92m"
	print "\n\t\tCONFIGURACION DE FIREWALL\n"
	print "\t1. Habilitar conexiones SSH desde la red interna a cualquier destino"
	print "\t2. Habilitar conexiones FTP desde la red interna a cualquier destino"
	print "\t3. Habilitar conexiones a un puerto especifico desde la red interna a cualquier destino"
	print "\t4. Configurar nueva regla (avanzado)"
	print "\t5. Listar reglas de iptables"
	print "\t6. Listar reglas nat de iptables"
	print "\t7. Editar script de reglas de iptables"
	print "\t8. Restaurar politicas de firewall por defecto"
	print "\t9. Atras"
	print chr(27)+"[0m"

def menuProxy():
	os.system("clear")
	logo()
	print chr(27)+"[0;92m"
	print "\n\t\tCONFIGURACION DE PROXY\n"
	print "\t1. Ver direccion y puerto"
	print "\t2. Agregar restriccion por dominio"
	print "\t3. Listar restricciones por dominio"
	print "\t4. Agregar restriccion por expresion regular"
	print "\t5. Listar restricciones por expresion regular"
	print "\t6. Agregar restriccion por extension"
	print "\t7. Listar restricciones por extension"
	print "\t8. Ver configuracion de Squid"
	print "\t9. Aplicar cambios"
	print "\t10. Ver logs con Squidview"
	print "\t11. Generar reportes de squid con Sarg"
	print "\t12. Ver reportes de Sarg con w3m"
	print "\t13. Ver logs de Squid de forma continua con tail"
	print "\t14. Ver logs de Squid de forma fija con nano"
	print "\t15. Atras"
	print chr(27)+"[0m"

def menuIDS():
	os.system("clear")
	logo()
	print chr(27)+"[0;92m"
	print "\n\t\tCONFIGURACION DE IDS\n"
	print "\t1. Iniciar Snort visualizando las alertas en pantalla"
	print "\t2. Iniciar Snort guardando las alertas en logs (full)"
	print "\t3. Iniciar Snort como Packet loger, direccion de logs: /var/log/snort/"
	print "\t4. Visualizar el log de alertas"
	print "\t5. Visualizar log especifico"
	print "\t6. Atras"
	print chr(27)+"[0m"

def menuSELinux():
	os.system("clear")
	logo()
	print chr(27)+"[0;92m"
	print "\n\t\tCONFIGURACION DE SELINUX\n"
	print "\t1. Ver logs de SELinux de forma continua con tail"
	print "\t2. Ver logs de SELinux de forma fija con nano"
	print "\t3. Atras"
	print chr(27)+"[0m"

def buscar(id_regla): #funcion para verificar si la regla ya  esta en el script
	try:
		archivo=open("iptables-rules.sh","r")
		linea=archivo.readline()
		for linea in archivo:
			if linea==id_regla:
				return True
		archivo.close()
		return False
	except IOError:
		print chr(27)+"[0;31m"+"No se encuentra el script de reglas de iptables: "+chr(27)+"[0m"+"iptables-rules.sh"
		sys.exit()

def escribir(cadena): #funcion para escribir la regla en el script
	try:
		archivo=open("iptables-rules.sh","a")
		archivo.write(cadena)
		archivo.close()
	except IOError:
		print chr(27)+"[0;31m"+"No se encuentra el script de reglas de iptables: "+chr(27)+"[0m"+"iptables-rules.sh"
		sys.exit()

def nuevaRestriccion(cadena,archivo):
	try:
		archivo=open("/home/pi/Secure_RPI_Config/listas-squid/"+archivo,"a+")
		linea=archivo.readline()
		for linea in archivo:
			if linea==cadena:
				print chr(27)+"[0;31m"+"La restriccion ya se encuentra agregada"+chr(27)+"[0m"
				archivo.close()
				return 0
		archivo.write(cadena)
		archivo.close()
	except IOError:
		print chr(27)+"[0;31m"+"No se encuentra el archivo "+archivo+chr(27)+"[0m"
		sys.exit()

def validate_ip(cadena): #funcion para validar si la cadena ingresada es una direccion ip o una red
	a=cadena.split('.')
	if len(a)!=4:
		return False
	b=a[3].split('/')
	if len(b)==1:
		for x in a:
			if not x.isdigit():
				return False
			i=int(x)
			if i<0 or i>255:
				return False
	elif len(b)==2:
		a.pop(3)
		for x in a:
			if not x.isdigit():
				return False
			i=int(x)
			if i<0 or i>255:
				return False
		if not b[0].isdigit():
			return False
		i=int(b[0])
		if i<0 or i>255:
			return False
		if not b[1].isdigit():
			return False
		i=int(b[1])
		if i<0 or i>32:
			return False
	return True

#inicio del programa
while True:
	menuInicial()
	try:
		opc=int(raw_input("\nElige una opcion: "))
		if opc==1:
			while True:
				menuIptables()
				try:
					opc2=int(raw_input("\nElige una opcion: "))
					if opc2==1:
						if buscar("#SSH\n"):
							print chr(27)+"[0;31m"+"Las conexiones a SSH ya se encuentran habilitadas"+chr(27)+"[0m"
						else:
							escribir("\n#SSH\niptables -A FORWARD -p tcp -s $LAN --dport 22 -m state --state NEW -j ACCEPT\n")
							os.system("sudo ./iptables-rules.sh")
							print chr(27)+"[0;92m"+"conexiones a SSH habilitadas"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==2:
						if buscar("#FTP\n"):
							print chr(27)+"[0;31m"+"Las conexiones a FTP ya se encuentran habilitadas"+chr(27)+"[0m"
						else:
							escribir("\n#FTP\niptables -A FORWARD -p tcp -s $LAN --dport 21 -m state --state NEW -j ACCEPT\n")
							os.system("sudo ./iptables-rules.sh")
							print chr(27)+"[0;92m"+"conexiones a FTP habilitadas"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==3:
						while True: #identificador de la regla
							id_regla=(raw_input("Identificador de la regla: "))
							if len(id_regla.strip())>0:
								if buscar("#"+id_regla+"\n"):
									print chr(27)+"[0;31m"+"La regla "+id_regla+" ya existe"+chr(27)+"[0m"
								else:
									break

							else:
								print chr(27)+"[0;31m"+"El identificador de la regla no puede quedar vacio."+chr(27)+"[0m"
						proto=""
						puerto=0
						while True: #indica el protocolo de la regla
							protocolo=raw_input("Protocolo [tcp(t)/udp(u)]: ")
							if protocolo=="t":
								proto="tcp"
								break
							elif protocolo=="u":
								proto="udp"
								break
							else:
								print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						while True: #indica el puerto
							try:
								puerto=int(raw_input("Puerto [0-65536]: "))
								if puerto>=0 and puerto<=65536:
									break
								else:
									print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							except ValueError:
								print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
						escribir("\n#"+id_regla+"\niptables -A FORWARD -p "+proto+" -s $LAN --dport "+str(puerto)+" -m state --state NEW -j ACCEPT\n")
						os.system("sudo ./iptables-rules.sh")
						print chr(27)+"[0;92m"+"Se agrego la regla "+chr(27)+"[0m"+id_regla+chr(27)+"[0;92m"+" que habilita las conexiones al puerto "+chr(27)+"[0m"+str(puerto)+chr(27)+"[0;92m"+" por el protocolo "+chr(27)+"[0m"+proto
						raw_input("pulse enter para continuar")
					elif opc2==4:
						while True: #identificador de la regla
							id_regla=(raw_input("Identificador de la regla: "))
							if len(id_regla.strip())>0:
								if buscar("#"+id_regla+"\n"):
									print chr(27)+"[0;31m"+"La regla "+id_regla+" ya existe"+chr(27)+"[0m"
								else:
									break
							else:
								print chr(27)+"[0;31m"+"El identificador de la regla no puede quedar vacio."+chr(27)+"[0m"
						while True: #indicar que cadena
							chain=(raw_input("Cadena [INPUT(i)/OUTPUT(o)/FORWARD(f)]: "))
							if chain=="i":
								chain="INPUT"
								break
							elif chain=="o":
								chain="OUTPUT"
								break
							elif chain=="f":
								chain="FORWARD"
								break
							else:
								print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						while True: #indica tipo de protocolo
							protocolo=raw_input("Protocolo [tcp(t)/udp(u)/icmp(i)]: ")
							if protocolo=="t":
								protocolo="tcp"
								break
							elif protocolo=="u":
								protocolo="udp"
								break
							elif protocolo=="i":
								protocolo="ICMP"
								break
							else:
								print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						while True: #idica el origen del trafico
							origen=raw_input("Origen del trafico, puede ser una red o una direccion ip, para cualquier origen 0.0.0.0/0: ")
							if validate_ip(origen):
								break
							else:
								print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						while True: #idica el destino del trafico
							destino=raw_input("Destino del trafico, puede ser una red o una direccion ip, para cualquier destino 0.0.0.0/0: ")
							if validate_ip(destino):
								break
							else:
								print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						while True: #indica puerto origen
							try:
								puertoo=int(raw_input("Puerto origen del trafico, si desea no especificar este ingrese 0: "))
								if puertoo>=0 and puertoo<=65536:
									break
								else:
									print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							except ValueError:
								print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
						while True: #indica puerto destino
							try:
								puertod=int(raw_input("Puerto destino del trafico, si desea no especificar este ingrese 0: "))
								if puertod>=0 and puertod<=65536:
									break
								else:
									print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							except ValueError:
								print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
						if puertoo==0 and puertod==0: # si no se especificaron puertos
							if chain=="FORWARD":
								s="iptables -A FORWARD -p "+protocolo+" -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
							elif chain=="INPUT":
								while True:
									interfaz=raw_input("Interfaz de entrada [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A INPUT -p "+protocolo+" -i $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A INPUT -p "+protocolo+" -i $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							elif chain=="OUTPUT":
								while True:
									interfaz=raw_input("Interfaz de salida [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A OUTPUT -p "+protocolo+" -o $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A OUTPUT -p "+protocolo+" -o $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						elif puertoo!=0 and puertod==0: # solo se especifico puerto origen
							if chain=="FORWARD":
								s="iptables -A FORWARD -p "+protocolo+" --sport "+str(puertoo)+" -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
							elif chain=="INPUT":
								while True:
									interfaz=raw_input("Interfaz de entrada [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A INPUT -p "+protocolo+" --sport "+str(puertoo)+" -i $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A INPUT -p "+protocolo+" --sport "+str(puertoo)+" -i $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							elif chain=="OUTPUT":
								while True:
									interfaz=raw_input("Interfaz de salida [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A OUTPUT -p "+protocolo+" --sport "+str(puertoo)+" -o $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A OUTPUT -p "+protocolo+" --sport "+str(puertoo)+" -o $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						elif puertoo==0 and puertod!=0: # solo se especifico puerto destino
							if chain=="FORWARD":
								s="iptables -A FORWARD -p "+protocolo+" --dport "+str(puertod)+" -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
							elif chain=="INPUT":
								while True:
									interfaz=raw_input("Interfaz de entrada [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A INPUT -p "+protocolo+" --dport "+str(puertod)+" -i $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A INPUT -p "+protocolo+" --dport "+str(puertod)+" -i $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							elif chain=="OUTPUT":
								while True:
									interfaz=raw_input("Interfaz de salida [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A OUTPUT -p "+protocolo+" --dport "+str(puertod)+" -o $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A OUTPUT -p "+protocolo+" --dport "+str(puertod)+" -o $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
						elif puertoo!=0 and puertod!=0: # se especificaron puerto origen y puerto destino
							if chain=="FORWARD":
								s="iptables -A FORWARD -p "+protocolo+" --sport "+str(puertoo)+" --dport "+str(puertod)+" -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
							elif chain=="INPUT":
								while True:
									interfaz=raw_input("Interfaz de entrada [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A INPUT -p "+protocolo+" --sport "+str(puertoo)+" --dport "+str(puertod)+" -i $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A INPUT -p "+protocolo+" --sport "+str(puertoo)+" --dport "+str(puertod)+" -i $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"
							elif chain=="OUTPUT":
								while True:
									interfaz=raw_input("Interfaz de salida [LAN(l)/WAN(w)]: ")
									if interfaz=="l":
										s="iptables -A OUTPUT -p "+protocolo+" --sport "+str(puertoo)+" --dport "+str(puertod)+" -o $ILAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									elif interfaz=="w":
										s="iptables -A OUTPUT -p "+protocolo+" --sport "+str(puertoo)+" --dport "+str(puertod)+" -o $IWAN -s "+origen+" -d "+destino+" -m state --state NEW -j ACCEPT"
										break
									else:
										print chr(27)+"[0;31m"+"El valor ingresado no es valido."+chr(27)+"[0m"

						escribir("\n#"+id_regla+"\n"+s+"\n")
						os.system("sudo ./iptables-rules.sh")
						print chr(27)+"[0;92m"+"Se agrego la regla "+chr(27)+"[0m"+s
						raw_input("pulse enter para continuar")
					elif opc2==5:
						os.system("sudo iptables -nL --line-number")
						raw_input("pulse enter para continuar")
					elif opc2==6:
						os.system("sudo iptables -t nat -nL --line-number")
						raw_input("pulse enter para continuar")
					elif opc2==7:
						os.system("sudo nano iptables-rules.sh")
					elif opc2==8:
						os.system("sudo ./iptables-rules-default.sh && cp iptables-rules-default.sh iptables-rules.sh")
						print chr(27)+"[0;92m"+"restauradas las politicas de firewall por defecto"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==9:
						opc=0
						break
					else:
						print chr(27)+"[0;31m"+"La opcion elegida no es valida"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
				except ValueError:
					print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
					raw_input("pulse enter para continuar")
		elif opc==2:
			while True:
				menuProxy()
				try:
					opc2=int(raw_input("\nElige una opcion: "))
					if opc2==1: #se indica ip y puerto del servidor
						datos=netifaces.ifaddresses("eth1")
						variables=datos.keys()
						if netifaces.AF_INET in variables:
							print chr(27)+"[0;92m"+"\nIP: %s" %datos[netifaces.AF_INET][0]["addr"]
						try:
							archivo=open("/etc/squid/squid.conf","r")
							linea=archivo.readline()
							for linea in archivo:
								if linea.find("http_port")>=0:
									print "Puerto: "+linea[linea.find(" "):len(linea)-1]+chr(27)+"[0m"
									break
							archivo.close()
						except IOError:
							print chr(27)+"[0;31m"+"No se encuentra el archivo de configuracion de Squid"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==2: # se agrega restriccion de dominio al archivo dominios-denegados.txt
						restriccion="."
						while True:
							restriccion+=raw_input("Ingrese el dominio a restringir: ")
							if restriccion.strip()!=".":
								if restriccion.find(".www.")>=0:
									if nuevaRestriccion(restriccion[1:len(restriccion)]+"\n","dominios-denegados.txt")!=0:
										print chr(27)+"[0;92m"+"Se agrego la restriccion de dominio"+chr(27)+"[0m"
									break
								else:
									if nuevaRestriccion(restriccion+"\n","dominios-denegados.txt")!=0:
										print chr(27)+"[0;92m"+"Se agrego la restriccion de dominio"+chr(27)+"[0m"
									break
							else:
								print chr(27)+"[0;31m"+"La restriccion no puede ser vacia"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==3: # se abre el archivo dominios-denegados.txt
						os.system("sudo nano /home/pi/Secure_RPI_Config/listas-squid/dominios-denegados.txt")
					elif opc2==4: # se agrega restriccion de expresion regular al arcivo expresiones-denegadas.txt
						while True:
							restriccion=raw_input("Ingrese la expresion regular a restringir: ")
							if len(restriccion.strip())!=0:
								if nuevaRestriccion(restriccion+"\n","expresiones-denegadas.txt")!=0:
									print chr(27)+"[0;92m"+"Se agrego la restriccion de expresion regular"+chr(27)+"[0m"
								break
							else:
								print chr(27)+"[0;31m"+"La restriccion no puede ser vacia"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==5: # se abre el archivo expresiones-denegadas.txt
						os.system("sudo nano /home/pi/Secure_RPI_Config/listas-squid/expresiones-denegadas.txt")
					elif opc2==6: # se agrega restriccion de extension al archivo extensiones-denegadas.txt
						restriccion="\."
						while True:
							restriccion+=raw_input("Ingrese la extension a restringir: ")
							if restriccion.strip()!="\.":
								if nuevaRestriccion(restriccion+"$\n","extensiones-denegadas.txt")!=0:
									print chr(27)+"[0;92m"+"Se agrego la restriccion de extension"+chr(27)+"[0m"
								break
							else:
								print chr(27)+"[0;31m"+"La restriccion no puede ser vacia"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==7: # se abre el archivo de extensiones denegadas
						os.system("sudo nano /home/pi/Secure_RPI_Config/listas-squid/extensiones-denegadas.txt")
					elif opc2==8: # se abre el archivo de configuracion del servidor squid
						os.system("sudo nano /etc/squid/squid.conf")
					elif opc2==9: # se recarga los archivos de configuracion del servidor squid
						os.system("sudo /etc/init.d/squid reload")
						raw_input("pulse enter para continuar")
					elif opc2==10: # se abre squidview
						os.system("sudo squidview")
					elif opc2==11: # se genera reporte con sarg
						os.system("sudo sarg")
						print chr(27)+"[0;92m"+"Reporte generado"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
					elif opc2==12: # se abre los reportes de sarg con w3m
						os.system("sudo w3m /var/lib/sarg/index.html")
					elif opc2==13: # se visualizan los logs con tail
						os.system("sudo tail -f /var/log/squid/access.log")
					elif opc2==14: # se abre el archivo de logs del servidor squid
						os.system("sudo nano /var/log/squid/access.log")
					elif opc2==15: # atras
						break
					else:
						print chr(27)+"[0;31m"+"La opcion elegida no es valida"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
				except ValueError:
					print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
					raw_input("pulse enter para continuar")
		elif opc==3:
			while True:
				menuIDS()
				try:
					opc2=int(raw_input("\nElige una opcion: "))
					if opc2==1: # se ejecuta snort y se visualizan las alertas en pantalla
						os.system("sudo snort -A console -c /etc/snort/snort.conf -i eth1")
						raw_input("pulse enter para continuar")
					elif opc2==2: # se ejecuta snort y se almacenan las alertas en un archivo
						os.system("sudo snort -A full -c /etc/snort/snort.conf -i eth1")
						raw_input("pulse enter para continuar")
					elif opc2==3: # se ejecuta snort como packet logger
						os.system("sudo snort -l /var/log/snort")
						raw_input("pulse enter para continuar")
					elif opc2==4: # se visualiza el listado de alertas almacenados
						os.system("sudo nano /var/log/snort/alert")
					elif opc2==5: # se visualizan los log de snort como packet loger
						os.system("ls /var/log/snort/")
						log=raw_input("Indique el archivo log que desea ver: ")
						os.system("sudo snort -r /var/log/snort/"+log)
						raw_input("pulse enter para continuar")
					elif opc2==6: # atras
						break
					else:
						print chr(27)+"[0;31m"+"La opcion elegida no es valida"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
				except ValueError:
					print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
					raw_input("pulse enter para continuar")
		elif opc==4:
			while True:
				menuSELinux()
				try:
					opc2=int(raw_input("\nElige una opcion: "))
					if opc2==1:
						os.system("sudo tail -f /var/log/audit/audit.log")
					elif opc2==2:
						os.system("sudo nano /var/log/audit/audit.log")
					elif opc2==3:
						break
					else:
						print chr(27)+"[0;31m"+"La opcion elegida no es valida"+chr(27)+"[0m"
						raw_input("pulse enter para continuar")
				except ValueError:
					print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
					raw_input("pulse enter para continuar")
		elif opc==5:
			break
		else:
			print chr(27)+"[0;31m"+"La opcion elegida no es valida"+chr(27)+"[0m"
			raw_input("pulse enter para continuar")
	except ValueError:
		print chr(27)+"[0;31m"+"El valor ingresado no es un numero."+chr(27)+"[0m"
		raw_input("pulse enter para continuar")

