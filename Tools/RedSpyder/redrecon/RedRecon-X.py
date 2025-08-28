#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# RedRecon-X RedSpyder Security Edition
#La presente herramienta de reconocimiento de red es una herramienta de exploración de red
#que utiliza un enfoque de escaneo de puertos y exploración de servicios para identificar
#puertos abiertos y servicios disponibles en una red.
#Autor: gstxx + un poco de IA para varirar

import sys
import os
import re
import requests
import json
import time
import socket
import threading
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QGroupBox, QSplitter, QComboBox,
                             QStatusBar, QProgressBar, QMessageBox, QFrame)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, QTimer, Qt, QSize, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap
import urllib.request

def obtener_ip_publica():
    try:
        return urllib.request.urlopen('https://api.ipify.org').read().decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

class EscanerPuertosHilo(QThread):
    progreso = pyqtSignal(int, str)
    finalizado = pyqtSignal(dict)
    
    def __init__(self, ip: str, puertos: List[int], reintentos: int = 1, 
                 timeout_conexion: float = 0.3, max_hilos: int = 100):
        super().__init__()
        self.ip = ip
        self.puertos = puertos
        self.reintentos = reintentos
        self.timeout_conexion = timeout_conexion
        self.max_hilos = max_hilos
        self.detener = False
        self._firmas_servicios = [(r"ssh","SSH"),(r"telnet","Telnet"),(r"rlogin","Rlogin"),(r"rexec","Rexec"),(r"sftp","SFTP"),(r"ftp","FTP"),(r"ftps","FTPS"),(r"scp","SCP"),(r"smtp","SMTP"),(r"esmtp","SMTP"),(r"pop3","POP3"),(r"imap","IMAP"),(r"submission","SMTP Submission"),(r"microsoft exchange","MS Exchange"),(r"lotus","IBM Lotus Notes"),(r"http","HTTP"),(r"https","HTTPS"),(r"proxy","HTTP Proxy"),(r"squid","Squid Proxy"),(r"varnish","Varnish Cache"),(r"apache","Apache HTTPD"),(r"nginx","Nginx"),(r"iis","Microsoft IIS"),(r"tomcat","Apache Tomcat"),(r"jboss","JBoss/Wildfly"),(r"weblogic","Oracle WebLogic"),(r"websphere","IBM WebSphere"),(r"glassfish","GlassFish"),(r"php","PHP Server"),(r"asp.net","ASP.NET"),(r"django","Django"),(r"flask","Flask"),(r"gunicorn","Gunicorn"),(r"uwsgi","uWSGI"),(r"mysql","MySQL"),(r"mariadb","MariaDB"),(r"postgres","PostgreSQL"),(r"oracle","Oracle DB"),(r"mssql","MS SQL"),(r"sql","Generic SQL"),(r"mongodb","MongoDB"),(r"couchdb","CouchDB"),(r"cassandra","Cassandra"),(r"redis","Redis"),(r"elasticsearch","Elasticsearch"),(r"riak","Riak"),(r"influxdb","InfluxDB"),(r"prometheus","Prometheus TSDB"),(r"memcached","Memcached"),(r"neo4j","Neo4j"),(r"rdp","RDP"),(r"terminal services","RDP"),(r"vnc","VNC"),(r"x11","X11"),(r"citrix","Citrix ICA"),(r"ldap","LDAP"),(r"kerberos","Kerberos"),(r"radius","RADIUS"),(r"tacacs","TACACS"),(r"active directory","Active Directory"),(r"smb","SMB"),(r"netbios","NetBIOS"),(r"nfs","NFS"),(r"afp","AFP"),(r"rsync","Rsync"),(r"pptp","PPTP"),(r"openvpn","OpenVPN"),(r"ike","IPSec/IKE"),(r"l2tp","L2TP"),(r"wireguard","WireGuard"),(r"anyconnect","Cisco AnyConnect"),(r"fortigate","Fortinet VPN"),(r"globalprotect","Palo Alto GlobalProtect"),(r"xmpp","XMPP"),(r"jabber","XMPP/Jabber"),(r"irc","IRC"),(r"slack","Slack API"),(r"teams","MS Teams API"),(r"snmp","SNMP"),(r"ntp","NTP"),(r"syslog","Syslog"),(r"dns","DNS"),(r"dhcp","DHCP"),(r"tftp","TFTP"),(r"bgp","BGP"),(r"ospf","OSPF"),(r"modbus","Modbus"),(r"dnp3","DNP3"),(r"bacnet","BACnet"),(r"siemens","Siemens S7"),(r"opc","OPC UA/DA"),(r"mqtt","MQTT"),(r"coap","CoAP"),(r"docker","Docker API"),(r"kubernetes","Kubernetes API"),(r"etcd","etcd"),(r"consul","Consul"),(r"vault","HashiCorp Vault"),(r"jenkins","Jenkins"),(r"gitlab","GitLab"),(r"gitea","Gitea"),(r"harbor","Harbor"),(r"sonarqube","SonarQube"),(r"cups","CUPS"),(r"plex","Plex Media"),(r"wowza","Wowza Streaming"),(r"rtsp","RTSP"),(r"sip","SIP"),(r"teamspeak","TeamSpeak"),(r"steam","Steam Server"),(r"minecraft","Minecraft Server"),(r"bitcoin","Bitcoin Node"),(r"monero","Monero Node"),(r"litecoin","Litecoin Node")]

    def run(self):
        abiertos = {}
        total_puertos = len(self.puertos)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_hilos) as executor:
            futuros = {executor.submit(self.probar_puerto, puerto): puerto for puerto in self.puertos}
            
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros)):
                if self.detener:
                    break
                
                puerto = futuros[futuro]
                progreso = int((i+1)/total_puertos*100)
                
                try:
                    if futuro.result():
                        servicio = self.banner_grabbing(puerto)
                        abiertos[puerto] = servicio
                        self.progreso.emit(progreso, f"[ + ] {puerto}: {servicio}")
                    else:
                        self.progreso.emit(progreso, f"[ - ] {puerto}: Cerrado")
                except Exception as e:
                    self.progreso.emit(progreso, f"[ ! ] Error puerto {puerto}: {str(e)}")
        
        self.finalizado.emit(abiertos)

    def probar_puerto(self, puerto: int) -> bool:
        for _ in range(self.reintentos):
            if self.detener:
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout_conexion)
                    if s.connect_ex((self.ip, puerto)) == 0:
                        return True
            except (socket.timeout, socket.error):
                time.sleep(0.1)
        return False

    def banner_grabbing(self, puerto: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((self.ip, puerto))
                banner = s.recv(2048).decode(errors="ignore").strip()
                
                if not banner:
                    return self._obtener_servicio_por_puerto(puerto) or "Abierto (sin banner)"
                
                servicio = self.identificar_servicio(banner)
                return servicio if servicio != "Desconocido" else self._obtener_servicio_por_puerto(puerto) or f"Desconocido ({banner[:50]})"
        except (socket.timeout, socket.error, ConnectionResetError):
            return self._obtener_servicio_por_puerto(puerto) or "Abierto (sin respuesta)"


    def identificar_servicio(self, banner: str) -> str:
        banner_lower = banner.lower()
        for patron, nombre in self._firmas_servicios:
            if re.search(patron, banner_lower):
                return f"{nombre} ({banner})"
        return "Desconocido"

    def _obtener_servicio_por_puerto(self, puerto: int) -> Optional[str]:
        try:
            return f"{socket.getservbyport(puerto)} (por puerto)"
        except (OSError, socket.error):
            return None

    def stop(self):
        self.detener = True
        self.wait()

class AplicacionRastreadorIP(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RedRecon - X ")
        self.setGeometry(100, 100, 1600, 900)
        
        # almacenar datos
        self.datos_ip_actual = {}
        self.ips_rastreadas = {}
        self.intervalo_actualizacion = 300000  #segundos
        self.ruta_html = os.path.abspath("mapa_satelital.html")
        self.escaner_activo = None
        self.ultimos_mensajes = set()
        
        # configurar interfaz
        self.configurar_interfaz()
        
        self.temporizador = QTimer()
        self.temporizador.timeout.connect(self.actualizar_todos_datos)
        self.temporizador.start(self.intervalo_actualizacion * 1000)
        
        self.rastrear_ip(obtener_ip_publica())  #IP por defecto

    def configurar_interfaz(self):
        widget_central = QWidget()
        self.setCentralWidget(widget_central)
        
        layout_principal = QHBoxLayout(widget_central)
        layout_principal.setSpacing(0)
        layout_principal.setContentsMargins(0, 0, 0, 0)
        
        panel_izquierdo = QFrame()
        panel_izquierdo.setFrameStyle(QFrame.StyledPanel)
        panel_izquierdo.setMaximumWidth(450)
        panel_izquierdo.setStyleSheet("QFrame { background-color: #141414; }")
        layout_izquierdo = QVBoxLayout(panel_izquierdo)
        layout_izquierdo.setContentsMargins(10, 10, 10, 10)
        
        etiqueta_titulo = QLabel("Cazador de IPs")
        etiqueta_titulo.setFont(QFont("Arial", 16, QFont.Bold))
        etiqueta_titulo.setAlignment(Qt.AlignCenter)
        etiqueta_titulo.setStyleSheet("padding: 10px; background-color: #2c3e50; color: white; border-radius: 5px;")
        layout_izquierdo.addWidget(etiqueta_titulo)
        
        grupo_busqueda = QGroupBox("Cazar IP")
        grupo_busqueda.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #2c3e50; border-radius: 5px; margin-top: 1em; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }")
        layout_busqueda = QVBoxLayout(grupo_busqueda)
        
        self.entrada_ip = QLineEdit()
        self.entrada_ip.setPlaceholderText("Ingresa una dirección IP ")
        self.entrada_ip.setText(obtener_ip_publica())
        self.entrada_ip.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px; background-color: #260000; color: #f5f5f5; border: 1px solid #c80000; border-radius: 4px; padding: 8px;")
        layout_busqueda.addWidget(self.entrada_ip)
        
        boton_buscar = QPushButton("Localizar")
        boton_buscar.clicked.connect(self.al_rastrear_ip)
        boton_buscar.setStyleSheet("QPushButton {background-color: #e74c3c; color: white; font-weight: bold; padding: 10px; border: none; border-radius: 4px;} QPushButton:hover {background-color: #c0392b;}")
        layout_busqueda.addWidget(boton_buscar)
        
        layout_intervalo = QHBoxLayout()
        layout_intervalo.addWidget(QLabel("Actualización:"))
        
        self.combo_intervalo = QComboBox()
        self.combo_intervalo.addItems(["10 segundos", "30 segundos", "1 minuto", "5 minutos", "10 minutos", "30 minutos", "1 hora", "2 horas", "4 horas", "8 horas", "12 horas", "1 dia", "2 dias", "3 dias"])
        self.combo_intervalo.setCurrentIndex(1)
        self.combo_intervalo.currentIndexChanged.connect(self.cambiar_intervalo_actualizacion)
        layout_intervalo.addWidget(self.combo_intervalo)
        
        layout_busqueda.addLayout(layout_intervalo)
        layout_izquierdo.addWidget(grupo_busqueda)
        
        grupo_info = QGroupBox("Información de Geolocalización")
        grupo_info.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #2c3e50; border-radius: 5px; margin-top: 1em; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }")
        layout_info = QVBoxLayout(grupo_info)
        
        self.mostrador_info = QTextEdit()
        self.mostrador_info.setReadOnly(True)
        self.mostrador_info.setStyleSheet("border: 1px solid #ddd; border-radius: 4px; background-color: #260000; color: #f5f5f5; border: 1px solid #c80000;")
        layout_info.addWidget(self.mostrador_info)
        
        layout_izquierdo.addWidget(grupo_info)
        
        grupo_puertos = QGroupBox("Escáner de Puertos")
        grupo_puertos.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #2c3e50; border-radius: 5px; margin-top: 1em; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }")
        layout_puertos = QVBoxLayout(grupo_puertos)
        
        self.mostrador_puertos = QTextEdit()
        self.mostrador_puertos.setReadOnly(True)
        self.mostrador_puertos.setMaximumHeight(150)
        self.mostrador_puertos.setStyleSheet("border: 1px solid #ddd; border-radius: 4px; background-color: #260000; color: #f5f5f5; border: 1px solid #c80000; font-size: 10px;")
        layout_puertos.addWidget(self.mostrador_puertos)
        
        self.barra_progreso_puertos = QProgressBar()
        self.barra_progreso_puertos.setTextVisible(False)
        self.barra_progreso_puertos.setVisible(False)
        layout_puertos.addWidget(self.barra_progreso_puertos)
        
        layout_izquierdo.addWidget(grupo_puertos)
        
        grupo_historial = QGroupBox("IPs Rastreadas Recientemente")
        grupo_historial.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #2c3e50; border-radius: 5px; margin-top: 1em; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }")
        layout_historial = QVBoxLayout(grupo_historial)
        
        self.lista_historial = QComboBox()
        self.lista_historial.currentTextChanged.connect(self.al_seleccionar_historial)
        self.lista_historial.setStyleSheet("padding: 5px; border: 1px solid #ccc; border-radius: 4px;")
        layout_historial.addWidget(self.lista_historial)
        
        layout_control = QHBoxLayout()
        self.boton_actualizar = QPushButton("Actualizar Ahora")
        self.boton_actualizar.clicked.connect(self.actualizar_todos_datos)
        self.boton_actualizar.setStyleSheet("QPushButton {background-color: #e74c3c; color: white; font-weight: bold; padding: 10px; border: none; border-radius: 4px;} QPushButton:hover {background-color: #c0392b;}")
        layout_control.addWidget(self.boton_actualizar)
        
        self.boton_exportar = QPushButton("Exportar Datos")
        self.boton_exportar.clicked.connect(self.exportar_datos)
        self.boton_exportar.setStyleSheet("QPushButton {background-color: #e74c3c; color: white; font-weight: bold; padding: 10px; border: none; border-radius: 4px;} QPushButton:hover {background-color: #c0392b;}")
        layout_control.addWidget(self.boton_exportar)
        
        layout_historial.addLayout(layout_control)
        layout_izquierdo.addWidget(grupo_historial)
        
        layout_izquierdo.addStretch()
        
        panel_derecho = QFrame()
        panel_derecho.setFrameStyle(QFrame.StyledPanel)
        layout_derecho = QVBoxLayout(panel_derecho)
        layout_derecho.setContentsMargins(0, 0, 0, 0)
        layout_derecho.setSpacing(0)
        
        self.vista_web = QWebEngineView()
        layout_derecho.addWidget(self.vista_web)
        
        self.barra_progreso = QProgressBar()
        self.barra_progreso.setMaximumHeight(6)
        self.barra_progreso.setTextVisible(False)
        self.barra_progreso.setVisible(False)
        layout_derecho.addWidget(self.barra_progreso)
        
        divisor = QSplitter(Qt.Horizontal)
        divisor.addWidget(panel_izquierdo)
        divisor.addWidget(panel_derecho)
        divisor.setSizes([450, 1150])
        
        layout_principal.addWidget(divisor)
        
        self.statusBar().showMessage("Listo")
        
        self.vista_web.loadStarted.connect(self.inicio_carga_pagina)
        self.vista_web.loadFinished.connect(self.fin_carga_pagina)
        self.vista_web.loadProgress.connect(self.progreso_carga_pagina)

    def rastrear_ip(self, direccion_ip):
        try:
            self.statusBar().showMessage(f"Rastreando IP: {direccion_ip}...")
            
            if self.escaner_activo and self.escaner_activo.isRunning():
                self.escaner_activo.stop()
            
            respuesta = requests.get(f"http://ip-api.com/json/{direccion_ip}", timeout=10)
            datos = respuesta.json()
            
            if datos["status"] == "success":
                self.datos_ip_actual = datos
                self.ips_rastreadas[direccion_ip] = datos
                
                if direccion_ip not in [self.lista_historial.itemText(i) for i in range(self.lista_historial.count())]:
                    self.lista_historial.addItem(direccion_ip)
                
                self.actualizar_mostrador_info()
                self.actualizar_mapa_satelital()
                
                # Iniciar portscanner
                self.iniciar_escaneo_puertos(direccion_ip)
                
                self.guardar_en_historial(direccion_ip, datos)
                
                self.statusBar().showMessage(f"IP {direccion_ip} rastreada con éxito")
            else:
                mensaje_error = f"Error al rastrear la IP {direccion_ip}: {datos.get('message', 'Error desconocido, contacta a gstxx')}"
                self.mostrador_info.setText(mensaje_error)
                self.statusBar().showMessage(mensaje_error)
                
        except Exception as e:
            mensaje_error = f"Error: {str(e)}"
            self.mostrador_info.setText(mensaje_error)
            self.statusBar().showMessage(mensaje_error)

    def iniciar_escaneo_puertos(self, ip):
        self.mostrador_puertos.clear()
        self.mostrador_puertos.append(f"Iniciando escaneo de puertos en {ip}...")
        self.barra_progreso_puertos.setVisible(True)
        self.barra_progreso_puertos.setValue(0)
        
        puertos_comunes = [7,19,20,21,22,23,25,37,49,53,67,68,69,79,80,88,102,110,111,113,119,123,135,137,138,139,143,161,162,179,194,201,264,318,381,382,383,389,427,443,445,464,465,500,502,512,513,514,515,520,524,530,531,532,540,548,554,560,563,587,593,623,626,631,636,639,646,647,648,666,691,700,705,808,873,902,989,990,992,993,995,1025,1026,1027,1028,1029,1080,1194,1433,1434,1521,1720,1723,1741,1755,1812,1813,1883,1900,1985,2000,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2483,2484,25565,2601,2602,2604,2605,2607,3128,3260,3268,3269,3306,3389,3478,3632,3690,3702,4369,4786,4840,5000,5001,5060,5061,5201,5222,5223,5432,5555,5631,5632,5666,5672,5900,5901,5984,5985,5986,6000,6379,6443,6514,6660,6667,7000,7001,7077,7474,7547,7676,7777,8000,8008,8080,8081,8086,8087,8161,8181,8222,8243,8333,8443,8500,8554,8600,8834,8888,9000,9042,9080,9090,9091,9100,9160,9200,9300,9418,9443,9527,9543,9600,9999,10000,11211,15672,16010,18080,1935,27017,27018,27019,28017,37777,44818,47808,50000,50070,50075,50090,54321,55443,55555,56000,5683,60000,61616,63790,65535]
        self.escaner_activo = EscanerPuertosHilo(ip, puertos_comunes)
        self.escaner_activo.progreso.connect(self.actualizar_progreso_puertos)
        self.escaner_activo.finalizado.connect(self.finalizar_escaneo_puertos)
        self.escaner_activo.start()

    def actualizar_progreso_puertos(self, progreso, mensaje):
        self.barra_progreso_puertos.setValue(progreso)
        
        if mensaje and mensaje not in self.ultimos_mensajes:
            if "[ + ]" in mensaje or "[ ! ]" in mensaje:
                self.mostrador_puertos.append(mensaje)
            
            contenido = self.mostrador_puertos.toPlainText()
            lineas = contenido.split('\n')
            if len(lineas) > 20:
                self.mostrador_puertos.setPlainText('\n'.join(lineas[-20:]))
                
            self.ultimos_mensajes.add(mensaje)
            if len(self.ultimos_mensajes) > 50:
                self.ultimos_mensajes.clear()

    def finalizar_escaneo_puertos(self, puertos_abiertos):
        self.barra_progreso_puertos.setVisible(False)
        self.mostrador_puertos.append(f"Escaneo completado. Puertos abiertos: {len(puertos_abiertos)}")

    def actualizar_mostrador_info(self):
        datos = self.datos_ip_actual
        if not datos:
            return
            
        texto_info = f"""
        <div style="font-family: Arial, sans-serif;">
            <h3 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px;">
                Información de Geolocalización
            </h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 30%;">IP:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('query', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">País:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('country', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Región:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('regionName', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Ciudad:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('city', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Código Postal:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('zip', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Coordenadas:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">Lat {datos.get('lat', 'N/A')}, Lon {datos.get('lon', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Zona Horaria:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('timezone', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">ISP:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('isp', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Organización:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('org', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">AS:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee;">{datos.get('as', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Última actualización:</td>
                    <td style="padding: 8px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            </table>
        </div>
        """
        
        self.mostrador_info.setHtml(texto_info)

    def actualizar_mapa_satelital(self):
        datos = self.datos_ip_actual
        if not datos or "lat" not in datos or "lon" not in datos:
            return
            
        lat, lon = datos["lat"], datos["lon"]
        ip = datos.get("query", "Desconocida")
        ciudad = datos.get("city", "Desconocida")
        pais = datos.get("country", "Desconocido")
        
        lat_formateada = f"{lat:.4f}"
        lon_formateada = f"{lon:.4f}"
        
        codigo_html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="utf-8">
            <title>Rastreador IP con Vista Satelital</title>
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
            <style>
                html, body, #mapa {{ 
                    width: 100%; 
                    height: 100%; 
                    margin: 0; 
                    padding: 0; 
                    overflow: hidden; 
                }}
                .leaflet-control-attribution {{
                    display: none !important;
                }}
                .popup-personalizado .leaflet-popup-content-wrapper {{
                    background: rgba(42, 42, 42, 0.9);
                    color: white;
                    border-radius: 8px;
                    border: 2px solid #e74c3c;
                }}
                .popup-personalizado .leaflet-popup-tip {{
                    background: #e74c3c;
                }}
                .etiqueta-info {{
                    background: rgba(42, 42, 42, 0.9);
                    padding: 10px 15px;
                    border-radius: 5px;
                    border: 2px solid #e74c3c;
                    color: white;
                    font-family: Arial, sans-serif;
                    font-size: 14px;
                    font-weight: bold;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
                }}
            </style>
        </head>
        <body>
            <div id="mapa"></div>
            <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
            <script>
                var mapa = L.map('mapa', {{
                    zoomControl: true,
                    attributionControl: false
                }}).setView([{lat}, {lon}], 10);
                
                var capaSatelital = L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}.png', {{
                    maxZoom: 19
                }}).addTo(mapa);
                
                // Círculo con popup
                var circulo = L.circle([{lat}, {lon}], {{
                    color: '#e74c3c',
                    fillColor: '#e74c3c',
                    fillOpacity: 0.2,
                    radius: 5000
                }}).addTo(mapa);
                
                circulo.bindPopup(`
                    <div style="font-family: Arial, sans-serif; min-width: 200px;">
                        <h3 style="margin: 0 0 10px 0; color: #e74c3c; border-bottom: 1px solid #e74c3c; padding-bottom: 5px;">
                            <span style="display: inline-block; width: 12px; height: 12px; background: #e74c3c; border-radius: 50%; margin-right: 8px;"></span>
                            Ubicación de IP
                        </h3>
                        <p><strong>IP:</strong> {ip}</p>
                        <p><strong>Ubicación:</strong> {ciudad}, {pais}</p>
                        <p><strong>Coordenadas:</strong><br>{lat_formateada}, {lon_formateada}</p>
                        <p style="margin-top: 15px; font-size: 0.9em; color: #ccc;">
                            <em>Actualizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em>
                        </p>
                    </div>
                `, {{className: 'popup-personalizado'}});
                
                var etiqueta = L.marker([{lat}, {lon}], {{
                    icon: L.divIcon({{
                        className: 'etiqueta-info',
                        html: '<span style="color: #e74c3c;">🕷</span> IP: {ip}',
                        iconSize: [120, 30],
                        iconAnchor: [60, 15]
                    }})
                }}).addTo(mapa);
                
                mapa.setView([{lat}, {lon}], 10);
                
                function actualizarPosicion(nuevaLat, nuevoLng) {{
                    circulo.setLatLng([nuevaLat, nuevoLng]);
                    etiqueta.setLatLng([nuevaLat, nuevoLng]);
                    mapa.panTo([nuevaLat, nuevoLng]);
                }}
            </script>
        </body>
        </html>
        """
        
        try:
            with open(self.ruta_html, "w", encoding="utf-8") as f:
                f.write(codigo_html)
            self.vista_web.load(QUrl.fromLocalFile(self.ruta_html))
        except Exception as e:
            self.statusBar().showMessage(f"Error al cargar el mapa: {str(e)}, contacta a gstxx")

    def guardar_en_historial(self, ip, datos):
        archivo_historial = "Rastreo_IP.json"
        historial = {}
        
        if os.path.exists(archivo_historial):
            with open(archivo_historial, "r") as f:
                try:
                    historial = json.load(f)
                except:
                    historial = {}
        
        historial[ip] = {
            "datos": datos,
            "ultima_actualizacion": datetime.now().isoformat()
        }
        
        with open(archivo_historial, "w") as f:
            json.dump(historial, f, indent=2)

    def al_rastrear_ip(self):
        ip = self.entrada_ip.text().strip()
        if ip:
            self.rastrear_ip(ip)

    def al_seleccionar_historial(self, ip):
        if ip in self.ips_rastreadas:
            self.datos_ip_actual = self.ips_rastreadas[ip]
            self.actualizar_mostrador_info()
            self.actualizar_mapa_satelital()
            self.iniciar_escaneo_puertos(ip)

    def cambiar_intervalo_actualizacion(self, indice):
        intervalos = [10, 30, 60, 300, 600, 1800, 3600, 7200, 14400, 28800, 43200, 86400, 172800, 259200]  # segundos px
        self.intervalo_actualizacion = intervalos[indice]
        self.temporizador.setInterval(self.intervalo_actualizacion * 1000)
        self.statusBar().showMessage(f"Intervalo de actualización cambiado a {self.combo_intervalo.currentText()}")

    def actualizar_todos_datos(self):
        ip_actual = self.datos_ip_actual.get("query")
        if ip_actual:
            self.rastrear_ip(ip_actual)
            self.statusBar().showMessage(f"Datos actualizados: {datetime.now().strftime('%H:%M:%S')}")

    def exportar_datos(self):
        try:
            archivo_exportacion = f"exportacion_ip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(archivo_exportacion, "w") as f:
                json.dump(self.ips_rastreadas, f, indent=2)
            
            self.statusBar().showMessage(f"Datos exportados a {archivo_exportacion}")
            QMessageBox.information(self, "Exportación Exitosa", f"Los datos han sido exportados a {archivo_exportacion}")
        except Exception as e:
            QMessageBox.critical(self, "Error de Exportación", f"No se pudieron exportar los datos: {str(e)}")

    def inicio_carga_pagina(self):
        self.barra_progreso.setVisible(True)
        self.barra_progreso.setValue(0)

    def progreso_carga_pagina(self, progreso):
        self.barra_progreso.setValue(progreso)

    def fin_carga_pagina(self, exito):
        self.barra_progreso.setVisible(False)
        if not exito:
            self.statusBar().showMessage("Error al cargar el mapa satelital")
    
    def closeEvent(self, event):
        self.temporizador.stop()
        
        if self.escaner_activo and self.escaner_activo.isRunning():
            self.escaner_activo.stop()
            
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    paleta_redspyder = QPalette()

    paleta_redspyder.setColor(QPalette.Window, QColor(20, 20, 20))
    paleta_redspyder.setColor(QPalette.WindowText, QColor(230, 230, 230))

    paleta_redspyder.setColor(QPalette.Base, QColor(35, 0, 0))
    paleta_redspyder.setColor(QPalette.AlternateBase, QColor(50, 0, 0))
    paleta_redspyder.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    paleta_redspyder.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
    paleta_redspyder.setColor(QPalette.Text, QColor(230, 230, 230))
    paleta_redspyder.setColor(QPalette.Button, QColor(60, 0, 0))
    paleta_redspyder.setColor(QPalette.ButtonText, QColor(230, 230, 230))

    paleta_redspyder.setColor(QPalette.Highlight, QColor(200, 0, 0))
    paleta_redspyder.setColor(QPalette.HighlightedText, QColor(255, 255, 255))

    paleta_redspyder.setColor(QPalette.Link, QColor(255, 60, 60))

    app.setPalette(paleta_redspyder)

    app.setStyleSheet("""
        QMainWindow { background-color: #141414; }
        QGroupBox {
            border: 2px solid #c80000;
            border-radius: 6px;
            margin-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            color: #ff1a1a;
            font-weight: bold;
        }
        QLabel { color: #e6e6e6; }
        QLineEdit, QTextEdit, QComboBox {
            background-color: #260000;
            color: #f5f5f5;
            border: 1px solid #c80000;
            border-radius: 4px;
            padding: 5px;
        }
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
            border: 1px solid #ff1a1a;
        }
        QPushButton {
            background-color: #c80000;
            color: white;
            font-weight: bold;
            padding: 6px;
            border: none;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #a00000;
        }
        QStatusBar {
            background: #111111;
            color: #aaaaaa;
        }
    """)

    ventana = AplicacionRastreadorIP()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()