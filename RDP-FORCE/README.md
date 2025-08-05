#  Laboratorio de Detección y Respuesta ante Ataque de Fuerza Bruta RDP usando Wazuh

---

##  Introducción

Este documento describe el diseño y despliegue de un entorno controlado para simular un ataque de fuerza bruta contra el servicio de Escritorio Remoto (RDP) en una máquina con Windows 10.  

El objetivo es generar actividad maliciosa detectable mediante múltiples intentos fallidos de autenticación, utilizando **Kali Linux** y la herramienta **Hydra** como origen del ataque.  

La máquina objetivo ejecuta un **agente Wazuh**, encargado de recolectar y enviar eventos de seguridad al servidor central **Wazuh Manager**, donde se lleva a cabo la correlación, clasificación y análisis.  

La actividad detectada se evalúa bajo el marco **MITRE ATT&CK**, específicamente la técnica **T1110.001 – Password Guessing**, y se prueba la capacidad del sistema para escalar alertas y activar respuestas automáticas frente a un patrón hostil persistente.

---

## Objetivos del laboratorio

- Simular y monitorear un ataque de fuerza bruta RDP con **Hydra** y **Wazuh**.
- Analizar la correlación y severidad de alertas generadas por Wazuh.
- Ajustar la detección mediante una **regla personalizada** basada en MITRE ATT&CK (T1110.001).
- Implementar y verificar una **respuesta automática (active-response)** ante el patrón detectado.
- Documentar evidencias y hallazgos técnicos de utilidad en entornos SOC.

---

## Infraestructura

| Máquina     | IP              | Rol                       |
|-------------|-----------------|---------------------------|
| Windows 10  | 192.168.100.120 | Objetivo, con Wazuh Agent |
| Ubuntu      | 192.168.100.129 | Servidor Wazuh            |
| Kali Linux  | 192.168.100.110 | Atacante (Hydra)          |

---

## Herramientas utilizadas

| Herramienta       | Descripción                                 |
|-------------------|---------------------------------------------|
| Wazuh 4.12.0         | Plataforma SIEM/EDR para detección y respuesta |
| Hydra             | Herramienta de fuerza bruta para RDP         |
| Kali Linux        | Sistema atacante con herramientas ofensivas  |
| Windows 10 Pro    | Sistema víctima con RDP y agente Wazuh       |
| MITRE ATT&CK      | Marco de referencia para clasificar TTPs     |
| Nmap              | Escaneo de puerto RDP para confirmar visibilidad previa al ataque |

---

## Línea base antes del ataque

Antes de ejecutar el ataque, se estableció una línea base del entorno para validar que no existieran eventos de alta criticidad ni actividad anómala en el servicio RDP.

- El panel de overview muestra un agente activo, sin alertas críticas ni severas en las últimas 24 horas.

_Screenshot: `images/dashboard_overview.png`_

- Se detectan algunos eventos 4625 previos, pero de bajo volumen y clasificados con severidad media.

_Screenshot: `images/4625-04-08.png`_

---

## Verificación de puerto RDP con Nmap

Previo a la ejecución del ataque, se utilizó la herramienta **Nmap** desde Kali Linux para validar que el servicio RDP (puerto 3389/TCP) estuviera activo y accesible desde la red.

Comando utilizado:

```bash

nmap -p 3389 192.168.100.120 

```
_Screenshot: `images/nmap-3389.png`_

## Ejecución del ataque con Hydra

Desde la máquina atacante (Kali Linux), se ejecutó una campaña de fuerza bruta contra el servicio RDP de la máquina Windows 10 utilizando la herramienta Hydra.  
El objetivo fue forzar múltiples intentos de inicio de sesión fallidos en un corto periodo de tiempo, generando así un patrón detectable por Wazuh.

Comando utilizado:
```bash
hydra -V -f -u -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.120

```
_Screenshot: `images/hydra-bruteforce.png`_

---

## Detección y análisis inicial en Wazuh

Tras ejecutar el ataque de fuerza bruta desde Kali Linux, Wazuh comenzó a registrar múltiples eventos relacionados con intentos fallidos de inicio de sesión en la máquina Windows 10 (Event ID 4625). Estos eventos fueron generados por el agente instalado y enviados al Wazuh Manager para su análisis.

Al revisar los registros desde la interfaz, se identificó lo siguiente:

- Wazuh clasificó algunos eventos con **nivel de severidad bajo (`rule.level: 0`)**, tratándolos como fallos aislados.
- Otros eventos fueron clasificados como **`rule.level: 10` (Medium severity)**, especialmente cuando involucraban al usuario `Administrator`.

Este comportamiento indica que, aunque Wazuh detecta los eventos de manera correcta, **no los correlaciona automáticamente como un ataque de fuerza bruta**. La detección se basa en eventos individuales sin considerar su volumen, frecuencia ni IP de origen.

_Screenshot: `images/4625-postattack.png`_

Esta observación da paso a la siguiente etapa: el diseño de una **regla personalizada** que permita correlacionar estos eventos como un único incidente de severidad **alta**.
