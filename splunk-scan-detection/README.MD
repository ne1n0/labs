# Laboratorio de Detección de Escaneo de Red Interno con Splunk

---

## 🌐 Introducción

Este laboratorio tiene como objetivo simular un escenario de reconocimiento dentro de una red interna, donde un atacante intenta descubrir otros sistemas mediante técnicas de escaneo.

Utilizaremos **Splunk** para analizar los patrones generados por la herramienta **Nmap** y aprender a detectar actividad sospechosa basada en el volumen y tipo de conexiones iniciadas.

---

## 📊 Objetivos

* Simular un escaneo de red horizontal y vertical.
* Capturar y visualizar los logs de red en Splunk.
* Aplicar consultas SPL para detectar escaneos.
* Crear alertas automáticas por patrones de escaneo.
* Relacionar la actividad con técnicas MITRE ATT\&CK.

---

## 🚀 Infraestructura

| Máquina    | IP              | Rol             |
| ---------- | --------------- | --------------- |
| Kali Linux | 192.168.100.110 | Atacante (Nmap) |
| Windows 10 | 192.168.100.120 | Víctima         |
| Ubuntu     | 192.168.100.129 | Servidor Splunk |

---

## 🔧 Herramientas utilizadas

| Herramienta      | Descripción                             |
| ---------------- | --------------------------------------- |
| Nmap             | Escaneo de red (puertos/hosts)          |
| Splunk           | Análisis y visualización de logs        |
| Wireshark o Zeek | (Opcional) Captura o generación de logs |

---

## ⚖️ Simulación de escaneo

Desde la máquina atacante Kali:

Escaneo horizontal:

```bash
nmap -sS 192.168.100.0/24
```

Escaneo de puertos vertical:

```bash
nmap -sS -p- 192.168.100.120
```

---

## 🔢 Recolección de logs

* Habilitar el logueo de conexiones en firewall o usar logs de IDS/Zeek.
* O usar Wireshark para capturar el pcap y convertirlo a CSV para subirlo a Splunk.

---

## 🤖 Análisis en Splunk (SPL)

Ejemplo de consulta para detectar múltiples conexiones por IP:

```spl
index=red_logs action=blocked OR protocol=tcp
| stats count by src_ip, dest_ip, dest_port
| where count > 100
```

---

## 📊 Visualización

* Heatmap de IP origen vs puertos destino.
* Top 10 IPs con más intentos.
* Timeline de volumen de conexiones por minuto.

---

## ⚠️ Alerta programada

* Disparar alerta si una IP genera >200 intentos a distintos puertos en <1 minuto.
* Otra alerta si una misma IP intenta conectarse a >10 hosts en <5 minutos.

---

## 🪧 MITRE ATT\&CK relacionado

| Técnica                   | ID    |
| ------------------------- | ----- |
| Network Service Discovery | T1046 |
| Active Scanning           | T1595 |
| Remote System Discovery   | T1018 |

---

## 📂 Evidencias a documentar

* Captura del escaneo en Kali (pantalla o comandos).
* Paneles de Splunk con gráficos.
* Logs analizados.
* Captura de alerta generada.

---

## 📊 Conclusión

Este laboratorio demuestra la utilidad de Splunk para identificar tácticas comunes de reconocimiento utilizadas por atacantes en redes internas. Detectar escaneos tempranamente permite activar medidas proactivas de contención antes de una intrusión mayor.
