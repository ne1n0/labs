#  Laboratorio de Fuerza Bruta RDP con Splunk Enterprise  

---

##  Introducción  

En este laboratorio se simula un **ataque de fuerza bruta contra el servicio RDP (Remote Desktop Protocol)** en un entorno Windows 10.  
El propósito es **demostrar el ciclo completo de detección y respuesta** empleando **Splunk Enterprise** como SIEM central.  

La dinámica permite observar cómo un atacante, utilizando herramientas automatizadas desde Kali Linux, genera múltiples intentos de inicio de sesión fallidos. Estos eventos de seguridad son recolectados mediante **Universal Forwarder**, correlacionados en Splunk y finalmente usados como disparador de **alertas y acciones de respuesta automatizada (AR)**.  

Este escenario se ubica dentro de la fase de **Acceso Inicial** de la *Cyber Kill Chain* y está alineado con la técnica **T1110.001 – Brute Force (RDP)** del marco **MITRE ATT&CK**.  

---

##  Objetivos del laboratorio  

- **Simular un ataque de fuerza bruta** contra RDP en un endpoint Windows utilizando **Hydra** desde Kali Linux.  
- **Recolectar y enviar logs de seguridad** (Event ID **4625 – Failed Logon**) a Splunk.  
- **Correlacionar intentos fallidos** mediante búsquedas en SPL para identificar patrones de ataque.  
- **Generar una alerta en Splunk** que:  
  - Notifique vía correo electrónico.  
  - Ejecute un **script de respuesta automática** para bloquear la IP atacante en el firewall de Windows.  

---

##  Componentes Involucrados

| Rol                | Detalles                                        |
|-------------------|-------------------------------------------------|
| Máquina víctima    | Windows 10 con servicio de Escritorio Remoto (RDP) habilitado.                 |
| Máquina atacante   | Kali Linux, ejecutando Hydra para el ataque de fuerza bruta.         |
| Recolector SIEM    | Splunk Enterprise instalado en Windows Server 2022.     |
| Agente de envío    | Splunk Universal Forwarder en Windows 10 para transmitir logs al SIEM.        |

---

##  Ejecución del Ataque  

El ataque se llevó a cabo desde la máquina **Kali Linux** utilizando la herramienta **Hydra** para realizar un ataque de fuerza bruta contra el servicio RDP del endpoint Windows.  

En este escenario, el atacante probó **varios nombres de usuario** combinados con un diccionario de contraseñas, con el objetivo de forzar accesos remotos no autorizados.  

Recursos utilizados:  

- **Diccionario de contraseñas:** `rockyou.txt`  
- **Lista de usuarios comunes:** `top-usernames-shortlist.txt` de **SecLists**  

Este procedimiento generó múltiples eventos de autenticación fallida (**Event ID 4625**) en el endpoint Windows, los cuales fueron enviados a Splunk para su posterior detección y correlación.


```bash
sudo hydra -V -f -u -L -I /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.140
```

- -V  Muestra cada intento de autenticación (verbose).
- -f  Detiene el ataque si encuentra una combinación válida.
- -u  Intenta todas las contraseñas por usuario antes de cambiar de usuario.
- -L  Archivo con lista de posibles usuarios.
- -P  Archivo con diccionario de contraseñas.
- -I  Evita pausa de 10 segundos.

rdp:// → Especifica el protocolo y la IP del objetivo.

Este ataque genera múltiples eventos de inicio de sesión fallido (4625) en los registros de seguridad de Windows, los cuales son enviados a Splunk para su análisis y detección.


![ataque con hydra](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/attack-hydra.png)

## Eventos recolectados en Splunk

En la vista de **Events** se observa un registro con ID **4625 - An account failed to log on**, generado en la máquina víctima.  
Este evento evidencia un intento de inicio de sesión fallido desde la máquina atacante:

- **Event Code:** 4625 
- **Computer Name:**  DESKTOP-5QGOT2G 
- **Account Name:** puppet  
- **Failure Reason:** Unknown user name or bad password  
- **Workstation Name:** kali 
- **Source Network Address:** 192.168.100.110  

![dashboard event](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/detail-3.png)

Estos campos son los que permiten a Splunk identificar tanto el origen del ataque como el usuario objetivo.

##  Correlación con SPL

Para correlacionar múltiples intentos fallidos, se utilizó la siguiente búsqueda:

```spl
index=windows EventCode=4625 
| stats count by src_ip, user, ComputerName, Failure_Reason
```
![dashboard event](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/event-detail.png)


Una vez identificada la correlación de intentos fallidos, la búsqueda se refinó para incluir una ventana de tiempo de 5 minutos y un umbral de más de 10 intentos por IP/usuario. Esta versión final de la consulta servirá como base para la alerta de fuerza bruta en Splunk:


```bash
index=windows EventCode=4625 earliest=-5m@m latest=now
| stats count by src_ip, user
| where count > 10
```

Con esta búsqueda, Splunk es capaz de detectar de forma automática un patrón de ataque en tiempo casi real

Explicación de la consulta

1. index=windows EventCode=4625 : filtra únicamente los eventos de seguridad con ID 4625 (Logon Failed) en el índice windows.
2. earliest=-5m@m latest=now : limita la búsqueda a los últimos 5 minutos, creando una ventana de tiempo de correlación.
3. stats count by src_ip, user : agrupa los resultados por IP de origen y usuario atacado, contando la cantidad de intentos fallidos.
4. where count > 10 : aplica un umbral de más de 10 intentos fallidos en 5 minutos, criterio utilizado para identificar actividad de fuerza bruta.

Resultado obtenido

La ejecución de la consulta muestra que una misma IP atacante (192.168.100.110) realizó múltiples intentos de autenticación fallida contra diferentes cuentas de usuario (admin, root, test, oracle, etc.), superando el umbral establecido.
Este patrón corresponde al comportamiento típico de un ataque de fuerza bruta con diccionario.

![detection de ataque](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/attack-detection.png)

