#  Laboratorio de Fuerza Bruta RDP con Splunk Enterprise

---

##  Introducción  

Este laboratorio reproduce, en un entorno controlado, un ataque de fuerza bruta al servicio de Escritorio Remoto (RDP) contra un endpoint Windows. El propósito es demostrar el ciclo completo de detección y respuesta utilizando Splunk Enterprise como SIEM central.

La dinámica del ejercicio permite observar cómo, ante múltiples intentos fallidos de autenticación remota, Splunk:

- Recibe y procesa los eventos de seguridad desde el endpoint.
- Identifica patrones anómalos en los intentos de inicio de sesión.
- Genera una alerta de seguridad, la cual dispara acciones de notificación y respuesta automatizada (AR).

Este escenario corresponde a la fase de acceso inicial dentro de la Cyber Kill Chain y se relaciona con la técnica T1110.001 - Fuerza Bruta de Contraseñas (RDP) del marco MITRE ATT&CK.
---

##  Objetivo

Simular un ataque de fuerza bruta contra RDP en una máquina con Windows 10, utilizando la herramienta Hydra desde Kali Linux.

El ataque generará múltiples eventos de intentos fallidos de inicio de sesión (Event ID 4625), los cuales serán:

- Recolectados y enviados a Splunk mediante un Universal Forwarder.
- Detectados y correlacionados mediante búsquedas SPL
- Utilizados como disparador de una alerta configurada en Splunk, que enviará un correo de notificación y ejecutará un script de respuesta para bloquear la IP atacante en el firewall de Windows.

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

El ataque se llevó a cabo desde la máquina Kali Linux utilizando Hydra, una herramienta de fuerza bruta ampliamente utilizada en pruebas de penetración.

---

###  Ataque a multiples usuarios

En este escenario, el atacante busca probar varios nombres de usuario combinados con un diccionario de contraseñas. Para ello se usó:

- Diccionario de contraseñas: rockyou.txt.
- Lista de usuarios comunes: top-usernames-shortlist.txt de SecLists.

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

![dashboard event](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/event-detail-3.png)

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