#  Laboratorio de Ataque en Cadena con Splunk Enterprise

---

##  Introducción  

Este laboratorio tiene como propósito **simular un ataque en cadena dentro de un entorno controlado**, utilizando **Splunk Enterprise** como plataforma central de monitoreo y análisis de seguridad.  

La idea es reproducir, de forma progresiva, varias fases de la cadena de ataque que un adversario real podría llevar a cabo en una red corporativa. Cada fase genera eventos de seguridad en los sistemas comprometidos, los cuales son enviados a Splunk mediante **Universal Forwarder**, permitiendo su detección, correlación y análisis.  

El flujo general del laboratorio está inspirado en el modelo de la **Cyber Kill Chain** y técnicas de **MITRE ATT&CK**, siguiendo este orden:  

1. **Reconocimiento y fuerza bruta RDP** → Múltiples intentos fallidos de autenticación desde una máquina atacante (Kali).  
2. **Acceso inicial** → Inicio de sesión exitoso tras los intentos fallidos, indicando una posible cuenta comprometida.  
3. **Persistencia / Ejecución de malware** → Descarga y ejecución de un binario sospechoso en el endpoint Windows 10.  
4. **Movimiento lateral** → Intentos de conexión hacia otros recursos de la red.  
5. **Acciones sobre el objetivo** → Bloqueo de cuentas y actividades que degradan la disponibilidad del sistema.  




##  Infraestructura del Laboratorio  

| Componente            | Rol                              |
|-----------------------|------------------------------------------------------|
| **Windows Server 2022** | Servidor Splunk Enterprise (SIEM)                   |
| **Windows 10**         | Endpoint víctima con Universal Forwarder             |
| **Kali Linux**         | Máquina atacante que ejecuta las distintas fases     |




## Escenarios de Ataque 

1. **Fuerza bruta RDP**  
   - Desde Kali Linux se realizan múltiples intentos fallidos de inicio de sesión RDP hacia el Windows 10.  
   - El Windows 10 genera eventos 4625 (logon failed).  
   - Splunk recolecta los logs vía Forwarder y se ejecuta una búsqueda para identificar 5 o más intentos fallidos desde la misma IP.  

2. **Ejecución de comandos maliciosos tras acceso**  
   - Una vez obtenido acceso válido, el atacante ejecuta comandos de reconocimiento en el endpoint.  
   - Se generan eventos 4688 (process creation).  
   - Splunk permite detectar procesos sospechosos como `whoami`, `ipconfig`, `net user`, etc.  

3. **Descarga de malware simulado**  
   - El atacante descarga un archivo desde internet usando `certutil` o `powershell Invoke-WebRequest`.  
   - Estos procesos quedan registrados en logs de seguridad.  
   - Splunk los identifica por la combinación de procesos inusuales con conexiones de red salientes.  

4. **Persistencia**  
   - Se crea una clave en el registro de Windows para ejecutar un binario al iniciar sesión.  
   - Eventos 4657 (Registry value modification) o 4688 (nuevo proceso en startup) son generados.  
   - En Splunk se correlacionan para identificar cambios en persistencia.  


#  Escenario 1: Fuerza bruta RDP

---

##  Objetivo del Escenario

Simular un ataque de fuerza bruta contra el servicio de **Escritorio Remoto (RDP)** en una máquina con Windows 10, utilizando la herramienta **Hydra** desde Kali Linux. El propósito es **generar múltiples intentos fallidos de inicio de sesión** que queden registrados en los eventos de seguridad del sistema y sean posteriormente **detectados y analizados mediante Splunk Enterprise**.

Este escenario representa la **fase de reconocimiento y acceso inicial** dentro de la cadena de ataque, permitiendo validar la capacidad del SIEM para identificar comportamientos anómalos desde una misma fuente.

---

##  Componentes Involucrados

| Rol                | Detalles                                        |
|-------------------|-------------------------------------------------|
| Máquina víctima    | Windows 10 con RDP habilitado                  |
| Máquina atacante   | Kali Linux ejecutando ataque con Hydra         |
| Recolector SIEM    | Splunk Enterprise en Windows Server 2022       |
| Agente de envío    | Universal Forwarder en Windows 10              |

---


##  Ejecución del Ataque

Se realizaron dos variantes del ataque de fuerza bruta desde Kali Linux, utilizando `Hydra`. Cada una representa un enfoque diferente utilizado por atacantes reales.

---

###  Variante 1: Ataque a un usuario específico conocido

Este ataque se basa en el uso de un nombre de usuario legítimo previamente identificado ("Usuario" para este caso) y se prueban múltiples contraseñas contra esa cuenta.

```bash

sudo hydra -t 1 -V -f -u -l Usuario -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.120

```
 - -l Usuario: es el usuario objetivo
 - -P rockyou.txt: Diccionario de contraseñas.
 - rdp:// : Protocolo objetivo

![Ataque hydra to Usuario](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/usuario-atck.png)

Cada intento fallido de autenticación genera un evento con ID 4625 en el visor de eventos de Windows, que luego es recolectado por el Universal Forwarder y enviado a Splunk.

Estos eventos incluyen detalles como:

- Usuario atacado: `TargetUserName = Usuario`
- IP de origen: Kali Linux (`IpAddress`)
- Estado de autenticación fallida: `Status = 0xc000006d`

![Eventos 4625 para Usuario](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/4625.png)

Debido a las políticas de seguridad configuradas, el sistema bloquea automáticamente la cuenta tras 10 intentos fallidos consecutivos. Esto genera un evento con ID 4740 que indica explícitamente que la cuenta fue bloqueada.

![Evento 4740 - Cuenta bloqueada](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/4740.png)