# 🧪 Laboratorio de Ataque en Cadena con Splunk Enterprise

---

## 📝 Introducción  

Este laboratorio tiene como propósito **simular un ataque en cadena dentro de un entorno controlado**, utilizando **Splunk Enterprise** como plataforma central de monitoreo y análisis de seguridad.  

La idea es reproducir, de forma progresiva, varias fases de la cadena de ataque que un adversario real podría llevar a cabo en una red corporativa. Cada fase genera eventos de seguridad en los sistemas comprometidos, los cuales son enviados a Splunk mediante **Universal Forwarder**, permitiendo su detección, correlación y análisis.  

El flujo general del laboratorio está inspirado en el modelo de la **Cyber Kill Chain** y técnicas de **MITRE ATT&CK**, siguiendo este orden:  

1. **Reconocimiento y fuerza bruta RDP** → Múltiples intentos fallidos de autenticación desde una máquina atacante (Kali).  
2. **Acceso inicial** → Inicio de sesión exitoso tras los intentos fallidos, indicando una posible cuenta comprometida.  
3. **Persistencia / Ejecución de malware** → Descarga y ejecución de un binario sospechoso en el endpoint Windows 10.  
4. **Movimiento lateral** → Intentos de conexión hacia otros recursos de la red.  
5. **Acciones sobre el objetivo** → Bloqueo de cuentas y actividades que degradan la disponibilidad del sistema.  

Este diseño permite no solo validar búsquedas y detecciones puntuales (por ejemplo, un ataque de fuerza bruta), sino también demostrar cómo los analistas pueden **reconstruir toda la cadena de ataque en Splunk**, desde el acceso inicial hasta el impacto final.  

##  Infraestructura del Laboratorio  

| Componente            | Rol                              |
|-----------------------|------------------------------------------------------|
| **Windows Server 2022** | Servidor Splunk Enterprise (SIEM)                   |
| **Windows 10**         | Endpoint víctima con Universal Forwarder             |
| **Kali Linux**         | Máquina atacante que ejecuta las distintas fases     |


El objetivo final es evidenciar cómo Splunk puede centralizar logs, aplicar consultas, y correlacionar eventos para detectar un ataque complejo de extremo a extremo.  
