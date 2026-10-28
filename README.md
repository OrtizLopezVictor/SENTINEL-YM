# SENTINEL-YM v0.3 — Centro de ciberdefensa

Actualización del proyecto v0.2 de Víctor. Para Ubuntu/Debian con systemd.

## Inicio rápido

Descomprime el ZIP y abre una terminal dentro de `SENTINEL-YM-v0.3`:

```bash
sudo bash install.sh
sudo sentinel-ym status
sudo sentinel-ym dashboard
```

Abre **http://127.0.0.1:8765** en ese mismo equipo. Mantén la terminal del panel abierta.
El servicio de vigilancia funciona por separado. El instalador conserva la configuración
existente y la base de datos; reemplaza los módulos y reinicia el servicio.
Antes de actualizar, conserva una copia del paquete anterior y una copia consistente
SQLite de `/var/lib/sentinel-ym` si necesitas volver a la versión anterior.
No habilita parches automáticamente con los comandos anteriores.

## Qué cambia

- Consola adaptable con navegación, indicadores, búsqueda por IP/texto, filtros,
  exportación JSON y estado de lectura de logs. Sin scripts, CDN o recursos externos.
- Correlación SSH persistente en ventana de 300 segundos entre escaneos y reinicios.
  Señala acumulación de fallos y accesos aceptados después de varios fallos.
- Fechas de journald preservadas: los registros antiguos no se presentan como ráfagas actuales.
- Aprendizaje excluye intervalos con journal/puertos no disponibles y cambios respecto
  a la referencia de archivos, incluso si el aviso se encuentra en periodo de silencio.
- Reserva atómica de reparaciones: evita la doble ejecución simultánea del mismo hallazgo.
- 22 pruebas automatizadas de la base y las mejoras, más comprobaciones HTTP locales.

## Probar el panel sin instalar ni tocar la configuración del equipo

```bash
python3 demo_console.py
```

Abre la dirección mostrada. Todos los datos se identifican como **DEMO** y viven
solo en un directorio temporal; Ctrl+C cierra y elimina esa base de demostración.

## Reparaciones bajo tu control

```bash
sudo sentinel-ym findings
sudo sentinel-ym review 1 aprobar
# o:
sudo sentinel-ym review 1 rechazar
```

Reemplaza `1` por el ID real. Lee el plan y escribe `APROBAR` o `RECHAZAR`.
No se automatizan reparaciones SSH ni cambios de permisos sensibles. Si el proceso
se interrumpe en `en_ejecucion`, verifica manualmente el estado de APT y del hallazgo;
no se vuelve a ejecutar automáticamente. `aplicado_no_verificado` no significa resuelto.

## Alcance y límites comprobables

Es un monitor defensivo local con reglas y detección estadística, no un EDR completo,
ni un escáner exhaustivo de CVE o una garantía de detectar cualquier puerta trasera.
El modelo opcional Isolation Forest y el asesor local Ollama de v0.2 se conservan;
no se entrenó aquí un modelo de lenguaje ni se comprobó Ollama en tu equipo.
El aprendizaje continuo es estadístico y puede sufrir contaminación de su referencia;
las exclusiones reducen ese riesgo pero no lo eliminan.

La correlación SSH usa las unidades `ssh.service` y `sshd.service`, IP válidas,
ventana de 5 minutos, hasta 10,000 registros y hasta 2,000 claves de supresión.
No cuenta intentos únicos: varios mensajes pueden corresponder a un mismo intento.
Servicios SSH con otros nombres requieren adaptar la lista de unidades.
Los contadores de señales acumulan observaciones, no ataques únicos. Un bloqueo de
UFW/AppArmor/fail2ban es evidencia del registro del control, no prueba de intrusión evitada.
Los logs no son una fuente infalsificable frente a un atacante que controle el host.
La búsqueda/exportación usa los últimos 5,000 registros; el panel muestra hasta 200.
El estado “reciente” usa un umbral fijo de 180 s, independiente del intervalo configurado.
El panel es local y de solo lectura, pero no tiene autenticación entre usuarios locales;
no lo publiques con proxies ni enlaces externos.

Validación realizada en entorno aislado: pruebas unitarias, simulación y HTTP local.
La instalación systemd, permisos de journal y reparaciones APT necesitan validarse en
una VM Ubuntu/Debian tuya. No se ejecutaron reparaciones reales durante el desarrollo.

## Documentación de la base v0.2

# SENTINEL-YM v0.2 — Consola de incidentes, aprobaciones y aprendizaje continuo

**Proyecto experimental de ciberdefensa para Ubuntu/Debian Linux con systemd.** Código abierto, funcionamiento local, sin suscripciones. Esta herramienta **no** es un EDR completo, no garantiza detectar todos los ataques y no corrige automáticamente cualquier vulnerabilidad.

## Cambios respecto de v0.1

- **Panel web local** con diseño oscuro que muestra ataques/señales detectadas, bloqueos confirmados, hallazgos de configuración, reparaciones pendientes, registro de autorizaciones y métricas de IA.
- **Bitácora persistente SQLite**: tablas `incidents`, `findings`, `audit` y las alertas históricas originales. Incluye primera/última fecha y número de apariciones.
- **Diferenciación real entre "detectado" y "bloqueado"**: solo se registra "bloqueado" cuando un evento explícito de UFW (`[UFW BLOCK]`), AppArmor (`DENIED`) o fail2ban (`Ban IP`) aparece en los logs. Eso **no prueba** por sí mismo que la actividad fuera maliciosa o que un ataque completo se haya detenido. SENTINEL-YM por defecto solo monitoriza: los bloqueos los aplican esos controles externos cuando están instalados y configurados.
- **Catálogo de hallazgos**: SSH inseguro, permisos sensibles y políticas/estado de actualizaciones APT. No es un escáner exhaustivo de CVE; "paquete actualizable" no equivale necesariamente a vulnerabilidad explotable. Los datos dependen de permisos, configuración y caché APT.
- **Aprobaciones explícitas**, independientes del análisis por IA. Dos operaciones predefinidas admiten reparación supervisada (`enable-updates` y `apply-security-updates`), tras presentar el plan y exigir escribir `APROBAR` en la terminal. Se puede `rechazar`. Configuraciones de SSH y `/etc/shadow` **solo** generan instrucciones de revisión manual: el sistema nunca las cambia por sí solo.
- **Modelo híbrido online** con detección robusta mediana/MAD + desviación estadística + EWMA y, si está instalado scikit-learn, Isolation Forest. Aprende continuamente **solo** muestras que no estén marcadas como sospechosas por las reglas y el propio modelo. Las sospechas no actualizan la línea base. El resultado es una indicación estadística, no una clasificación infalible del ataque.
- **Asesor local Ollama** opcional de v0.1 para enriquecer algunas alertas. El LLM **no** puede ejecutar comandos ni aprobar reparaciones.
- **Exportación de registros a JSON** para análisis y respaldo.

## Instalación / actualización Ubuntu

Requiere `python3` (3.10+), `systemd` y las utilidades habituales `journalctl`, `ss`, `apt`. Sin dependencias de `pip` para operar. El servicio corre con privilegios para leer los logs; el panel solo se abre si lo pides, en `127.0.0.1`.

Desde la carpeta descomprimida `SENTINEL-YM-v0.2`:

```bash
python3 -m unittest discover -s tests -v
python3 simulate.py              # simulación ficticia, no ataca al equipo
chmod +x install.sh
sudo ./install.sh                 # instala/actualiza preservando base y configuración
```

**No uses `sudo ./install.sh --enable-security-updates` si quieres aprobar cada intervención**. Esa opción explícita habilita las actualizaciones automáticas de Ubuntu, que pueden seguir aplicando paquetes sin pedir permiso en cada ejecución. Las actualizaciones automáticas que ya tenga Ubuntu configuradas no son desactivadas por este programa.

El instalador conserva `/var/lib/sentinel-ym/events.sqlite3` y `/etc/sentinel-ym/config.json` en actualizaciones desde v0.1. Guarda una copia del directorio `/var/lib/sentinel-ym` antes de desplegarlo en un equipo importante.

Opcional para agregar Isolation Forest (paquete de la distribución, sin modificar el Python administrado por el sistema):

```bash
sudo apt update
sudo apt install python3-sklearn
```

Sin ese paquete, el detector robusto estadístico sigue funcionando. El modelo parte de cero si actualizas desde v0.1 porque los vectores de entrenamiento son distintos.

## Consultar el panel de logs

```bash
sudo sentinel-ym dashboard
```

Abre en ese mismo equipo **http://127.0.0.1:8765**. Muestra cuatro pestañas:

1. **Incidentes**: sospechas de ataques, SSH, puertos y procesos, y bloqueos confirmados por los controles externos.
2. **Vulnerabilidades**: configuración insegura, evidencia, nivel de gravedad, acción recomendada y estado.
3. **Auditoría**: quién autorizó/rechazó una acción de consola (registro local del proceso, sin identidad individual verificable), cuándo, y si la ejecución acabó con o sin error.
4. **Aprendizaje IA**: muestras limpias, descartes y últimas anomalías.

Se actualiza automáticamente cada 20 segundos. Se enlaza **únicamente** a `127.0.0.1`, rechaza HTTP POST y no expone botones de modificación: no hay reparaciones ni ingreso de contraseñas por la web. Para cerrar el panel presiona `Ctrl+C`. **No abras el puerto 8765 al exterior** ni uses `sudo` para navegar en el explorador.

## Consultar ataques y bloqueos desde terminal

```bash
sudo sentinel-ym status
sudo sentinel-ym incidents --outcome detectado
sudo sentinel-ym incidents --outcome bloqueado
sudo sentinel-ym incidents --outcome todos --limit 100
sudo sentinel-ym findings
sudo journalctl -u sentinel-ym -f
```

**Precisión de los conteos:** `detectado` es una señal sospechosa, no un ataque confirmado. `bloqueado` es un evento reportado por un control externo, no necesariamente un ataque. Los conteos agrupan registros que comparten huella y no cubren ataques invisibles a las fuentes disponibles.

## Reparar únicamente con tu autorización

Para revisar los hallazgos:

```bash
sudo sentinel-ym findings
```

Si muestra, por ejemplo, `#1 [pendiente] ... enable-updates`, revisa el plan y elige:

```bash
sudo sentinel-ym review 1 aprobar
# El programa pedirá escribir la palabra APROBAR.
```

O bien:

```bash
sudo sentinel-ym review 1 rechazar
# El programa pedirá escribir RECHAZAR.
```

`1` es un **ejemplo**, utiliza el ID real de tu instalación. Rechazar nunca aplica un parche. Tras una ejecución exitosa, el hallazgo queda como **`aplicado_no_verificado`** hasta validar de nuevo; no se declara reparado solo porque un comando acabó sin error. Una reparación puede instalar paquetes, interrumpir servicios o requerir reinicio: conviene mantener un respaldo y ventana de mantenimiento.

**Importante:** La opción `enable-updates` activa el mecanismo de actualizaciones desatendidas de Ubuntu. Si deseas control por reparación, examina esa implicación y no la apruebes; `apply-security-updates` realiza una ejecución puntual con las reglas oficiales de `unattended-upgrades`. La base local de detección nunca autoriza ninguna de estas acciones automáticamente. Los comandos legacy `sentinel-ym patch ... --apply` siguen disponibles y requieren invocación explícita del administrador.

## Exportar bitácoras

```bash
sudo sentinel-ym export incidents /tmp/incidentes-sentinel.json
sudo sentinel-ym export findings /tmp/hallazgos-sentinel.json
sudo sentinel-ym export audit /tmp/auditoria-sentinel.json
```

Cada archivo exportado se crea en modo privado (`0600`) y **no** sobreescribe archivos existentes. Ten en cuenta que puede incluir IP, procesos y rutas sensibles; no lo publiques sin revisar. Los registros son locales: un atacante que obtenga `root` puede alterarlos, así que en un entorno real es recomendable enviarlos también a un servidor de logs remoto protegido.

## Configuración y límites

Configura `/etc/sentinel-ym/config.json` y reinicia con `sudo systemctl restart sentinel-ym`. Por defecto escanea cada 45 segundos. Al iniciar, acepta el inventario actual de archivos y puertos como *referencia*, no como "seguro": revisa ese estado antes de confiar. Si el atacante ya estaba presente, puede formar parte de la referencia inicial. `sudo sentinel-ym baseline --accept` **solo** debe ejecutarse tras auditar el equipo.

Logs `journalctl` consumidos con cursor en lotes acotados, para prevenir lecturas ilimitadas. En equipos con eventos por encima de la capacidad del monitor, podrían perderse durante rotación. El módulo de IA no es un modelo de lenguaje entrenado desde cero: usa aprendizaje no supervisado online, Isolation Forest opcional y heurísticas defensivas; no entrena un modelo generativo ni descarga datasets automáticamente. No detecta todos los rootkits, 0-days o exfiltraciones. No sustituye las actualizaciones del fabricante, un EDR probado, AppArmor, firewall ni backups.

## Desinstalar

```bash
sudo ./uninstall.sh
```

Conserva los datos, los archivos de configuración y cualquier ajuste APT anterior, por seguridad. Licencia MIT (`LICENSE`).
