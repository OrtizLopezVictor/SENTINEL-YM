# Validación v0.3

- 22 pruebas unittest aprobadas, incluidas 8 nuevas.
- HTTP 200: incidentes, hallazgos, auditoría, aprendizaje, exportación y salud.
- HTTP 403: Host no permitido; 405: POST; 400: colección de exportación inválida.
- Sintaxis del instalador verificada con bash -n.
- No se ejecutaron instalaciones systemd ni reparaciones APT reales.
- No se completó inspección visual en navegador: el entorno no tenía Chromium instalado.
  La consola fue comprobada mediante generación HTML, escape de contenido y respuestas HTTP.

Ejecutar pruebas desde la carpeta del proyecto:

```bash
python3 -m unittest discover -s tests -v
```
