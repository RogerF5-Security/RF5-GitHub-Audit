# RF5 GitHub Audit

**Inventario de seguridad de GitHub con consultas de lectura y reportes HTML/JSON sin recursos externos.**

RF5 GitHub Audit integra GitHub REST API mediante GitHub CLI para revisar controles de repositorios, permisos de automatización, protección de ramas y cantidades de alertas. Mantiene explícitos los resultados no disponibles por permisos o errores de consulta.

[Informe de demostración con datos simulados](docs/demo.html) · Descarga el HTML y ábrelo en tu navegador.

## Requisitos

- Python 3.11 o superior.
- [GitHub CLI](https://cli.github.com/) para consultas reales; utiliza una sesión existente de `gh auth login`.
- La aplicación no requiere paquetes Python adicionales durante la ejecución.

## Uso rápido

```sh
git clone https://github.com/RogerF5-Security/RF5-GitHub-Audit.git
cd RF5-GitHub-Audit
python -m rf5_github_audit --demo
python -m rf5_github_audit --owner RogerF5-Security
python -m rf5_github_audit --repo OWNER/REPOSITORY --output reports
```

Instalación opcional del comando:

```sh
python -m pip install .
rf5-github-audit --owner OWNER
```

`--demo` funciona sin red ni autenticación y etiqueta sus datos como simulados. Abre el HTML generado para filtrar los repositorios por nombre y estado.

## Alcance y privacidad

- Las solicitudes salientes utilizan únicamente `GET` y el host `github.com`. No hay funciones para cambiar configuraciones, aprobar PR, crear incidencias ni fusionar código.
- Por defecto se descubren repositorios públicos. Los privados requieren `--include-private` y pueden revelar nombres y datos internos en los reportes locales.
- Para cuentas personales, `--include-private` permite consultar únicamente los repositorios del propietario autenticado. Para organizaciones se respeta el acceso de la sesión.
- GitHub CLI filtra las respuestas de alertas de secretos a cantidades por página antes de entregarlas a la aplicación. El reporte no incluye valores de secretos ni tokens.
- `reports/` está excluido de Git. Revisa el contenido de cualquier reporte antes de compartirlo.
- El límite predeterminado es de 50 repositorios; puede ajustarse con `--limit 1..500`. El JSON registra si el alcance quedó limitado.

## Qué comprueba

| Área | Evidencia de API |
| --- | --- |
| Escaneo de secretos y protección de pushes | Configuración del repositorio y cantidad de alertas abiertas |
| Dependabot | Alertas habilitadas, actualizaciones de seguridad y cantidades por severidad |
| Reporte privado de vulnerabilidades | Estado de habilitación |
| GitHub Actions | Permisos predeterminados y capacidad de aprobar PR |
| Rama predeterminada | Reglas efectivas y protección clásica |

Una respuesta `403` o un `404` ambiguo se registra como **unavailable**, no como ausencia de alertas. Un `404` que indica expresamente “Branch not protected” se representa como protección clásica no configurada.

El informe usa estos estados: `attention` (observaciones), `partial` (cobertura incompleta), `checked` (sin observaciones en lo comprobado), `unavailable` y `skipped`. Las observaciones de dependencias son alertas de GitHub y requieren validar su aplicabilidad; este inventario no es un análisis del código ni una prueba de explotabilidad.

## Permisos

Los metadatos públicos pueden estar disponibles con acceso básico. La consulta de alertas, reglas y permisos de Actions puede requerir permisos adicionales de lectura o administración según el recurso y el tipo de token. La aplicación conserva las consultas no autorizadas como cobertura parcial; no solicita ampliaciones automáticas de permisos.

Se recomienda una sesión con el mínimo acceso de lectura necesario a los repositorios elegidos. El programa no recibe credenciales mediante argumentos ni las escribe en reportes.

## Desarrollo

```sh
python -m unittest discover -v
python -m rf5_github_audit --help
python -m rf5_github_audit --demo --output reports/demo
```

Las pruebas cubren restricciones de transporte, paginación, permisos insuficientes, privacidad de repositorios y secretos, escape de HTML y generación de reportes.

Soporte: [GitHub Issues](https://github.com/RogerF5-Security/RF5-GitHub-Audit/issues). Para vulnerabilidades consulta [SECURITY.md](SECURITY.md).

Roger Arana · [Roger F5](https://rogerf5-security.github.io/whoami/)
