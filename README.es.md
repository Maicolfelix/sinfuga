# SinFuga

[Read in English](README.md)

SinFuga frena las fugas accidentales de secretos y datos personales antes de que lleguen a Claude Code o Codex. Es un solo archivo de Python sin dependencias, y detecta documentos de identidad de América Latina.

> **Estado: versión temprana.** El bloqueo se verificó en Windows dentro de Codex 0.166.0-alpha.5.1 real, y dentro de Claude Code 2.1.309 real con un modelo local simulado. Otras versiones pueden comportarse distinto. Reduce los accidentes, pero no garantiza que nada se filtre.

## Qué bloquea

- **Secretos:** claves de AWS, GitHub, OpenAI, Anthropic, Google, Slack y Stripe, llaves privadas, JWT, URL con contraseña y valores asignados a nombres como `password` o `api_key`.
- **Datos personales:** tarjetas (Luhn), CPF de Brasil, RUT de Chile, NIT de Colombia y CURP de México. Las cédulas y los DNI solo cuentan si el texto indica que lo son.
- **Rutas sensibles:** `.env`, `.ssh`, credenciales de la nube y tokens de herramientas de IA. `.env.example` se permite.
- **Archivos con secretos:** revisa el contenido antes de que la IA lo lea, tanto con herramientas de archivos como con comandos como `cat config.py`.

Los avisos nunca repiten el secreto, y lo que SinFuga no entiende se bloquea.

## Tú decides

SinFuga no es un límite de tu plan ni de la IA. Es una protección local: explica qué encontró, por qué es peligroso y te deja elegir.

- **Lo más seguro:** quita el dato, o usa una variable de entorno o valores falsos.
- **Continuar con un mensaje:** vuelve a enviarlo empezando por `sinfuga permitir:`.
- **Continuar con una acción:** escribe el código del aviso, por ejemplo `sinfuga permitir 1a2b3c`. Funciona una vez, solo para esa acción exacta y durante 10 minutos.

Solo cuenta un mensaje escrito por una persona, así que la IA no puede aprobarse sola con sus herramientas. Aun así, los hooks no son una barrera de seguridad completa: una IA con acceso total a la terminal podría intentar rodearlos.

## Qué incluye

| Pieza | Claude Code | Codex | Qué hace |
|---|---|---|---|
| Hook | Sí | Sí | Detiene el dato, explica el riesgo y pide tu decisión. Es la única pieza que bloquea. |
| Skill `sinfuga` | Sí | Sí | Enseña a la IA a manejar los avisos y hacer auditorías. |
| Agente auditor | `sinfuga-auditor` | `sinfuga_auditor` | Ejecuta `audit` sobre un proyecto o repositorio y lo resume, de solo lectura por instrucción. |

La skill y el agente son instrucciones que la IA puede ignorar. En Codex real se probaron con un modelo real desde un proyecto temporal. En Claude Code real se verificó que cargan con un modelo simulado, pero no cómo se comporta un modelo real con ellos.

Se usan pidiéndolo, por ejemplo: «Have sinfuga_auditor audit this project», o con `$sinfuga` en Codex.

## Instalación

Necesita Python 3.9 o superior disponible como `python`.

```bash
git clone <url-del-repositorio>
cd sinfuga
python test_sinfuga.py
python sinfuga.py install
```

`install` copia el script a `~/.sinfuga`, agrega hooks a `~/.claude/settings.json` y `~/.codex/hooks.json` (con una copia `.bak`), e instala la skill y el agente auditor en la carpeta de usuario de cada herramienta. 

**Codex ignora en silencio los hooks que no has aprobado.** Hasta que abras `/hooks` y apruebes SinFuga, Codex no avisa y no se bloquea nada.

Para quitar los hooks, la skill y el agente:

```bash
python sinfuga.py uninstall
```

## Auditar un proyecto o repositorio

```bash
python sinfuga.py audit ruta/del/proyecto
python sinfuga.py audit https://github.com/dueno/repositorio
```

`audit` revisa la versión actual, todo el historial de git y los archivos en disco que nunca se subieron, así que también encuentra secretos que se borraron pero siguen en el historial. El informe agrupa los hallazgos por gravedad, con archivo, línea, commit, por qué importa y qué hacer. Nunca muestra los valores.

- Sale con 0 si no encuentra nada, con 1 si encuentra algo y con 2 si hay un error.
- Los repositorios privados usan tu propio acceso de git. Las URL con credenciales se rechazan.
- En una URL no se respeta el `.sinfuga-ignore` del repositorio auditado.
- Algunos hallazgos pueden ser datos de ejemplo o de prueba, así que verifica cada uno.
- Audita solo repositorios tuyos o que tengas permiso de revisar.

Para revisar rápido solo los archivos actuales:

```bash
python sinfuga.py scan ruta/del/proyecto
```

## Excepciones

Lista los archivos con datos falsos en `.sinfuga-ignore`, un patrón por línea:

```text
# datos de prueba
fixtures/*
```

Las excepciones valen para leer archivos existentes. No aplican a mensajes ni a contenido nuevo, y la IA no puede editar este archivo.

## Límites

- **Se puede evadir.** `cat .e*` o `grep -r clave .` pasan, porque SinFuga no ve la salida de los comandos. Las dos herramientas describen los hooks como una protección, no como una barrera de seguridad completa.
- **Solo conoce patrones.** No detecta estrategias de negocio, notas médicas ni nombres en lenguaje normal, ni formatos de clave que no estén en la lista.
- **No deshace una fuga.** Si un secreto ya llegó a una IA o a un repositorio, revócalo.
- **Solo cubre Claude Code y Codex.** Los chats en el navegador quedan fuera.
- **Permitir es tu responsabilidad.** Lo que permitas sale de tu equipo como de costumbre. El flujo de permiso se verificó en Claude Code real con un modelo simulado, no en Codex real.
- **Necesita Python.** Si `python` no se puede ejecutar, el hook no bloquea.
- **Puede dar falsos positivos.** Un número largo puede pasar un dígito de control por casualidad.

## Licencia

[MIT](LICENSE)
