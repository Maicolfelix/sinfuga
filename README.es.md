# SinFuga

[Read in English](README.md)

SinFuga frena las fugas accidentales de secretos y datos personales antes de que lleguen a Claude Code o Codex. Es un solo archivo de Python sin dependencias, y detecta documentos de identidad de América Latina.

> **Estado: versión temprana.** El bloqueo se verificó dentro de Claude Code 2.1.309 real con un modelo local simulado. Dentro de Codex real aún no se ha verificado, solo con llamadas simuladas. Reduce los accidentes, pero no garantiza que nada se filtre.

## Qué bloquea

- **Secretos:** claves de AWS, GitHub, OpenAI, Anthropic, Google, Slack y Stripe, llaves privadas, JWT, URL con contraseña y valores asignados a nombres como `password` o `api_key`.
- **Datos personales:** tarjetas (Luhn), CPF de Brasil, RUT de Chile, NIT de Colombia y CURP de México. Las cédulas y los DNI solo cuentan si el texto indica que lo son.
- **Rutas sensibles:** `.env`, `.ssh`, credenciales de la nube y tokens de herramientas de IA. `.env.example` se permite.
- **Archivos con secretos:** revisa el contenido antes de que la IA lo lea, tanto con herramientas de archivos como con comandos como `cat config.py`.

Los avisos nunca repiten el secreto, y lo que SinFuga no entiende se bloquea.

## Instalación

Necesita Python 3.9 o superior disponible como `python`.

```bash
git clone <url-del-repositorio>
cd sinfuga
python test_sinfuga.py
python sinfuga.py install
```

`install` copia el script a `~/.sinfuga`, agrega hooks a `~/.claude/settings.json` y `~/.codex/hooks.json` (con una copia `.bak`), e instala la skill y el agente auditor. 

**Codex ignora en silencio los hooks que no has aprobado.** Hasta que abras `/hooks` y apruebes SinFuga, Codex no avisa y no se bloquea nada.

Para quitar los hooks:

```bash
python sinfuga.py uninstall
```

## Auditar un proyecto

```bash
python sinfuga.py scan ruta/del/proyecto
```

Muestra archivo, línea y tipo, nunca el valor, y sale con 1 si encuentra algo.

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
- **Necesita Python.** Si `python` no se puede ejecutar, el hook no bloquea.
- **Puede dar falsos positivos.** Un número largo puede pasar un dígito de control por casualidad.

## Licencia

[MIT](LICENSE)
