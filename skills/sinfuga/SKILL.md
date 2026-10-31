---
name: sinfuga
description: Evita fugas de datos hacia la IA. Usar al trabajar con credenciales, archivos .env o datos personales, cuando SinFuga bloquee una accion, o cuando pidan auditar un proyecto en busca de secretos expuestos.
---

# SinFuga

Un hook ya bloquea secretos y rutas sensibles antes de enviarlos. Esta skill cubre lo que el hook no puede decidir.

## Si SinFuga bloquea algo

1. No intentes rodearlo: nada de renombrar, codificar, partir o copiar el dato a otro archivo.
2. Muestra el aviso completo al usuario. Nunca repitas el valor del secreto.
3. Aclara que no es un limite de su plan ni tuyo: es una proteccion local y la decision es suya.
4. Espera su decision. `sinfuga permitir` solo vale si lo escribe el usuario; no lo presiones ni intentes aprobarlo tu.
5. Mientras tanto, ofrece seguir sin el dato: variables de entorno o un archivo `.env.example` con valores falsos.

## Al trabajar

- Pide nombres de variables, nunca sus valores.
- Usa datos falsos en ejemplos y pruebas.
- Trata como sensible lo que el hook no detecta: datos de clientes, medicos, financieros y documentos internos. Pregunta antes de procesarlos.

## Para auditar

```bash
python ~/.sinfuga/sinfuga.py audit RUTA_O_URL
```

Revisa la version actual, el historial de git completo y lo que este en disco. Tambien acepta la URL de un repositorio. Usa `scan RUTA` solo para una revision rapida de archivos actuales.

Reporta archivo, linea y tipo, nunca el valor. Separa lo que parezca dato de ejemplo de lo que parezca real. Si un secreto ya llego a un repositorio o a una conversacion con IA, se considera expuesto: indica al usuario que lo revoque y genere otro. Borrarlo no basta.
