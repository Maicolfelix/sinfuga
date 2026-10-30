---
name: sinfuga
description: Evita fugas de datos hacia la IA. Usar al trabajar con credenciales, archivos .env o datos personales, cuando SinFuga bloquee una accion, o cuando pidan auditar un proyecto en busca de secretos expuestos.
---

# SinFuga

Un hook ya bloquea secretos y rutas sensibles antes de enviarlos. Esta skill cubre lo que el hook no puede decidir.

## Si SinFuga bloquea algo

1. No intentes rodearlo: nada de renombrar, codificar, partir o copiar el dato a otro archivo.
2. Di al usuario que se bloqueo y por que. Nunca repitas el valor del secreto.
3. Sigue sin el dato: usa variables de entorno o un archivo `.env.example` con valores falsos.

## Al trabajar

- Pide nombres de variables, nunca sus valores.
- Usa datos falsos en ejemplos y pruebas.
- Trata como sensible lo que el hook no detecta: datos de clientes, medicos, financieros y documentos internos. Pregunta antes de procesarlos.

## Para auditar

```bash
python ~/.sinfuga/sinfuga.py scan RUTA
```

Reporta archivo, linea y tipo, nunca el valor. Si un secreto ya llego a un repositorio o a una conversacion con IA, se considera expuesto: indica al usuario que lo revoque y genere otro. Borrarlo no basta.
