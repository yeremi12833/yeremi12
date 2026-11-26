# RX7 LOGIN — Sistema de acceso y panel administrativo

Incluye:
- Login público por KEY.
- Panel privado `/admin.html`.
- Creación manual de KEYS desde el panel.
- Duración: 1, 7, 30, 90, 365 días, fecha personalizada o permanente.
- Desactivación inmediata de KEYS.
- Lista de KEYS con fecha de creación, vencimiento y último uso.
- La KEY completa se muestra una sola vez; la base de datos almacena un HMAC, no la KEY original.
- Sesiones administrativas en SQLite, cookie HttpOnly/SameSite Strict, regeneración de sesión, limitación de intentos, protección CSRF y comprobación de origen.

## Requisitos
Node.js 20 o superior.

## Ejecutar localmente
1. Descomprime el proyecto.
2. Copia `.env.example` y crea un archivo llamado `.env`.
3. Cambia `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `SESSION_SECRET` y `KEY_PEPPER`. La contraseña debe tener 16+ caracteres y cada secreto 32+.
4. Instala dependencias: `npm install`
5. Inicia: `npm start`
6. Abre `http://localhost:3000` y el panel en `http://localhost:3000/admin.html`.

Puedes generar secretos con:
`node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`

## Publicar
El proyecto incluye `Dockerfile` y `render.yaml` como base para Render. Crea un servicio web con disco persistente montado en `/app/data`; configura las variables de entorno indicadas en `.env.example`. Usa HTTPS y no publiques ni compartas `.env`. No uses almacenamiento efímero para `/app/data`, porque ahí se guardan las KEYS y sesiones.

## Personalizar el destino después del login
Edita `public/acceso.html` y coloca allí el contenido privado de tu sitio. La ruta `/acceso.html` está protegida por sesión.

## Importante
Este proyecto es una base funcional lista para configurar y desplegar, pero no queda alojada en Internet automáticamente. Antes de producción:
- Configura un dominio HTTPS.
- Cambia todas las credenciales de ejemplo.
- Configura copias de seguridad del directorio `data/`.
- Añade la política de privacidad y condiciones de uso aplicables.
- Mantén Node y las dependencias actualizados.
