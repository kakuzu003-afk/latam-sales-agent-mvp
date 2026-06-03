# BotBuilder LATAM MVP

MVP local para una agencia de ventas con vendedores IA para negocios latinoamericanos.

## Incluye

- Registro e ingreso simple.
- Panel principal tipo centro de control.
- Panel de ventas con vendedores activos, conversaciones, oportunidades calientes, conversion, ventas ganadas y calidad promedio.
- Embudo de ventas por estado y vendedores con mas actividad.
- Bandeja comercial para atender oportunidades desde una vista de trabajo diaria.
- Crear y editar vendedores IA por negocio.
- Creador por pasos: negocio, informacion del negocio, cultura, venta, canales y prueba final.
- Informacion principal para que el cliente explique su negocio con detalle.
- Boton "Mejorar con IA" para revisar y reescribir una descripcion debil.
- Pais/mercado, moneda, tono, formalidad y vocabulario local.
- Preguntas frecuentes, temas a evitar y mision comercial.
- Conversacion de prueba real antes de instalar.
- Escenarios de prueba: precio, cliente indeciso, cliente molesto, WhatsApp, agenda y preguntas sin respuesta.
- Guardado local de usuarios, vendedores IA, conversaciones, mensajes y oportunidades.
- Captura de oportunidades con intencion detectada, contacto, estado y notas internas.
- Panel de oportunidades con filtros, estados comerciales, notas y apertura directa de WhatsApp.
- Estados comerciales: nuevo, interesado, cotizacion, agendado, contactado, ganado y perdido.
- Panel de conversaciones con detalle, resumen e historial.
- Historial inteligente con intencion, prioridad y proxima accion recomendada.
- Boton de WhatsApp.
- Boton web real en `/widget.js` con boton flotante, color, titulo, texto del boton, mensaje inicial y endpoint publico por vendedor IA.
- Editor visual del boton web con vista previa en vivo dentro del creador.
- URL publica por vendedor IA, por ejemplo `/a/studio-corte`.
- Codigo publico por vendedor IA, por ejemplo `/widget/studio-corte.js`.
- Planes comerciales Inicial, Crecimiento y Agencia con limites de vendedores y mensajes.
- Plantillas por rubro.
- Test de calidad del vendedor IA con recomendaciones accionables.
- Asistente interno de la plataforma para guiar al cliente paso a paso.
- Prompt comercial reforzado: entiende necesidad, responde con datos reales, maneja objeciones y deriva al siguiente paso.
- Modo demo cuando no hay clave configurada.
- Conexion real al motor de IA cuando agregas tu clave privada.
- Mejoras de rendimiento en base de datos e indices para crecer mejor.

## Ejecutar

```powershell
cd outputs\latam-sales-agent-mvp
python app.py
```

Abrir:

```text
http://localhost:8765
```

## Configurar la IA

La app puede leer la clave desde `secrets.json`:

```json
{
  "GROQ_API_KEY": "tu_api_key",
  "GROQ_MODEL": "llama-3.3-70b-versatile"
}
```

Tambien puedes usar variables de entorno antes de ejecutar:

```powershell
$env:GROQ_API_KEY="tu_api_key"
$env:GROQ_MODEL="llama-3.3-70b-versatile"
python app.py
```

Si no configuras la clave, el chat funciona en modo demo para validar el flujo completo.

## Nota

Este MVP esta pensado para probar la idea rapido con negocios reales. Para produccion faltaria endurecer seguridad, recuperacion de contrasena, pagos, WhatsApp Business API real, despliegue, dominios, limites de uso y auditoria de conversaciones.
