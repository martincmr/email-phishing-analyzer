# Detector de phishing en emails

Esta herramienta analiza un email y detecta un posible ataque de phishing.

## Características de la herramienta

- Discrepancia del nombre del remitente con el dominio.
- URLs en el email que apuntan a páginas sospechosas.
- Reputación de URLs en el email.
- Posibles adjuntos peligrosos.
- Archivos adjuntos de doble extensión.
- Hash SHA256 de archivos adjuntos en el email.
- Tracking pixels en el email.
- Palabras claves comunmente usadas en phishing.
- Resultados de autenticación.

## Requisitos

- Python 3.x
- API key de VirusTotal (es gratis: https://www.virustotal.com/)

## Cómo usar la herramienta

Primero debe clonar o descargar el repositorio y dirigirse al directorio de la herramienta.

Instalará las dependencias necesarias ejecutando:

```bash
pip install -r requirements.txt
```

Necesitará utilizar la API de VirusTotal para obtener información sobre las URLs en los emails. Deberá registrarse en https://www.virustotal.com/ y obtener una API key desde su perfil.

Luego, debe crear el archivo .env en la raíz del proyecto y agregar la API obtenida en VirusTotal en api_vt=su_api_key

Todo listo. Ahora puede ejecutar el script:

```bash
python analyzer.py mail.eml
```

Para más información acerca de ésta herramienta puede consultar mi artículo: https://martincamara.com/blog/analyzer-tool
