# Proyecto: Sistema de Seguridad en Correo Electrónico (PKI)

## 🚀 Guía de Inicio Rápido

Sigue estos pasos para configurar e inicializar el proyecto desde cero.

### 1. Prerrequisitos (Descargas)

Si no tienes instaladas las herramientas base, descárgalas aquí:

*   **Git:** [Descargar Git](https://git-scm.com/downloads) - Necesario para clonar el repositorio.
*   **Docker Desktop:** [Descargar Docker](https://www.docker.com/products/docker-desktop/) - Recomendado para ejecutar el proyecto sin configurar Python localmente.
*   **Python (Opcional):** [Descargar Python 3.10+](https://www.python.org/downloads/) - Solo si deseas ejecutarlo de forma nativa sin Docker.

### 2. Clonar el Proyecto

Abre una terminal (CMD, PowerShell o Git Bash) y ejecuta:

```bash
git clone https://github.com/Isaiah-Work/MailGuard-PKI.git
cd MailGuard-PKI
```

### 3. Inicialización y Previsualización

Tienes dos métodos para poner en marcha el proyecto:

#### Opción A: Usando Docker (Recomendado)
Este método configura automáticamente todo el entorno, incluyendo OpenSSL y las dependencias.

1.  Asegúrate de que Docker esté abierto.
2.  En la terminal, dentro de la carpeta del proyecto, ejecuta:
    ```bash
    docker-compose up --build
    ```
3.  Una vez finalizado, abre tu navegador en: [http://localhost:8099](http://localhost:8099)

#### Opción B: Ejecución Local (Nativa)
Requiere tener Python instalado en tu sistema.

1.  **Crear entorno virtual:**
    ```bash
    python -m venv env
    ```
2.  **Activar entorno:**
    *   **Windows:** `.\env\Scripts\activate`
    *   **Mac/Linux:** `source ./env/bin/activate`
3.  **Instalar dependencias:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Ejecutar aplicación:**
    ```bash
    python main.py
    ```
5.  Accede a: [http://localhost:8099](http://localhost:8099)

---

