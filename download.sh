#!/bin/bash
set -euo pipefail

# --- CONFIGURACIÓN ---
REPO="0rphee/cripto_final"
ASSET_BASE="cripto-final"
# ---------------------

# Detectar arquitectura
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)
        ASSET="${ASSET_BASE}-x86_64"
        ;;
    i386|i686)
        ASSET="${ASSET_BASE}-i386"
        ;;
    *)
        echo "ERROR: Arquitectura no soportada: $ARCH"
        exit 1
        ;;
esac

echo "Descargando $ASSET del último release de $REPO..."

# Obtener etiqueta del último release
TAG=$(curl -sL \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name":' \
    | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')

if [ -z "$TAG" ]; then
    echo "ERROR: No se pudo obtener la etiqueta del último release."
    exit 1
fi

echo "Versión encontrada: $TAG"

# URL del binario
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

# Archivo temporal
TMPFILE="$(mktemp)"

echo "Descargando binario..."
if ! curl -sL "$DOWNLOAD_URL" --output "$TMPFILE"; then
    echo "ERROR: No se pudo descargar el binario."
    exit 1
fi

# Nombre final sin sufijo de arquitectura
FINAL_NAME="$ASSET_BASE"

# Sobrescribir si existe
if [ -f "$FINAL_NAME" ]; then
    echo "Eliminando versión previa de $FINAL_NAME..."
    rm -f "$FINAL_NAME"
fi

# Mover el archivo descargado al nombre final
mv -f "$TMPFILE" "$FINAL_NAME"

chmod +x "$FINAL_NAME"

echo "Instalación completada. Ejecuta con: ./$FINAL_NAME server"
