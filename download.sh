#!/bin/bash
set -euo pipefail

# --- CONFIGURACIÓN ---
REPO="0rphee/cripto_final"
ASSET="cripto-final"
# ---------------------

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

# Sobrescribir si existe
if [ -f "$ASSET" ]; then
    echo "Eliminando versión previa de $ASSET..."
    rm -f "$ASSET"
fi

# Mover el archivo descargado al nombre final (forzado)
mv -f "$TMPFILE" "$ASSET"

chmod +x "$ASSET"

echo "Instalación completada. Ejecuta con: ./$ASSET server"
