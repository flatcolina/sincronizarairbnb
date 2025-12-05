#!/bin/bash
set -e

echo "📦 Instalando dependências..."
pip install -r requirements_robos.txt

echo "🤖 Iniciando robô de sincronização Airbnb..."
python3 robo_gmail_airbnb.py
