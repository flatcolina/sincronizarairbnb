FROM python:3.11-slim

WORKDIR /app

# Copiar arquivos
COPY requirements_robos.txt .
COPY robo_gmail_airbnb.py .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements_robos.txt

# Executar o robô
CMD ["python3", "robo_gmail_airbnb.py"]
