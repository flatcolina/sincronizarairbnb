#!/usr/bin/env python3
"""
Robô de Sincronização de Reservas entre Gmail, Airbnb e Firebase.

Funcionalidades principais:
- Lê e-mails no Gmail relacionados a reservas do Airbnb
- Processa os dados da reserva
- Atualiza o Firestore com as reservas sincronizadas

Modo de execução:
- Execução única: roda uma vez e finaliza
- Modo contínuo: verifica a cada X minutos (configurável)
"""

import os
import sys
import time
import json
import logging
import base64
import re
from typing import List, Dict, Optional
from datetime import datetime, timedelta

# Firebase Admin
import firebase_admin
from firebase_admin import credentials, firestore

# Gmail API
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

try:
    from googleapiclient.errors import HttpError
except ImportError:
    HttpError = Exception

# Configuração básica de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


class AirbnbGmailSyncBot:
    """
    Robô responsável por:
    - Conectar ao Gmail
    - Buscar e-mails de reservas do Airbnb
    - Extrair dados relevantes
    - Atualizar Firestore
    """

    def __init__(self):
        self.db = None
        self.gmail_service = None
        
        # Configurações
        self.email_user = os.getenv('GMAIL_USER_EMAIL', '')
        self.search_query = os.getenv(
            'GMAIL_SEARCH_QUERY',
            'from:(express@airbnb.com) subject:(Confirmação de reserva)'
        )
        
        # Tempo entre execuções em modo contínuo (em segundos)
        self.intervalo_segundos = int(os.getenv('SYNC_INTERVAL_SECONDS', '300'))
        
        logger.info("🔧 Iniciando configuração do bot de sincronização Airbnb-Gmail-Firebase")
        self.inicializar_firebase()
        self.inicializar_gmail()

    # ---------------------------------------------------------
    # Inicialização de serviços
    # ---------------------------------------------------------
    def inicializar_firebase(self):
        """Inicializa a conexão com Firebase"""
        try:
            creds_json = os.getenv('FIREBASE_CREDENTIALS_JSON')
            
            if creds_json:
                creds_dict = json.loads(creds_json)
                creds = credentials.Certificate(creds_dict)
            else:
                creds_path = 'firebase-credentials.json'
                if not os.path.exists(creds_path):
                    logger.error(f"Arquivo de credenciais não encontrado: {creds_path}")
                    sys.exit(1)
                creds = credentials.Certificate(creds_path)

            # Garante que o app padrão esteja inicializado
            try:
                firebase_admin.get_app()
            except ValueError:
                firebase_admin.initialize_app(creds)
            
            self.db = firestore.client()
            logger.info("✅ Firebase inicializado com sucesso")
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar Firebase: {e}")
            sys.exit(1)

    def inicializar_gmail(self):
        """Inicializa a conexão com Gmail API"""
        try:
            # Obter credenciais do ambiente
            client_id = os.getenv('GOOGLE_CLIENT_ID')
            client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
            refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')

            if not all([client_id, client_secret, refresh_token]):
                logger.error("⚠️ Variáveis de ambiente do Gmail incompletas.")
                raise ValueError("Credenciais do Gmail não configuradas corretamente.")
            
            token_uri = "https://oauth2.googleapis.com/token"
            
            creds_data = {
                "token": "",
                "refresh_token": refresh_token,
                "token_uri": token_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": [
                    "https://www.googleapis.com/auth/gmail.readonly"
                ]
            }
            
            creds = Credentials.from_authorized_user_info(creds_data)
            
            if not creds.valid and creds.expired and creds.refresh_token:
                logger.info("🔄 Atualizando token de acesso do Gmail...")
                creds.refresh(Request())
            
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            logger.info("✅ Gmail API inicializada com sucesso")
        
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar Gmail API: {e}")
            sys.exit(1)

    # ---------------------------------------------------------
    # Funções utilitárias
    # ---------------------------------------------------------
    def extrair_corpo_email(self, message_payload: Dict) -> str:
        """Extrai o corpo em texto do e-mail (em HTML ou texto simples)"""
        try:
            if 'parts' in message_payload:
                parts = message_payload['parts']
                for part in parts:
                    body = part.get('body', {})
                    data = body.get('data')
                    if data:
                        decoded_bytes = base64.urlsafe_b64decode(data)
                        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                        return decoded_text
            else:
                body = message_payload.get('body', {})
                data = body.get('data')
                if data:
                    decoded_bytes = base64.urlsafe_b64decode(data)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                    return decoded_text
            return ""
        except Exception as e:
            logger.error(f"Erro ao extrair corpo de e-mail: {e}")
            return ""

    def extrair_header(self, headers: List[Dict], name: str) -> Optional[str]:
        """Extrai um header específico por nome"""
        for h in headers:
            if h.get('name', '').lower() == name.lower():
                return h.get('value', '')
        return None

    # ---------------------------------------------------------
    # Parsing de e-mail Airbnb
    # ---------------------------------------------------------
    def parse_reserva_airbnb(self, email_body: str) -> Dict:
        """
        Interpreta o corpo de e-mail do Airbnb para extrair dados da reserva.
        Esta função é simplificada e pode ser ajustada conforme o padrão do e-mail.
        """
        reserva = {
            "origem": "airbnb",
            "status": "pendente",
            "hospede": "",
            "checkin": "",
            "checkout": "",
            "quantidade_hospedes": 0,
            "valor_total": 0.0,
            "moeda": "BRL",
            "codigo_reserva": "",
        }
        
        try:
            # Exemplos de regex que você pode ir refinando conforme seus e-mails reais:
            
            # Nome do hóspede (exemplo de padrão)
            match_hospede = re.search(r"Hóspede:\s*(.*)", email_body)
            if match_hospede:
                reserva["hospede"] = match_hospede.group(1).strip()
            
            # Check-in
            match_checkin = re.search(r"Check[- ]in:\s*([\d]{1,2}\s+\w+\s+[\d]{4})", email_body)
            if match_checkin:
                reserva["checkin"] = self._parse_data_pt_br(match_checkin.group(1))
            
            # Check-out
            match_checkout = re.search(r"Check[- ]out:\s*([\d]{1,2}\s+\w+\s+[\d]{4})", email_body)
            if match_checkout:
                reserva["checkout"] = self._parse_data_pt_br(match_checkout.group(1))
            
            # Quantidade de hóspedes
            match_hospedes = re.search(r"(\d+)\s+hóspede", email_body, re.IGNORECASE)
            if match_hospedes:
                reserva["quantidade_hospedes"] = int(match_hospedes.group(1))
            
            # Valor total (exemplo: R$ 1.234,56)
            match_valor = re.search(r"R\$\s*([\d\.\,]+)", email_body)
            if match_valor:
                valor_str = match_valor.group(1).replace('.', '').replace(',', '.')
                reserva["valor_total"] = float(valor_str)
            
            # Código de reserva (por exemplo, código alfanumérico do Airbnb)
            match_codigo = re.search(r"Código da reserva:\s*([A-Z0-9]+)", email_body)
            if match_codigo:
                reserva["codigo_reserva"] = match_codigo.group(1).strip()
            
            logger.info(f"📦 Reserva Airbnb parseada: {reserva}")
        
        except Exception as e:
            logger.error(f"Erro ao parsear e-mail de reserva Airbnb: {e}")
        
        return reserva

    def _parse_data_pt_br(self, data_str: str) -> str:
        """
        Converte uma data em português (tipo '10 de dezembro de 2025')
        ou ('10 dezembro 2025') para formato ISO (YYYY-MM-DD).
        """
        # Este mapeamento pode ser expandido conforme necessário
        meses = {
            "janeiro": 1,
            "fevereiro": 2,
            "março": 3,
            "marco": 3,
            "abril": 4,
            "maio": 5,
            "junho": 6,
            "julho": 7,
            "agosto": 8,
            "setembro": 9,
            "outubro": 10,
            "novembro": 11,
            "dezembro": 12
        }
        
        try:
            # Tenta padronizar removendo "de"
            data_str_limpa = data_str.lower().replace(" de ", " ").strip()
            partes = data_str_limpa.split()
            if len(partes) == 3:
                dia = int(partes[0])
                mes_nome = partes[1]
                ano = int(partes[2])
                mes = meses.get(mes_nome, 1)
                dt = datetime(ano, mes, dia)
                return dt.strftime("%Y-%m-%d")
        except Exception as e:
            logger.error(f"Erro ao converter data '{data_str}': {e}")
        
        # Em caso de falha, retorna a string original
        return data_str

    # ---------------------------------------------------------
    # Integração com Gmail
    # ---------------------------------------------------------
    def buscar_emails_reservas(self, max_results: int = 10) -> List[Dict]:
        """Busca e-mails de confirmação de reserva do Airbnb no Gmail."""
        try:
            logger.info(f"🔎 Buscando e-mails no Gmail com query: {self.search_query}")
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=self.search_query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            logger.info(f"📨 {len(messages)} e-mails encontrados")
            return messages
        except HttpError as error:
            logger.error(f"Erro ao buscar e-mails: {error}")
            return []

    def processar_emails(self, max_results: int = 10):
        """Processa e-mails de reservas do Airbnb, salvando/atualizando no Firestore."""
        messages = self.buscar_emails_reservas(max_results=max_results)
        
        for msg in messages:
            msg_id = msg['id']
            try:
                email = self.gmail_service.users().messages().get(
                    userId='me', id=msg_id, format='full'
                ).execute()
                
                payload = email.get('payload', {})
                headers = payload.get('headers', [])
                
                assunto = self.extrair_header(headers, 'Subject') or ''
                data_envio = self.extrair_header(headers, 'Date') or ''
                
                corpo = self.extrair_corpo_email(payload)
                
                logger.info(f"✉️ Processando e-mail ID={msg_id}, Assunto='{assunto}'")
                
                reserva = self.parse_reserva_airbnb(corpo)
                reserva["assunto_email"] = assunto
                reserva["data_envio_email"] = data_envio
                reserva["id_email"] = msg_id
                
                self.salvar_reserva_no_firestore(reserva)
            
            except HttpError as error:
                logger.error(f"Erro HTTP ao processar e-mail {msg_id}: {error}")
            except Exception as e:
                logger.error(f"Erro inesperado ao processar e-mail {msg_id}: {e}")

    # ---------------------------------------------------------
    # Integração com Firestore
    # ---------------------------------------------------------
    def salvar_reserva_no_firestore(self, reserva: Dict):
        """
        Salva ou atualiza uma reserva no Firestore.
        A coleção e chave podem ser adaptadas de acordo com a sua estrutura.
        """
        try:
            # Exemplo: coleção 'reservas_airbnb', documento pelo 'codigo_reserva' ou 'id_email'
            colecao = "reservas_airbnb"
            doc_id = reserva.get("codigo_reserva") or reserva.get("id_email")
            
            if not doc_id:
                logger.warning(f"⚠️ Reserva sem identificador único, não será salva: {reserva}")
                return
            
            doc_ref = self.db.collection(colecao).document(doc_id)
            
            # Adiciona timestamp de sincronização
            reserva["sincronizado_em"] = datetime.utcnow().isoformat()
            
            doc_ref.set(reserva, merge=True)
            logger.info(f"💾 Reserva salva/atualizada no Firestore: {colecao}/{doc_id}")
        
        except Exception as e:
            logger.error(f"Erro ao salvar reserva no Firestore: {e}")

    # ---------------------------------------------------------
    # Loop principal
    # ---------------------------------------------------------
    def executar_uma_vez(self):
        """Executa uma varredura única de e-mails e processa as reservas."""
        logger.info("🚀 Executando sincronização única de reservas (Airbnb ↔ Gmail ↔ Firebase)")
        self.processar_emails()

    def executar_continuamente(self):
        """Executa o robô em loop, verificando e-mails periodicamente."""
        logger.info("🔁 Iniciando execução contínua do robô de sincronização.")
        try:
            while True:
                self.executar_uma_vez()
                logger.info(f"⏳ Aguardando {self.intervalo_segundos} segundos para nova verificação...")
                time.sleep(self.intervalo_segundos)
        except KeyboardInterrupt:
            logger.info("🛑 Execução interrompida manualmente.")


def main():
    modo = os.getenv("SYNC_MODE", "once").lower()
    
    bot = AirbnbGmailSyncBot()
    
    if modo == "continuous":
        bot.executar_continuamente()
    else:
        bot.executar_uma_vez()


if __name__ == "__main__":
    main()
