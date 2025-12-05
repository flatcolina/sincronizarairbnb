#!/usr/bin/env python3
"""
Robô de Sincronização de Reservas - Airbnb via Gmail
======================================================

Este script sincroniza automaticamente as reservas do Airbnb
através da análise de e-mails de confirmação de reserva.

Configuração:
- Executar em um servidor (ex: Railway) com agendamento (ex: a cada 15 minutos)
- Variáveis de ambiente necessárias:
  - FIREBASE_CREDENTIALS_JSON: JSON com credenciais do Firebase
  - FIREBASE_PROJECT_ID: ID do projeto Firebase
  - GOOGLE_CLIENT_ID: Client ID do Google OAuth
  - GOOGLE_CLIENT_SECRET: Client Secret do Google OAuth
  - GOOGLE_REFRESH_TOKEN: Refresh Token do Google OAuth

Uso:
  python3 robo_gmail_airbnb.py

Configuração do Google OAuth:
1. Acesse https://console.cloud.google.com
2. Crie um novo projeto
3. Ative a Gmail API
4. Crie uma credencial OAuth 2.0 (Desktop application)
5. Use o refresh token obtido
"""

import os
import sys
import json
import logging
import base64
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from html.parser import HTMLParser

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Importar Firebase
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except ImportError:
    logger.error("Firebase Admin SDK não instalado. Instale com: pip install firebase-admin")
    sys.exit(1)

# Importar Google
try:
    from google.auth.transport.requests import Request
    from google.oauth2.service_account import Credentials
    from google.oauth2 import service_account
    import google.auth
except ImportError:
    logger.error("Google Auth não instalado. Instale com: pip install google-auth google-auth-oauthlib google-auth-httplib2")
    sys.exit(1)

try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    logger.error("Google API Client não instalado. Instale com: pip install google-api-python-client")
    sys.exit(1)


class HTMLStripper(HTMLParser):
    """Remove tags HTML de um texto"""
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.text = []

    def handle_data(self, d):
        self.text.append(d)

    def get_data(self):
        return ''.join(self.text)


class RoboGmailAirbnb:
    """Robô para sincronizar reservas do Airbnb via Gmail"""

    def __init__(self):
        """Inicializa o robô"""
        self.db = None
        self.gmail_service = None
        self.inicializar_firebase()
        self.inicializar_gmail()

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

            if not firebase_admin.get_app():
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
                logger.warning("⚠️  Credenciais do Google não configuradas")
                logger.warning("   Defina: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN")
                self.gmail_service = None
                return

            # Criar credencial OAuth
            from google.oauth2.credentials import Credentials
            
            creds = Credentials(
                token=None,
                refresh_token=refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=client_id,
                client_secret=client_secret
            )

            # Construir serviço Gmail
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            logger.info("✅ Gmail API inicializado com sucesso")
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar Gmail: {e}")
            self.gmail_service = None

    def buscar_emails_airbnb(self) -> List[Dict]:
        """Busca e-mails de confirmação do Airbnb"""
        if not self.gmail_service:
            logger.warning("⚠️  Gmail não configurado, pulando sincronização de e-mails")
            return []

        try:
            logger.info("📧 Buscando e-mails do Airbnb...")
            
            # Buscar e-mails do Airbnb com label 'airbnb-reservas'
            results = self.gmail_service.users().messages().list(
                userId='me',
                q='from:reservations@airbnb.com label:airbnb-reservas is:unread',
                maxResults=10
            ).execute()

            messages = results.get('messages', [])
            logger.info(f"✅ {len(messages)} e-mails encontrados")
            return messages
        except HttpError as error:
            logger.error(f"❌ Erro ao buscar e-mails: {error}")
            return []

    def obter_conteudo_email(self, message_id: str) -> Optional[str]:
        """Obtém o conteúdo de um e-mail"""
        try:
            message = self.gmail_service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()

            # Tentar obter conteúdo
            if 'parts' in message['payload']:
                for part in message['payload']['parts']:
                    if part['mimeType'] == 'text/html':
                        data = part['body'].get('data', '')
                        if data:
                            return base64.urlsafe_b64decode(data).decode('utf-8')
                    elif part['mimeType'] == 'text/plain':
                        data = part['body'].get('data', '')
                        if data:
                            return base64.urlsafe_b64decode(data).decode('utf-8')
            else:
                data = message['payload']['body'].get('data', '')
                if data:
                    return base64.urlsafe_b64decode(data).decode('utf-8')

            return None
        except Exception as e:
            logger.error(f"❌ Erro ao obter conteúdo do e-mail: {e}")
            return None

    def remover_html(self, html: str) -> str:
        """Remove tags HTML de um texto"""
        stripper = HTMLStripper()
        stripper.feed(html)
        return stripper.get_data()

    def extrair_dados_email_airbnb(self, conteudo: str) -> Optional[Dict]:
        """Extrai dados de reserva do e-mail do Airbnb"""
        try:
            # Remover HTML
            texto = self.remover_html(conteudo)
            
            # Padrões de busca
            padrao_nome = r'(?:Hóspede|Guest|Name):\s*([^\n]+)'
            padrao_checkin = r'(?:Check-in|Check in)[\s\n]*([^\n]+)'
            padrao_checkout = r'(?:Check-out|Check out)[\s\n]*([^\n]+)'
            padrao_codigo = r'(?:Código|Code|Confirmation)[\s\n]*([A-Z0-9]+)'
            padrao_anuncio = r'(?:Acomodação|Accommodation|Listing)[\s\n]*([^\n]+)'
            padrao_valor = r'R\$\s*([\d.,]+)'
            padrao_hospedes = r'(\d+)\s*(?:adultos|adults)'

            # Extrair informações
            nome_match = re.search(padrao_nome, texto, re.IGNORECASE)
            checkin_match = re.search(padrao_checkin, texto, re.IGNORECASE)
            checkout_match = re.search(padrao_checkout, texto, re.IGNORECASE)
            codigo_match = re.search(padrao_codigo, texto, re.IGNORECASE)
            anuncio_match = re.search(padrao_anuncio, texto, re.IGNORECASE)
            valor_match = re.search(padrao_valor, texto, re.IGNORECASE)
            hospedes_match = re.search(padrao_hospedes, texto, re.IGNORECASE)

            if not all([nome_match, checkin_match, checkout_match, codigo_match]):
                logger.warning("⚠️  Não foi possível extrair todos os dados do e-mail")
                return None

            nome = nome_match.group(1).strip()
            codigo = codigo_match.group(1).strip()
            anuncio = anuncio_match.group(1).strip() if anuncio_match else ''
            valor = valor_match.group(1).strip() if valor_match else '0'
            hospedes = int(hospedes_match.group(1)) if hospedes_match else 1

            # Processar datas
            data_checkin = self.extrair_data(checkin_match.group(1))
            data_checkout = self.extrair_data(checkout_match.group(1))

            if not data_checkin or not data_checkout:
                logger.warning("⚠️  Não foi possível extrair datas válidas")
                return None

            return {
                'nome': nome,
                'dataCheckin': data_checkin,
                'dataCheckout': data_checkout,
                'codigoReserva': codigo,
                'anuncio': anuncio,
                'valor': valor,
                'numeroHospedes': hospedes
            }
        except Exception as e:
            logger.error(f"❌ Erro ao extrair dados do e-mail: {e}")
            return None

    def extrair_data(self, texto_data: str) -> Optional[str]:
        """Extrai data no formato YYYY-MM-DD de um texto"""
        try:
            # Remover espaços extras
            texto_data = texto_data.strip()
            
            # Tentar vários formatos
            formatos = [
                '%d/%m/%Y',
                '%d-%m-%Y',
                '%Y-%m-%d',
                '%d de %B de %Y',
                '%d de %b de %Y',
                '%d %B %Y',
                '%d %b %Y',
            ]

            for fmt in formatos:
                try:
                    data = datetime.strptime(texto_data, fmt)
                    return data.strftime('%Y-%m-%d')
                except ValueError:
                    continue

            # Se nenhum formato funcionou, tentar extrair números
            numeros = re.findall(r'\d+', texto_data)
            if len(numeros) >= 3:
                dia, mes, ano = numeros[0], numeros[1], numeros[2]
                if len(ano) == 2:
                    ano = '20' + ano
                return f"{ano}-{mes.zfill(2)}-{dia.zfill(2)}"

            return None
        except Exception as e:
            logger.warning(f"⚠️  Erro ao extrair data: {e}")
            return None

    def obter_apartamento_por_anuncio(self, nome_anuncio: str) -> Optional[str]:
        """Obtém o ID do apartamento a partir do nome do anúncio"""
        try:
            config = self.db.collection('integracao_config').stream()
            
            for doc in config:
                config_data = doc.to_dict()
                mappings = config_data.get('airbnbMappings', [])
                
                for mapping in mappings:
                    if mapping.get('nomeAnuncio', '').lower() == nome_anuncio.lower():
                        return mapping.get('apartamentoId')
            
            return None
        except Exception as e:
            logger.error(f"❌ Erro ao obter apartamento: {e}")
            return None

    def verificar_reserva_existente(self, apartamento_id: str, codigo_reserva: str) -> bool:
        """Verifica se uma reserva já existe"""
        try:
            docs = self.db.collection('pre_reservas').where(
                'apartamentoId', '==', apartamento_id
            ).where(
                'codigoReservaOrigem', '==', codigo_reserva
            ).where(
                'origem', '==', 'airbnb'
            ).stream()

            existe = len(list(docs)) > 0
            
            if existe:
                logger.info(f"ℹ️  Reserva {codigo_reserva} já existe, pulando...")
            
            return existe
        except Exception as e:
            logger.error(f"❌ Erro ao verificar reserva: {e}")
            return False

    def criar_pre_reserva(self, dados: Dict, apartamento_id: str) -> bool:
        """Cria uma pré-reserva no Firestore"""
        try:
            # Converter valor
            valor = 0
            try:
                valor_str = dados['valor'].replace('.', '').replace(',', '.')
                valor = float(valor_str)
            except:
                pass

            pre_reserva = {
                'nome': dados['nome'],
                'dataCheckin': dados['dataCheckin'],
                'dataCheckout': dados['dataCheckout'],
                'apartamentoId': apartamento_id,
                'origem': 'airbnb',
                'codigoReservaOrigem': dados['codigoReserva'],
                'status': 'pendente_validacao',
                'valor': valor,
                'numeroHospedes': dados.get('numeroHospedes', 1),
                'observacao': f"Anúncio: {dados.get('anuncio', '')}",
                'criadoEm': firestore.SERVER_TIMESTAMP
            }

            self.db.collection('pre_reservas').add(pre_reserva)
            logger.info(f"✅ Pré-reserva criada: {dados['codigoReserva']}")
            return True
        except Exception as e:
            logger.error(f"❌ Erro ao criar pré-reserva: {e}")
            return False

    def marcar_email_como_lido(self, message_id: str):
        """Marca um e-mail como lido"""
        try:
            self.gmail_service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
        except Exception as e:
            logger.warning(f"⚠️  Erro ao marcar e-mail como lido: {e}")

    def executar(self):
        """Executa o robô de sincronização"""
        logger.info("=" * 60)
        logger.info("🤖 Robô de Sincronização - Airbnb via Gmail")
        logger.info("=" * 60)

        try:
            if not self.gmail_service:
                logger.warning("⚠️  Gmail não configurado. Pulando sincronização de e-mails.")
                return

            # Buscar e-mails
            emails = self.buscar_emails_airbnb()
            if not emails:
                logger.info("ℹ️  Nenhum e-mail novo encontrado")
                return

            total_criadas = 0
            for message in emails:
                message_id = message['id']
                
                # Obter conteúdo
                conteudo = self.obter_conteudo_email(message_id)
                if not conteudo:
                    logger.warning(f"⚠️  Não foi possível obter conteúdo do e-mail {message_id}")
                    continue

                # Extrair dados
                dados = self.extrair_dados_email_airbnb(conteudo)
                if not dados:
                    logger.warning(f"⚠️  Não foi possível extrair dados do e-mail {message_id}")
                    self.marcar_email_como_lido(message_id)
                    continue

                # Obter apartamento
                apartamento_id = self.obter_apartamento_por_anuncio(dados['anuncio'])
                if not apartamento_id:
                    logger.warning(f"⚠️  Apartamento não encontrado para: {dados['anuncio']}")
                    self.marcar_email_como_lido(message_id)
                    continue

                # Verificar se já existe
                if self.verificar_reserva_existente(apartamento_id, dados['codigoReserva']):
                    self.marcar_email_como_lido(message_id)
                    continue

                # Criar pré-reserva
                if self.criar_pre_reserva(dados, apartamento_id):
                    total_criadas += 1
                    self.marcar_email_como_lido(message_id)

            logger.info("=" * 60)
            logger.info(f"✅ Sincronização concluída: {total_criadas} pré-reservas criadas")
            logger.info("=" * 60)

        except Exception as e:
            logger.error(f"❌ Erro durante a sincronização: {e}")
            sys.exit(1)


def main():
    """Função principal"""
    robo = RoboGmailAirbnb()
    robo.executar()


if __name__ == '__main__':
    main()
