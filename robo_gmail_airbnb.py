#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
            'from:(tiagoddantas@me.com) subject:(Enc: Confirmação de reserva)'
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
            
            if (not creds.valid) and creds.expired and creds.refresh_token:
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

    def _limpar_html(self, texto: str) -> str:
        """Remove tags HTML e normaliza espaços."""
        if not texto:
            return ""
        # remove tags
        sem_tags = re.sub(r'<[^>]+>', '', texto)
        # normaliza espaços
        sem_tags = re.sub(r'\s+', ' ', sem_tags)
        return sem_tags.strip()

    # ---------------------------------------------------------
    # Parsing de datas PT-BR (incluindo abreviações Airbnb)
    # ---------------------------------------------------------
    def _parse_data_pt_br(self, data_str: str) -> str:
        """
        Converte uma data em português para formato ISO (YYYY-MM-DD).

        Exemplos aceitos:
        - "qua., 18 de fev. de 2026"
        - "18 de fevereiro de 2026"
        - "10 dezembro 2025"
        """
        meses = {
            "jan": 1, "janeiro": 1,
            "fev": 2, "fev.": 2, "fevereiro": 2,
            "mar": 3, "mar.": 3, "marco": 3, "março": 3,
            "abr": 4, "abr.": 4, "abril": 4,
            "mai": 5, "mai.": 5, "maio": 5,
            "jun": 6, "junho": 6,
            "jul": 7, "julho": 7,
            "ago": 8, "ago.": 8, "agosto": 8,
            "set": 9, "set.": 9, "setembro": 9,
            "out": 10, "out.": 10, "outubro": 10,
            "nov": 11, "nov.": 11, "novembro": 11,
            "dez": 12, "dez.": 12, "dezembro": 12,
        }
        
        try:
            if not data_str:
                return data_str

            s = data_str.lower().strip()

            # Remove dia da semana no início, ex: "qua., ", "dom. "
            s = re.sub(r'^[a-zç\.]{3,},?\s*', '', s)

            # Tenta padrão "18 de fev. de 2026"
            m = re.search(r'(\d{1,2})\s+de\s+([a-zç\.]+)\s+de\s+(\d{4})', s)
            if m:
                dia = int(m.group(1))
                mes_token = m.group(2).strip().rstrip('.')
                ano = int(m.group(3))
                mes = meses.get(mes_token, meses.get(mes_token + '.', 1))
                dt = datetime(ano, mes, dia)
                return dt.strftime("%Y-%m-%d")

            # Fallback: "10 dezembro 2025"
            s2 = s.replace(" de ", " ")
            partes = s2.split()
            if len(partes) == 3:
                dia = int(partes[0])
                mes_nome = partes[1].strip().rstrip('.')
                ano = int(partes[2])
                mes = meses.get(mes_nome, meses.get(mes_nome + '.', 1))
                dt = datetime(ano, mes, dia)
                return dt.strftime("%Y-%m-%d")

        except Exception as e:
            logger.error(f"Erro ao converter data '{data_str}': {e}")
        
        # Em caso de falha, retorna a string original
        return data_str

    # ---------------------------------------------------------
    # Parsing de e-mail Airbnb (HTML)
    # ---------------------------------------------------------
    def parse_reserva_airbnb(self, email_body: str) -> Dict:
        """
        Interpreta o corpo de e-mail do Airbnb para extrair dados da reserva,
        usando especificamente os elementos informados:

        1) <h2> ... nome do apto -> nomeApAirbnb
        2) <p style="font-size:22px..."> data check-in (primeiro) -> checkin
        3) <p style="font-size:22px..."> data check-out (segundo) -> checkout
        4) <p style="font-size:18px;...font-weight:400..."> HMB39THXQK -> codigo_reserva
        5) <p style="font-size:18px;...font-weight:700!..."> Letícia -> hospede
        6) <p style="font-size:18px;...font-weight:400!..."> "2 adultos" ou "2 adultos, 1 criança" -> quantidade_hospedes (soma)
        7) <h3 style="font-size:18px;...text-align:right!...">R$1.717,53</h3> -> valor_total
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
            "nomeApAirbnb": ""
        }
        
        try:
            html = email_body

            # -------- 1) Nome do apartamento (h2) --------
            match_nome = re.search(
                r'<h2[^>]*>(.*?)</h2>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_nome:
                nome_raw = match_nome.group(1)
                reserva["nomeApAirbnb"] = self._limpar_html(nome_raw)
            
            # -------- 2) & 3) Datas de check-in e check-out --------
            # <p style="font-size:22px;line-height:26px;...">qua., 18 de fev. de 2026</p>
            padrao_datas = (
                r'<p[^>]*font-size:22px;line-height:26px;'
                r'color:#222222;font-family:Cereal[^>]*>(.*?)</p>'
            )
            datas = re.findall(padrao_datas, html, flags=re.IGNORECASE | re.DOTALL)
            if datas:
                # Primeiro p = check-in
                checkin_str = self._limpar_html(datas[0])
                reserva["checkin"] = self._parse_data_pt_br(checkin_str)

                # Segundo p (se existir) = check-out
                if len(datas) > 1:
                    checkout_str = self._limpar_html(datas[1])
                    reserva["checkout"] = self._parse_data_pt_br(checkout_str)

            # -------- 4) Código da reserva --------
            # <p style="font-size:18px;line-height:28px;...font-weight:400;margin:0!important">HMB39THXQK</p>
            match_codigo_tag = re.search(
                r'<p[^>]*font-size:18px;line-height:28px;font-family:Cereal[^>]*'
                r'font-weight:400[^>]*margin:0!important[^>]*>(.*?)</p>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_codigo_tag:
                texto_codigo = self._limpar_html(match_codigo_tag.group(1))
                # Procura algo tipo HMB39THXQK
                m_cod = re.search(r'\b[A-Z0-9]{6,14}\b', texto_codigo)
                if m_cod:
                    reserva["codigo_reserva"] = m_cod.group(0).strip()

            # Fallback extra para código se ainda estiver vazio
            if not reserva["codigo_reserva"]:
                texto_limpo = self._limpar_html(html)
                possiveis_codigos = re.findall(r'\b[A-Z0-9]{8,14}\b', texto_limpo)
                if possiveis_codigos:
                    reserva["codigo_reserva"] = possiveis_codigos[0]

            # -------- 5) Nome do hóspede --------
            # <p ...font-weight:700!important">Letícia</p>
            match_hospede = re.search(
                r'<p[^>]*font-weight:700!important[^>]*>(.*?)</p>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_hospede:
                reserva["hospede"] = self._limpar_html(match_hospede.group(1))

            # -------- 6) Quantidade de hóspedes (adultos + crianças + bebês) --------
            # <p ...font-weight:400!important">2 adultos</p>
            blocos_hosp = re.findall(
                r'<p[^>]*font-weight:400!important[^>]*>(.*?)</p>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            for bloco in blocos_hosp:
                texto = self._limpar_html(bloco).lower()
                if any(p in texto for p in ["adult", "crian", "beb"]):
                    numeros = [int(n) for n in re.findall(r'(\d+)', texto)]
                    if numeros:
                        reserva["quantidade_hospedes"] = sum(numeros)
                        break

            # -------- 7) Valor total --------
            # <h3 ...text-align:right!important">R$1.717,53</h3>
            match_valor_tag = re.search(
                r'<h3[^>]*text-align:right!important[^>]*>(.*?)</h3>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_valor_tag:
                valor_txt = self._limpar_html(match_valor_tag.group(1))
                # Ex: "R$1.717,53" ou "R$ 1.717,53"
                valor_sem_simbolo = valor_txt.replace('R$', '').strip()
                valor_sem_simbolo = valor_sem_simbolo.replace('.', '').replace(',', '.')
                try:
                    reserva["valor_total"] = float(valor_sem_simbolo)
                except Exception as e:
                    logger.error(f"Erro ao converter valor_total '{valor_txt}': {e}")

            logger.info(f"📦 Reserva Airbnb parseada: {reserva}")

        except Exception as e:
            logger.error(f"Erro ao parsear e-mail de reserva Airbnb: {e}")
        
        return reserva

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
        Coleção: reservas_airbnb
        Documento: codigo_reserva ou id_email (fallback).
        """
        try:
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
