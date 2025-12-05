#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Robô de Sincronização de Reservas entre Gmail, Airbnb e Firebase.

Funcionalidades principais:
- Lê e-mails no Gmail relacionados a reservas do Airbnb (encaminhados por tiagoddantas@me.com)
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
from datetime import datetime

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
            'from:(tiagoddantas@me.com) subject:("Enc: Reserva confirmada -")'
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
    def _decode_part_body(self, part: Dict) -> str:
        body = part.get("body", {})
        data = body.get("data")
        if not data:
            return ""
        try:
            decoded_bytes = base64.urlsafe_b64decode(data)
            return decoded_bytes.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Erro ao decodificar parte do e-mail: {e}")
            return ""

    def _buscar_html_ou_texto(self, payload: Dict) -> str:
        """Procura recursivamente text/html; se não achar, usa text/plain."""
        mime_type = payload.get("mimeType", "")

        if mime_type.startswith("text/html"):
            return self._decode_part_body(payload)

        if "parts" in payload:
            text_fallback = ""
            for part in payload["parts"]:
                mt = part.get("mimeType", "")
                if mt.startswith("text/html"):
                    html = self._decode_part_body(part)
                    if html:
                        return html
                elif mt.startswith("text/plain") and not text_fallback:
                    text_fallback = self._decode_part_body(part)

                if "parts" in part:
                    sub = self._buscar_html_ou_texto(part)
                    if sub and ("<html" in sub.lower() or "<body" in sub.lower()):
                        return sub
                    if sub and not text_fallback:
                        text_fallback = sub

            if text_fallback:
                return text_fallback

        if mime_type.startswith("text/plain"):
            return self._decode_part_body(payload)

        return ""

    def extrair_corpo_email(self, message_payload: Dict) -> str:
        try:
            corpo = self._buscar_html_ou_texto(message_payload)
            return corpo or ""
        except Exception as e:
            logger.error(f"Erro ao extrair corpo de e-mail: {e}")
            return ""

    def extrair_header(self, headers: List[Dict], name: str) -> Optional[str]:
        for h in headers:
            if h.get('name', '').lower() == name.lower():
                return h.get('value', '')
        return None

    def _limpar_html(self, texto: str) -> str:
        if not texto:
            return ""
        sem_tags = re.sub(r'<[^>]+>', ' ', texto)
        sem_tags = re.sub(r'\s+', ' ', sem_tags)
        return sem_tags.strip()

    # ---------------------------------------------------------
    # Helpers específicos
    # ---------------------------------------------------------
    def _extrair_hospede_do_assunto(self, assunto: str) -> Optional[str]:
        """
        Entre: 'Enc: Reserva confirmada - ' e ' chega'
        Ex: Enc: Reserva confirmada - Letícia chega em 18 de fev. de 2026
        """
        if not assunto:
            return None
        m = re.search(
            r'Enc:\s*Reserva\s+confirmada\s*-\s*(.*?)\s+chega',
            assunto,
            flags=re.IGNORECASE
        )
        if m:
            return m.group(1).strip()
        return None

    def _extrair_nomeap_envie_mensagem(self, email_body: str, hospede: str) -> Optional[str]:
        """
        Fallback: 'Envie uma Mensagem para {HOSPEDE} {NOME_AP}'
        """
        if not email_body or not hospede:
            return None
        texto_limpo = self._limpar_html(email_body)
        pattern = rf'Envie uma Mensagem para\s+{re.escape(hospede)}\s+([^\n]+)'
        m = re.search(pattern, texto_limpo, flags=re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return None

    def _parse_data_pt_br(self, data_str: str) -> str:
        meses = {
            "jan": 1, "jan.": 1, "janeiro": 1,
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
            s = re.sub(r'^[a-zç\.]{3,},?\s*', '', s)

            m = re.search(r'(\d{1,2})\s+de\s+([a-zç\.]+)\s+de\s+(\d{4})', s)
            if m:
                dia = int(m.group(1))
                mes_token = m.group(2).strip()
                ano = int(m.group(3))
                mes = meses.get(mes_token, meses.get(mes_token.rstrip('.'), 1))
                dt = datetime(ano, mes, dia)
                return dt.strftime("%Y-%m-%d")

            s2 = s.replace(" de ", " ")
            partes = s2.split()
            if len(partes) == 3:
                dia = int(partes[0])
                mes_nome = partes[1].strip()
                ano = int(partes[2])
                mes = meses.get(mes_nome, meses.get(mes_nome.rstrip('.'), 1))
                dt = datetime(ano, mes, dia)
                return dt.strftime("%Y-%m-%d")

        except Exception as e:
            logger.error(f"Erro ao converter data '{data_str}': {e}")
        return data_str

    # ---------------------------------------------------------
    # Parsing do e-mail
    # ---------------------------------------------------------
    def parse_reserva_airbnb(self, email_body: str) -> Dict:
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
            html = email_body or ""
            texto_limpo = self._limpar_html(html)

            # nomeApAirbnb: PRIMEIRO <h2>
            match_h2 = re.search(
                r'<h2[^>]*>(.*?)</h2>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_h2:
                reserva["nomeApAirbnb"] = self._limpar_html(match_h2.group(1))

            # Datas
            padrao_datas_html = (
                r'<p[^>]*font-size:22px;line-height:26px;[^>]*>'
                r'(.*?)</p>'
            )
            datas_html = re.findall(
                padrao_datas_html,
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if datas_html:
                reserva["checkin"] = self._parse_data_pt_br(self._limpar_html(datas_html[0]))
                if len(datas_html) > 1:
                    reserva["checkout"] = self._parse_data_pt_br(self._limpar_html(datas_html[1]))

            if not reserva["checkin"] or not reserva["checkout"]:
                datas_txt = re.findall(
                    r'(?:seg|ter|qua|qui|sex|sáb|sab|dom)\.?,?\s*\d{1,2}\s+de\s+[a-zç\.]+\s+de\s+\d{4}',
                    texto_limpo,
                    flags=re.IGNORECASE
                )
                if len(datas_txt) >= 1 and not reserva["checkin"]:
                    reserva["checkin"] = self._parse_data_pt_br(datas_txt[0])
                if len(datas_txt) >= 2 and not reserva["checkout"]:
                    reserva["checkout"] = self._parse_data_pt_br(datas_txt[1])

            # Código da reserva
            match_codigo_tag = re.search(
                r'<p[^>]*font-size:18px;line-height:28px;font-family[Cereal\s\:;#0-9a-zA-Z\-,"\.]*'
                r'font-weight:400[^>]*margin:0!important[^>]*>(.*?)</p>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            if match_codigo_tag:
                texto_codigo = self._limpar_html(match_codigo_tag.group(1))
                m_cod = re.search(r'\b[A-Z0-9]{6,14}\b', texto_codigo)
                if m_cod:
                    reserva["codigo_reserva"] = m_cod.group(0).strip()

            if not reserva["codigo_reserva"]:
                possiveis_codigos = re.findall(r'\b[A-Z0-9]{8,14}\b', texto_limpo)
                if possiveis_codigos:
                    reserva["codigo_reserva"] = possiveis_codigos[0]

            # quantidade_hospedes
            blocos_hosp = re.findall(
                r'<p[^>]*font-weight:400!important[^>]*>(.*?)</p>',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            for bloco in blocos_hosp:
                texto = self._limpar_html(bloco).lower()
                if any(p in texto for p in ["adult", "crian", "beb"]):
                    for m in re.finditer(
                        r'(\d+)\s+(adulto|adultos|criança|crianças|bebê|bebês)',
                        texto,
                        flags=re.IGNORECASE
                    ):
                        reserva["quantidade_hospedes"] += int(m.group(1))
                    if reserva["quantidade_hospedes"] > 0:
                        break

            if reserva["quantidade_hospedes"] == 0:
                for m in re.finditer(
                    r'(\d+)\s+(adulto|adultos|criança|crianças|bebê|bebês)',
                    texto_limpo,
                    flags=re.IGNORECASE
                ):
                    reserva["quantidade_hospedes"] += int(m.group(1))

            # valor_total (fallback geral)
            m_val_txt = re.search(r'R\$\s*([\d\.\,]+)', texto_limpo)
            if m_val_txt:
                v = m_val_txt.group(1).strip()
                v = v.replace('.', '').replace(',', '.')
                try:
                    reserva["valor_total"] = float(v)
                except Exception as e:
                    logger.error(f"Erro ao converter valor_total fallback '{v}': {e}")

            logger.info(f"📦 Reserva Airbnb parseada (parcial): {reserva}")

        except Exception as e:
            logger.error(f"Erro ao parsear e-mail de reserva Airbnb: {e}")
        
        return reserva

    # ---------------------------------------------------------
    # Gmail + Firestore
    # ---------------------------------------------------------
    def buscar_emails_reservas(self, max_results: int = 10) -> List[Dict]:
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

                # hóspede a partir do assunto
                hospede_assunto = self._extrair_hospede_do_assunto(assunto)
                if hospede_assunto:
                    reserva["hospede"] = hospede_assunto

                # nomeApAirbnb via "Envie uma Mensagem..." APENAS se não veio pelo <h2>
                if reserva.get("hospede") and not reserva.get("nomeApAirbnb"):
                    nome_apt = self._extrair_nomeap_envie_mensagem(corpo, reserva["hospede"])
                    if nome_apt:
                        reserva["nomeApAirbnb"] = nome_apt

                # valor_total via "você recebe R$..."
                texto_limpo = self._limpar_html(corpo or "")
                m_val_voce = re.search(
                    r'voc[êe]\s+recebe[^R$]*R\$\s*([\d\.\,]+)',
                    texto_limpo,
                    flags=re.IGNORECASE
                )
                if m_val_voce:
                    v = m_val_voce.group(1).strip()
                    v = v.replace('.', '').replace(',', '.')
                    try:
                        reserva["valor_total"] = float(v)
                    except Exception as e:
                        logger.error(f"Erro ao converter valor_total (você recebe) '{v}': {e}")

                reserva["assunto_email"] = assunto
                reserva["data_envio_email"] = data_envio
                reserva["id_email"] = msg_id
                
                self.salvar_reserva_no_firestore(reserva)
            
            except HttpError as error:
                logger.error(f"Erro HTTP ao processar e-mail {msg_id}: {error}")
            except Exception as e:
                logger.error(f"Erro inesperado ao processar e-mail {msg_id}: {e}")

    def salvar_reserva_no_firestore(self, reserva: Dict):
        """
        Salva ou atualiza uma reserva no Firestore.
        Se o nomeApAirbnb for 'Eco Resort Praia dos Carneiros - Flat Colina',
        grava também o apartamentoId correspondente.
        """
        try:
            colecao = "reservas_airbnb"
            doc_id = reserva.get("codigo_reserva") or reserva.get("id_email")
            
            if not doc_id:
                logger.warning(f"⚠️ Reserva sem identificador único, não será salva: {reserva}")
                return

            # 🔒 Regra pedida: vincular apartamentoId pelo nome do anúncio
            if reserva.get("nomeApAirbnb") == "Eco Resort Praia dos Carneiros - Flat Colina":
                reserva["apartamentoId"] = "cHqxxuHbV8dyusWgXYHG"
            
            doc_ref = self.db.collection(colecao).document(doc_id)
            reserva["sincronizado_em"] = datetime.utcnow().isoformat()
            doc_ref.set(reserva, merge=True)
            logger.info(f"💾 Reserva salva/atualizada no Firestore: {colecao}/{doc_id}")
        
        except Exception as e:
            logger.error(f"Erro ao salvar reserva no Firestore: {e}")

    # ---------------------------------------------------------
    # Loop principal
    # ---------------------------------------------------------
    def executar_uma_vez(self):
        logger.info("🚀 Executando sincronização única de reservas (Airbnb ↔ Gmail ↔ Firebase)")
        self.processar_emails()

    def executar_continuamente(self):
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
