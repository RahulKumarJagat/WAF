import logging
import os
import re
import torch
import torch.nn.functional as F
from urllib.parse import unquote
from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForSequenceClassification


logging.basicConfig(level=logging.INFO, format='[PYTHON BRAIN] %(message)s')
logger = logging.getLogger("WAF_Brain")

class WafEngine:
    def __init__(self):
        logger.info("Initializing AI Engine...")
        self.model = None
        self.tokenizer = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        try:
            
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "ai_model")

            if not os.path.exists(model_path):
                logger.error(f"Model directory not found at: {model_path}")
                return

            
            logger.info(f"Loading model from {model_path} on {self.device}...")
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
            
            
            self.model.to(self.device)
            self.model.eval()
            
            logger.info("Deep Learning Model Loaded Successfully!")
            
        except Exception as e:
            logger.error(f"Failed to load AI Model: {e}")

    @lru_cache(maxsize=5000)
    def _analyze_payload_cached(self, payload: str) -> float:
        
        if not self.model or not self.tokenizer:
            return 0.0
            
        try:
           
            inputs = self.tokenizer(
                payload, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512,
                padding=True
            ).to(self.device)

            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            
            probs = F.softmax(outputs.logits, dim=-1)
            
            attack_probability = float(probs[0][1].item())

            if attack_probability > 0.20:
                 
                 clean_print = payload[:40].replace('\n', ' ')
                 print(f"\nAnalysis: {clean_print}... -> RISK: {attack_probability:.4f}")
            
            return attack_probability

        except Exception as e:
            logger.error(f"Inference Error: {e}")
            return 0.0

    def inspect_request(self, method: str, uri: str, headers_json: str, body: str) -> float:
        try:
            
            payload = unquote(f"{uri} {body}").lower()
            
            
            if re.search(r'\.(jpg|jpeg|png|gif|css|js|ico|woff|ttf|svg)$', uri):
                return 0.0

            
            if len(payload) < 8:
                return 0.0

            
            if re.match(r'^[a-zA-Z0-9\s\-_./?=&]+$', payload):
                return 0.0

            
            if re.search(r'(price|cost|amount)\D{0,10}[=:]\s*(-?0(\.0+)?|-\d+)', payload):
                logger.warning("LOGIC ATTACK (FRAUD) DETECTED")
                return 1.0 

            
            score = self._analyze_payload_cached(payload)
            
            
            if score > 0.75:
                logger.warning(f"BLOCKING: Malicious Confidence {score:.2f}")
                return score
            
            return 0.0

        except Exception as e:
            logger.error(f"Inspection Error: {e}")
            return 0.0
