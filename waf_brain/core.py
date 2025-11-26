import logging
import os
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
        
        
        torch.set_num_threads(1) 
        
        self.model = None
        self.tokenizer = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "ai_model")

            if not os.path.exists(model_path):
                logger.error(f"Model directory not found at: {model_path}")
                return

            logger.info(f"Loading BERT-v3 from {model_path} on {self.device}...")
            
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
            
            self.model.to(self.device)
            self.model.eval()
            
            
            self._analyze_payload_cached("warmup payload")
            logger.info("Deep Learning Model Ready!")
            
        except Exception as e:
            logger.error(f"Failed to load AI Model: {e}")

    @lru_cache(maxsize=10000)
    def _analyze_payload_cached(self, payload: str) -> float:
        if not self.model or not self.tokenizer:
            return 0.0
            
        try:
            
            inputs = self.tokenizer(
                payload, 
                return_tensors="pt", 
                truncation=True, 
                max_length=128, 
                padding=True
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
            
            probs = F.softmax(outputs.logits, dim=-1)
            
            
            attack_probability = float(probs[0][1].item())
            return attack_probability

        except Exception as e:
            logger.error(f"Inference Error: {e}")
            return 0.0

    def inspect_request(self, method: str, uri: str, headers_json: str, body: str) -> float:
        
        try:
           
            
            decoded_uri = unquote(uri)
            payload = f"{method} {decoded_uri} {headers_json} {body}".lower()
            
            
            score = self._analyze_payload_cached(payload)
            
            return score

        except Exception as e:
            logger.error(f"Inspection Error: {e}")
            return 0.0
