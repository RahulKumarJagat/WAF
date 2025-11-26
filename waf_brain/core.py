import logging
import os
import torch
import torch.nn.functional as F
from urllib.parse import unquote
from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Configure Logging
logging.basicConfig(level=logging.INFO, format='[PYTHON BRAIN] %(message)s')
logger = logging.getLogger("WAF_Brain")

class WafEngine:
    def __init__(self):
        logger.info("Initializing AI Engine...")
        
        # CRITICAL for embedding in Rust: 
        # Prevent Torch from hogging all CPU cores, leaving none for Pingora
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
            
            # Load model
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
            
            self.model.to(self.device)
            self.model.eval()
            
            # Warmup (run one fake inference to allocate memory)
            self._analyze_payload_cached("warmup payload")
            logger.info("Deep Learning Model Ready!")
            
        except Exception as e:
            logger.error(f"Failed to load AI Model: {e}")

    @lru_cache(maxsize=10000)
    def _analyze_payload_cached(self, payload: str) -> float:
        if not self.model or not self.tokenizer:
            return 0.0
            
        try:
            # Truncate to 128 tokens for SPEED (WAFs need to be fast, 512 is too slow)
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
            
            # Assuming Class 1 is "Malicious"
            attack_probability = float(probs[0][1].item())
            return attack_probability

        except Exception as e:
            logger.error(f"Inference Error: {e}")
            return 0.0

    def inspect_request(self, method: str, uri: str, headers_json: str, body: str) -> float:
        """
        Called from Rust. 
        """
        try:
            # Combine relevant parts. 
            # Note: Rust has already filtered static assets and regex SQLi.
            # We are looking for semantic attacks (Obfuscated XSS, Logic attacks, sophisticated SQLi)
            
            decoded_uri = unquote(uri)
            payload = f"{method} {decoded_uri} {headers_json} {body}".lower()
            
            # Run Inference
            score = self._analyze_payload_cached(payload)
            
            return score

        except Exception as e:
            logger.error(f"Inspection Error: {e}")
            return 0.0