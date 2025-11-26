import logging
import os
import pickle
import re
from urllib.parse import unquote
from functools import lru_cache

logging.basicConfig(level=logging.INFO, format='[PYTHON BRAIN] %(message)s')
logger = logging.getLogger("WAF_Brain")

class WafEngine:
    def __init__(self):
        logger.info("Initializing Custom Engine...")
        self.model = None
        self.vectorizer = None
        
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(current_dir, "custom_model")
            
            vec_path = os.path.join(model_dir, "vectorizer.pkl")
            mod_path = os.path.join(model_dir, "model.pkl")

            if not os.path.exists(mod_path) or not os.path.exists(vec_path):
                logger.error("Model files not found!")
                return

            with open(vec_path, "rb") as f:
                self.vectorizer = pickle.load(f)
            with open(mod_path, "rb") as f:
                self.model = pickle.load(f)
            
            logger.info("Custom Beast Model Loaded!")
            
        except Exception as e:
            logger.error("Failed to load Model: %s", e)

    @lru_cache(maxsize=5000)
    def _analyze_payload_cached(self, payload: str) -> float:
        if not self.model or not self.vectorizer:
            return 0.0
            
        try:
            features = self.vectorizer.transform([payload])
            probs = self.model.predict_proba(features)[0]
            attack_probability = float(probs[1])

            if attack_probability > 0.20:
                 print(f"\nAnalysis: {payload[:40]}... -> RISK: {attack_probability:.4f}")
            
            return attack_probability
        except Exception:
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
                logger.warning("FRAUD DETECTED")
                return 1.0 

            score = self._analyze_payload_cached(payload)
            
            if score > 0.75:
                logger.warning(f"BEAST BLOCKED: Confidence {score:.2f}")
                return score
            
            return 0.0

        except Exception as e:
            logger.error("Error: %s", e)
            return 0.0