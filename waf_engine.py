"""
waf_engine.py
--------------
Implements Section 6.4 of the report: the WAF engine that intercepts a
request, extracts its features, runs it through the two-layer model,
and returns a decision (allow / block / flag).

feature extraction here mirrors the preprocessing pipeline used at
training time in data/generate_dataset.py + ml/train_model.py, so the
same transformation is applied live, matching Section 6.3.3.
"""
import os
import re
import time
from collections import defaultdict, deque

import joblib

BASE = os.path.dirname(os.path.abspath(__file__))
LAYER1_PATH = os.path.join(BASE, "ml", "layer1_pipeline.joblib")
LAYER2_PATH = os.path.join(BASE, "ml", "layer2_pipeline.joblib")

SQL_PATTERN = re.compile(r"(select|union|drop|insert|--|or 1=1|sleep\(|information_schema)", re.I)
SCRIPT_PATTERN = re.compile(r"(<script>|onerror=|javascript:|<img\s+src=|document\.cookie)", re.I)

# simple in-memory sliding windows used to derive "requests_per_10s" and
# "failed_logins_per_min" for a given source IP, since a single HTTP
# request on its own doesn't carry that flow-level information.
_REQUEST_LOG = defaultdict(lambda: deque(maxlen=500))
_FAILED_LOGIN_LOG = defaultdict(lambda: deque(maxlen=500))


class WAFEngine:
    """Loads the trained pipelines once and reuses them for every request,
    per Section 6.3.3 ("the Flask application loads the trained models
    once at startup instead of retraining them on every request")."""

    def __init__(self):
        if not (os.path.exists(LAYER1_PATH) and os.path.exists(LAYER2_PATH)):
            raise FileNotFoundError(
                "Trained models not found. Run: python ml/train_model.py"
            )
        self.layer1 = joblib.load(LAYER1_PATH)
        self.layer2 = joblib.load(LAYER2_PATH)

    # ---- feature extraction (mirrors data/generate_dataset.py schema) ----
    @staticmethod
    def _track_rate(ip, log_failed=False):
        now = time.time()
        window = _REQUEST_LOG[ip]
        window.append(now)
        while window and now - window[0] > 10:
            window.popleft()
        requests_per_10s = len(window)

        if log_failed:
            flog = _FAILED_LOGIN_LOG[ip]
            flog.append(now)
        flog = _FAILED_LOGIN_LOG[ip]
        while flog and now - flog[0] > 60:
            flog.popleft()
        failed_logins_per_min = len(flog)

        return requests_per_10s, failed_logins_per_min

    @staticmethod
    def _user_agent_entropy(ua: str) -> float:
        if not ua:
            return 0.5
        from collections import Counter
        import math
        counts = Counter(ua)
        total = len(ua)
        return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 2)

    def extract_features(self, request: dict) -> dict:
        url = request.get("url", "/")
        method = request.get("method", "GET").upper()
        ip = request.get("source_ip", "0.0.0.0")
        ua = request.get("user_agent", "Mozilla/5.0")
        is_login_attempt = request.get("is_failed_login", False)

        requests_per_10s, failed_logins_per_min = self._track_rate(ip, log_failed=is_login_attempt)

        return {
            "method": method,
            "url_length": len(url),
            "num_special_chars": sum(c in "<>;'\"=(){}" for c in url),
            "num_params": url.count("=") if "?" in url else 0,
            "has_sql_keyword": int(bool(SQL_PATTERN.search(url))),
            "has_script_tag": int(bool(SCRIPT_PATTERN.search(url))),
            "requests_per_10s": requests_per_10s,
            "failed_logins_per_min": failed_logins_per_min,
            "user_agent_entropy": self._user_agent_entropy(ua),
            "avg_packet_size": request.get("packet_size", 500),
            "flow_duration_ms": request.get("flow_duration_ms", 100),
        }

    def inspect(self, request: dict) -> dict:
        """Runs the full WAF decision pipeline for one request.
        Returns dict with layer1_result, layer2_result, status, severity, message.
        """
        features = self.extract_features(request)
        feature_row = [features]  # DataFrame-like single row for the pipeline
        import pandas as pd
        X = pd.DataFrame(feature_row)

        is_malicious = bool(self.layer1.predict(X)[0])
        layer1_conf = float(max(self.layer1.predict_proba(X)[0]))

        result = {
            "layer1_result": "Malicious" if is_malicious else "Normal",
            "layer1_confidence": round(layer1_conf, 3),
            "layer2_result": None,
            "layer2_confidence": None,
            "status": "allowed",
            "severity": None,
            "message": "Request classified as normal traffic.",
        }

        if is_malicious:
            attack_type = self.layer2.predict(X)[0]
            layer2_conf = float(max(self.layer2.predict_proba(X)[0]))
            severity = self._severity_for(attack_type, features)
            result.update({
                "layer2_result": attack_type,
                "layer2_confidence": round(layer2_conf, 3),
                "status": "blocked" if severity in ("high", "critical") else "flagged",
                "severity": severity,
                "message": f"{attack_type} detected with {round(layer2_conf * 100, 1)}% confidence.",
            })

        return result

    @staticmethod
    def _severity_for(attack_type, features):
        if attack_type in ("SQLi", "DDoS"):
            return "critical"
        if attack_type in ("BruteForce", "XSS"):
            return "high"
        return "medium"  # Bot


_engine_singleton = None


def get_engine():
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = WAFEngine()
    return _engine_singleton
