"""
generate_dataset.py
--------------------
Builds a labeled dataset of HTTP-request-style records that mimics the
features used in the CSIC 2010 (HTTP-level attacks: SQLi, XSS) and
CICIDS2017 (flow-level attacks: DDoS, Brute Force, Bot) datasets
referenced in Chapter 6 of the report.

No internet access is available in this environment, so the real
CSIC2010 / CICIDS2017 CSVs cannot be downloaded. This script generates
a synthetic dataset that follows the same feature schema described in
Section 6.2 of the report (URL length, special-char count, param count,
suspicious keywords, flow stats, etc.), with realistic noise, so the
rest of the pipeline (preprocessing -> Layer 1 -> Layer 2) is a genuine,
working implementation you can later re-point at the real datasets by
dropping them into data/raw/ and adjusting the loader.

Run:
    python data/generate_dataset.py
Produces:
    data/traffic_dataset.csv
"""
import random
import string
import numpy as np
import pandas as pd

random.seed(42)
np.random.seed(42)

N_PER_CLASS = 1500
LABELS = ["Normal", "SQLi", "XSS", "DDoS", "BruteForce", "Bot"]
METHODS = ["GET", "POST", "PUT", "DELETE"]

SQL_KEYWORDS = ["select", "union", "drop", "insert", "--", "or 1=1", "sleep(", "information_schema"]
SCRIPT_TOKENS = ["<script>", "onerror=", "javascript:", "<img src=x", "document.cookie"]
NORMAL_PATHS = ["/home", "/products", "/cart", "/checkout", "/profile", "/search", "/api/items"]


def rand_str(n):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def make_normal():
    path = random.choice(NORMAL_PATHS)
    n_params = random.randint(0, 4)
    query = "&".join(f"{rand_str(4)}={rand_str(random.randint(2, 8))}" for _ in range(n_params))
    url = f"{path}?{query}" if query else path
    return {
        "method": random.choice(["GET", "POST"]),
        "url": url,
        "url_length": len(url),
        "num_special_chars": sum(c in "<>;'\"=(){}" for c in url),
        "num_params": n_params,
        "has_sql_keyword": 0,
        "has_script_tag": 0,
        "requests_per_10s": np.random.poisson(2),
        "failed_logins_per_min": 0,
        "user_agent_entropy": round(np.random.normal(3.2, 0.3), 2),
        "avg_packet_size": round(np.random.normal(500, 80), 1),
        "flow_duration_ms": round(np.random.normal(120, 40), 1),
        "label": "Normal",
    }


def make_sqli():
    payload = f"{rand_str(3)}=" + " ".join(random.sample(SQL_KEYWORDS, k=random.randint(1, 3)))
    url = f"/search?q={payload}"
    return {
        "method": random.choice(["GET", "POST"]),
        "url": url,
        "url_length": len(url),
        "num_special_chars": sum(c in "<>;'\"=(){}" for c in url) + random.randint(1, 5),
        "num_params": random.randint(1, 3),
        "has_sql_keyword": 1,
        "has_script_tag": 0,
        "requests_per_10s": np.random.poisson(3),
        "failed_logins_per_min": 0,
        "user_agent_entropy": round(np.random.normal(3.0, 0.4), 2),
        "avg_packet_size": round(np.random.normal(520, 90), 1),
        "flow_duration_ms": round(np.random.normal(130, 40), 1),
        "label": "SQLi",
    }


def make_xss():
    payload = "".join(random.sample(SCRIPT_TOKENS, k=random.randint(1, 2)))
    url = f"/comment?msg={payload}{rand_str(5)}"
    return {
        "method": random.choice(["GET", "POST"]),
        "url": url,
        "url_length": len(url),
        "num_special_chars": sum(c in "<>;'\"=(){}" for c in url) + random.randint(2, 6),
        "num_params": 1,
        "has_sql_keyword": 0,
        "has_script_tag": 1,
        "requests_per_10s": np.random.poisson(3),
        "failed_logins_per_min": 0,
        "user_agent_entropy": round(np.random.normal(3.1, 0.4), 2),
        "avg_packet_size": round(np.random.normal(480, 70), 1),
        "flow_duration_ms": round(np.random.normal(110, 30), 1),
        "label": "XSS",
    }


def make_ddos():
    return {
        "method": "GET",
        "url": "/",
        "url_length": 1,
        "num_special_chars": 0,
        "num_params": 0,
        "has_sql_keyword": 0,
        "has_script_tag": 0,
        "requests_per_10s": np.random.poisson(180) + 50,
        "failed_logins_per_min": 0,
        "user_agent_entropy": round(np.random.normal(1.0, 0.2), 2),
        "avg_packet_size": round(np.random.normal(80, 20), 1),
        "flow_duration_ms": round(np.random.normal(5, 2), 1),
        "label": "DDoS",
    }


def make_bruteforce():
    return {
        "method": "POST",
        "url": "/login",
        "url_length": 6,
        "num_special_chars": 0,
        "num_params": 2,
        "has_sql_keyword": 0,
        "has_script_tag": 0,
        "requests_per_10s": np.random.poisson(15) + 5,
        "failed_logins_per_min": np.random.poisson(20) + 5,
        "user_agent_entropy": round(np.random.normal(2.0, 0.3), 2),
        "avg_packet_size": round(np.random.normal(300, 40), 1),
        "flow_duration_ms": round(np.random.normal(60, 15), 1),
        "label": "BruteForce",
    }


def make_bot():
    return {
        "method": random.choice(["GET", "POST"]),
        "url": random.choice(NORMAL_PATHS),
        "url_length": random.randint(5, 15),
        "num_special_chars": 0,
        "num_params": 0,
        "has_sql_keyword": 0,
        "has_script_tag": 0,
        "requests_per_10s": np.random.poisson(25) + 5,
        "failed_logins_per_min": 0,
        "user_agent_entropy": round(np.random.normal(0.5, 0.15), 2),
        "avg_packet_size": round(np.random.normal(200, 30), 1),
        "flow_duration_ms": round(np.random.normal(20, 5), 1),
        "label": "Bot",
    }


GENERATORS = {
    "Normal": make_normal,
    "SQLi": make_sqli,
    "XSS": make_xss,
    "DDoS": make_ddos,
    "BruteForce": make_bruteforce,
    "Bot": make_bot,
}


def build_dataset():
    rows = []
    for label, gen in GENERATORS.items():
        for _ in range(N_PER_CLASS):
            rows.append(gen())
    df = pd.DataFrame(rows)
    # binary target used by Layer 1
    df["is_malicious"] = (df["label"] != "Normal").astype(int)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_dataset()
    out_path = __file__.replace("generate_dataset.py", "traffic_dataset.csv")
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows to {out_path}")
    print(df["label"].value_counts())
