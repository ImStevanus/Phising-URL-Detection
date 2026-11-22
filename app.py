import os
import sys
import time
import json
import re
import math
import io
from collections import Counter
from urllib.parse import urlparse

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go

# ==============================================================================
# 1. KONFIGURASI HALAMAN & TEMA STREAMLIT
# ==============================================================================
st.set_page_config(
    page_title="Phishing Shield - Intelligent Web Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS Universal: Mendukung Light Mode & Dark Mode dengan Animasi Mulus
st.markdown("""
<style>
    /* Animasi Keyframes */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseDanger {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    @keyframes pulseSafe {
        0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }

    /* Hero Banner Welcoming Page */
    .hero-banner {
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(168, 85, 247, 0.15) 100%);
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 18px;
        padding: 40px;
        margin-bottom: 24px;
        text-align: center;
        animation: fadeIn 0.6s ease-out;
    }
    .hero-banner h1 {
        font-size: 2.6rem !important;
        font-weight: 800;
        margin-bottom: 12px;
        background: linear-gradient(90deg, #6366F1, #A855F7, #EC4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero-banner p {
        font-size: 1.15rem;
        max-width: 850px;
        margin: 0 auto 24px auto;
        opacity: 0.9;
        line-height: 1.6;
    }

    /* KPI Highlight Card */
    .kpi-card {
        background-color: rgba(128, 128, 128, 0.07);
        border: 1px solid rgba(128, 128, 128, 0.2);
        border-radius: 14px;
        padding: 22px 16px;
        text-align: center;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .kpi-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
    }
    .kpi-card h2 {
        font-size: 2.3rem !important;
        margin: 0;
        font-weight: 800;
    }
    .kpi-card p {
        margin: 6px 0 0 0;
        font-size: 0.95rem;
        opacity: 0.85;
    }

    /* Status Card - Danger (Phishing) */
    .status-card-danger {
        background-color: rgba(239, 68, 68, 0.12);
        border: 2px solid #EF4444;
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 20px;
        animation: fadeIn 0.4s ease-out, pulseDanger 2s infinite;
    }
    .status-card-danger h3 {
        color: #EF4444 !important;
        margin: 0;
        font-weight: 800;
    }

    /* Status Card - Warning (Waspada) */
    .status-card-warning {
        background-color: rgba(245, 158, 11, 0.12);
        border: 2px solid #F59E0B;
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 20px;
        animation: fadeIn 0.4s ease-out;
    }
    .status-card-warning h3 {
        color: #F59E0B !important;
        margin: 0;
        font-weight: 800;
    }

    /* Status Card - Safe (Legitimate) */
    .status-card-safe {
        background-color: rgba(34, 197, 94, 0.12);
        border: 2px solid #22C55E;
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 20px;
        animation: fadeIn 0.4s ease-out, pulseSafe 2s infinite;
    }
    .status-card-safe h3 {
        color: #22C55E !important;
        margin: 0;
        font-weight: 800;
    }

    /* Status Card - Hybrid Override (Whitelist Protected) */
    .status-card-hybrid {
        background-color: rgba(59, 130, 246, 0.12);
        border: 2px solid #3B82F6;
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 20px;
        animation: fadeIn 0.4s ease-out;
    }
    .status-card-hybrid h3 {
        color: #3B82F6 !important;
        margin: 0;
        font-weight: 800;
    }

    /* Box Container Metrik */
    .metric-box {
        background-color: rgba(128, 128, 128, 0.08);
        border-radius: 12px;
        padding: 16px 20px;
        border-left: 5px solid #6366F1;
        margin-bottom: 14px;
        animation: fadeIn 0.4s ease-out;
    }

    /* Pill Badges */
    .pill-badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-right: 6px;
        margin-bottom: 6px;
    }
    .pill-danger { background-color: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; }
    .pill-warning { background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B; }
    .pill-safe { background-color: rgba(34, 197, 94, 0.2); color: #22C55E; border: 1px solid #22C55E; }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 2. DEFINISI EKSTRAKSI 31 FITUR LEKSIKAL (IDENTIK DENGAN NOTEBOOK)
# ==============================================================================
KW = ["login", "signin", "verify", "secure", "account", "update", "bank", "paypal", "confirm",
      "password", "webscr", "ebay", "free", "bonus", "support", "wallet"]
KW_RE = re.compile("|".join(KW), re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SHORT_RE = re.compile(r"(^|\.)(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|cutt\.ly|rb\.gy)$")
EXT_RE = re.compile(r"\.(php|exe|zip|js|asp|aspx|jsp|cgi)$", re.I)

FITUR = [
    "url_len", "host_len", "path_len", "query_len", "host_dots", "host_hyphens", "host_digits",
    "n_subdomain", "tld_len", "host_is_ip", "host_entropy", "url_entropy", "longest_label",
    "path_depth", "n_slash", "n_question", "n_equal", "n_and", "n_percent", "n_at",
    "n_underscore", "n_digits", "digit_ratio", "special_ratio", "n_keyword", "has_shortener",
    "has_punycode", "ext_risky", "double_slash_path", "has_https", "has_www"
]

# Baseline Netral Aman untuk Imputasi Feature Masking
NEUTRAL_BASELINE = {
    "url_len": 25.0, "host_len": 15.0, "path_len": 5.0, "query_len": 0.0,
    "host_dots": 2.0, "host_hyphens": 0.0, "host_digits": 0.0, "n_subdomain": 1.0,
    "tld_len": 3.0, "host_is_ip": 0.0, "host_entropy": 2.8, "url_entropy": 3.5,
    "longest_label": 8.0, "path_depth": 1.0, "n_slash": 2.0, "n_question": 0.0,
    "n_equal": 0.0, "n_and": 0.0, "n_percent": 0.0, "n_at": 0.0, "n_underscore": 0.0,
    "n_digits": 0.0, "digit_ratio": 0.0, "special_ratio": 0.15, "n_keyword": 0.0,
    "has_shortener": 0.0, "has_punycode": 0.0, "ext_risky": 0.0, "double_slash_path": 0.0,
    "has_https": 1.0, "has_www": 1.0
}

# Kategori Pengelompokan Fitur untuk Pengaturan Checklist
FEATURE_GROUPS = {
    "🔐 Protokol & Konvensi Domain (Shortcut Features)": ["has_https", "has_www"],
    "🌐 Struktur & Kompleksitas Hostname": ["host_len", "host_dots", "host_hyphens", "host_digits", "n_subdomain", "tld_len", "longest_label"],
    "🎲 Keacakan Informasi (Entropi Shannon)": ["host_entropy", "url_entropy"],
    "📁 Struktur Path & Kedalaman Direktori": ["url_len", "path_len", "query_len", "path_depth", "n_slash", "double_slash_path"],
    "⚠️ Delimiter, Simbol & Rasio Numerik": ["n_question", "n_equal", "n_and", "n_percent", "n_underscore", "n_digits", "digit_ratio", "special_ratio"],
    "🚨 Indikator Bahaya Tingkat Tinggi & Rekayasa Sosial": ["host_is_ip", "n_at", "n_keyword", "has_shortener", "has_punycode", "ext_risky"]
}

def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())

def host_dari(u):
    try:
        p = urlparse(u if "://" in u else "http://" + u)
        return p, (p.hostname or "")
    except ValueError:
        return urlparse("http://x"), ""

def ekstrak_satu(u):
    p, host = host_dari(u)
    path, query = p.path, p.query
    labels = host.split(".") if host else []
    is_ip = 1 if IP_RE.match(host) else 0
    n = max(len(u), 1)
    dig = sum(c.isdigit() for c in u)
    let = sum(c.isalpha() for c in u)
    return [
        len(u), len(host), len(path), len(query),
        host.count("."), host.count("-"), sum(c.isdigit() for c in host),
        0 if is_ip else max(len(labels) - 2, 0),
        0 if (is_ip or not labels) else len(labels[-1]),
        is_ip, round(entropy(host), 3), round(entropy(u), 3),
        max((len(l) for l in labels), default=0),
        path.count("/"), u.count("/"), u.count("?"), u.count("="), u.count("&"),
        u.count("%"), u.count("@"), u.count("_"),
        dig, round(dig / n, 3), round((n - dig - let) / n, 3),
        len(KW_RE.findall(u)),
        1 if SHORT_RE.search(host) else 0,
        1 if "xn--" in host else 0,
        1 if EXT_RE.search(path) else 0,
        1 if "//" in path else 0,
        1 if u.lower().startswith("https") else 0,
        1 if host.startswith("www.") else 0,
    ]

FEATURE_META = {
    "url_len": ("Panjang Total URL", "Dimensi Karakter", "URL phishing sering sengaja dipanjangkan untuk menyembunyikan subdomain berbahaya atau menyisipkan token palsu."),
    "host_len": ("Panjang Hostname", "Struktur Domain", "Panjang nama host/domain. Nama host yang panjang menandakan penumpukan subdomain tiruan."),
    "path_len": ("Panjang Path Direktori", "Struktur Path", "Panjang jalur direktori web setelah nama host."),
    "query_len": ("Panjang Query Parameter", "Parameter Dinamis", "Panjang parameter query string (?key=value) tempat payload phishing sering dititipkan."),
    "host_dots": ("Jumlah Titik pada Host", "Struktur Domain", "Banyaknya tanda titik pada domain. > 3 titik mengindikasikan subdomain bertingkat."),
    "host_hyphens": ("Tanda Hubung pada Host (-)", "Struktur Domain", "Kerap digunakan penyerang untuk teknik typosquatting (misal: paypal-security-update.com)."),
    "host_digits": ("Jumlah Angka pada Host", "Struktur Domain", "Jumlah digit numerik dalam nama host."),
    "n_subdomain": ("Tingkat Subdomain", "Struktur Domain", "Jumlah level subdomain sebelum nama domain utama."),
    "tld_len": ("Panjang Top-Level Domain", "Struktur Domain", "Panjang ekstensi TLD (misal .com = 3, .online = 6)."),
    "host_is_ip": ("Domain Berupa Alamat IP", "Indikator Bahaya Tinggi", "Penyerang menggunakan alamat IP mentah (misal: 192.168.1.1) tanpa domain resmi."),
    "host_entropy": ("Entropi Shannon Host", "Keacakan Informasi", "Mengukur keacakan susunan huruf domain. Nilai tinggi menandakan Domain Generation Algorithm (DGA)."),
    "url_entropy": ("Entropi Shannon Total URL", "Keacakan Informasi", "Mengukur keacakan seluruh string URL (token enkripsi palsu atau hash terkompresi)."),
    "longest_label": ("Label Domain Terpanjang", "Struktur Domain", "Panjang karakter dari potongan subdomain atau nama domain terpanjang."),
    "path_depth": ("Kedalaman Path (/)", "Struktur Path", "Banyaknya tingkat direktori pada path URL."),
    "n_slash": ("Jumlah Garis Miring (/)", "Karakter Khusus", "Frekuensi simbol pemisah direktori dalam seluruh string URL."),
    "n_question": ("Jumlah Tanda Tanya (?)", "Parameter Dinamis", "Penanda awal dari query string dinamis."),
    "n_equal": ("Jumlah Simbol Sama Dengan (=)", "Parameter Dinamis", "Penanda assignment nilai parameter (misal: token login, redirect URL)."),
    "n_and": ("Jumlah Simbol Dan (&)", "Parameter Dinamis", "Pemisah antar parameter query tambahan."),
    "n_percent": ("Jumlah Simbol Persen (%)", "URL Encoding", "Indikator hex encoding yang kerap dipakai untuk menyamarkan karakter eksploit."),
    "n_at": ("Jumlah Simbol At (@)", "Indikator Bahaya Tinggi", "Browser mengabaikan teks sebelum tanda @ dan langsung mengakses host di sebelah kanannya."),
    "n_underscore": ("Jumlah Garis Bawah (_)", "Karakter Khusus", "Sering disisipkan dalam nama path file palsu."),
    "n_digits": ("Jumlah Angka Total", "Karakter Dasar", "Jumlah total karakter numerik (0-9) di seluruh URL."),
    "digit_ratio": ("Rasio Digit terhadap Panjang", "Rasio Karakter", "Proporsi karakter numerik dibandingkan total panjang URL."),
    "special_ratio": ("Rasio Karakter Khusus", "Rasio Karakter", "Proporsi simbol non-alfanumerik terhadap panjang URL."),
    "n_keyword": ("Jumlah Kata Kunci Sensitif", "Rekayasa Sosial", "Kemunculan kata-kata seperti login, verify, account, secure, bank, paypal, update, dll."),
    "has_shortener": ("Layanan Pemendek URL", "Indikator Bahaya Tinggi", "Penyembunyian domain asli via bit.ly, tinyurl, goo.gl, ow.ly, dll."),
    "has_punycode": ("Domain Punycode (xn--)", "Indikator Bahaya Tinggi", "Potensi serangan IDN Homograph Attack (mengganti huruf Latin dengan karakter visual serupa)."),
    "ext_risky": ("Ekstensi File Berbahaya", "Muatan Payload", "Target mengarah ke ekstensi executable/script (.php, .exe, .zip, .asp, .js)."),
    "double_slash_path": ("Garis Miring Ganda di Path (//)", "Evasion Teknik", "Teknik redirection bypass di mana tanda // muncul di bagian path."),
    "has_https": ("Menggunakan HTTPS", "Protokol Keamanan", "Status apakah URL diawali dengan protokol terenkripsi HTTPS."),
    "has_www": ("Menggunakan Prefiks www.", "Konvensi Domain", "Status apakah hostname diawali dengan subdomain standar www.")
}

# ==============================================================================
# 3. RESOURCE CACHING: LOAD MODEL ARTEFAK & BASIS DATA WHITELIST
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "phishing_url_hgb_model.pkl")
WHITELIST_FILE = os.path.join(BASE_DIR, "trusted_whitelist.json")

@st.cache_resource
def load_model_artifact():
    if os.path.exists(MODEL_FILE):
        return joblib.load(MODEL_FILE)
    return None

@st.cache_resource
def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return [
        {"domain": "google.com", "organization": "Google LLC", "category": "Mesin Pencari & Cloud", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "google.co.id", "organization": "Google Indonesia", "category": "Mesin Pencari Lokal", "status": "Verified National Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "youtube.com", "organization": "YouTube LLC (Google Platform)", "category": "Media & Streaming", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "wikipedia.org", "organization": "Wikimedia Foundation", "category": "Edukasi & Ensiklopedia Global", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "github.com", "organization": "GitHub Inc. (Microsoft Corp)", "category": "Platform Developer & Open Source", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"}
    ]

model_artefak = load_model_artifact()
whitelist_entries = load_whitelist()

if model_artefak is None:
    st.error("❌ Berkas model `phishing_url_hgb_model.pkl` tidak ditemukan! Pastikan model telah disimpan dari notebook.")
    st.stop()

# Helper pengecekan Whitelist
def check_domain_whitelist(url_string: str):
    try:
        clean = url_string.strip()
        if not clean.startswith(('http://', 'https://')):
            clean = 'http://' + clean
        parsed = urlparse(clean)
        hostname = (parsed.hostname or "").lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]

        for entry in whitelist_entries:
            trusted_domain = entry["domain"].lower()
            if hostname == trusted_domain or hostname.endswith("." + trusted_domain):
                return True, trusted_domain, entry["organization"]
        return False, None, None
    except Exception:
        return False, None, None

# ------------------------------------------------------------------------------
# Inisialisasi State Aplikasi (Halaman, Threshold, Whitelist)
# ------------------------------------------------------------------------------
calibrated_thr = float(model_artefak.get("threshold", 0.880))
target_rec = float(model_artefak.get("target_recall", 0.98))

if "current_page" not in st.session_state:
    st.session_state["current_page"] = "welcome"

if "current_threshold" not in st.session_state:
    st.session_state["current_threshold"] = calibrated_thr
if "tab_thresh_slider" not in st.session_state:
    st.session_state["tab_thresh_slider"] = calibrated_thr

if "use_whitelist" not in st.session_state:
    st.session_state["use_whitelist"] = False  # Default: OFF (Sesuai Permintaan)
if "tab_wl_toggle" not in st.session_state:
    st.session_state["tab_wl_toggle"] = False

# Sinkronisasi Nilai Variabel Global Operasional
calibrated_threshold = float(st.session_state["current_threshold"])
enable_whitelist = bool(st.session_state["use_whitelist"])

# ==============================================================================
# 4. SIDEBAR: NAVIGASI, IDENTITAS & KONTROL SISTEM
# (Sidebar HANYA dirender saat berada di Halaman Dashboard / App)
# ==============================================================================
if st.session_state["current_page"] == "app":
    with st.sidebar:
        st.title("🛡️ Phishing Shield")
        st.caption("Intelligent Web Threat Defense • HistGradientBoosting")
        st.markdown("---")

        # Kontrol Navigasi Kembali ke Halaman Depan
        if st.button("🏠 Kembali ke Halaman Depan", use_container_width=True):
            st.session_state["current_page"] = "welcome"
            st.rerun()

        st.markdown("---")
        st.subheader("👥 Identitas Pengembang (Kelompok 1)")
        st.markdown("""
        - **Stevanus** (`38250029`)
        - **Alra Nava Ratna Mandala** (`38250025`)
        """)
        st.info("**Mata Kuliah:** Keamanan Data (DSF01)\n\nProgram Artificial Intelligence — Semester 3")

        st.markdown("---")
        st.subheader("⚙️ Parameter Model Operasional")
        st.write("**Algoritma:** HistGradientBoosting")
        st.write("**Dimensi Fitur:** 31 Fitur Leksikal")
        st.write("**Ukuran Artefak:** 0.21 MB (Ultra-Ringan)")
        st.write(f"**Ambang Terkalibrasi (THR):** `{calibrated_thr:.3f}` (Recall: {target_rec * 100:.0f}%)")
        st.write(f"**Ambang Aktif:** `{calibrated_threshold:.3f}`")
        st.write(f"**Layer Whitelist:** `{'🟢 ON (Hybrid)' if enable_whitelist else '⚪ OFF (Murni ML)'}`")
        st.caption("💡 *Pengaturan threshold, whitelist, dan 31 fitur leksikal dapat disesuaikan pada tab:* **🎛️ Laboratorium Kustomisasi & Checklist Fitur**.")

        st.markdown("---")
        st.markdown("📌 **Fokus Utama (CIA Triad):**")
        st.caption("Melindungi **Confidentiality** dari pencurian kredensial, **Integrity** dari manipulasi form, dan **Availability** dari pemblokiran salah.")

# ==============================================================================
# 5. HALAMAN UTAMA (KONDISIONAL: WELCOMING PAGE VS MAIN DASHBOARD)
# ==============================================================================

# ------------------------------------------------------------------------------
# 5A. WELCOMING PAGE (HALAMAN DEPAN DENGAN BANNER, CYBER BACKGROUND & SIDEBAR TERKUNCI)
# ------------------------------------------------------------------------------
if st.session_state["current_page"] == "welcome":
    # CSS Khusus Welcoming Page: Mengunci Sidebar & Menghadirkan Latar Belakang Cyber Defense
    st.markdown("""
    <style>
        /* 1. Sembunyikan & Kunci Sidebar Sepenuhnya di Welcoming Page */
        [data-testid="stSidebar"],
        [data-testid="collapsedControl"],
        header[data-testid="stHeader"] button[data-testid="baseButton-header"],
        div[data-testid="stSidebarCollapseButton"] {
            display: none !important;
        }

        /* 2. Latar Belakang Welcoming Page: Cyber Defense Glowing Aesthetic (Bukan Putih Polos) */
        .stApp, [data-testid="stAppViewContainer"] {
            background: 
                radial-gradient(circle at 15% 15%, rgba(99, 102, 241, 0.22) 0%, transparent 40%),
                radial-gradient(circle at 85% 20%, rgba(168, 85, 247, 0.22) 0%, transparent 40%),
                radial-gradient(circle at 50% 80%, rgba(6, 182, 212, 0.16) 0%, transparent 50%),
                linear-gradient(180deg, #090e1a 0%, #050811 100%) !important;
            background-attachment: fixed !important;
            color: #F8FAFC !important;
        }

        /* Hero Banner Welcoming Page */
        .hero-banner {
            background: rgba(15, 23, 42, 0.82) !important;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(99, 102, 241, 0.4) !important;
            border-radius: 24px !important;
            padding: 48px 36px !important;
            margin-bottom: 28px !important;
            text-align: center;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 35px rgba(99, 102, 241, 0.25) !important;
        }
        .hero-banner h1 {
            font-size: 2.8rem !important;
            font-weight: 800 !important;
            margin-bottom: 16px !important;
            background: linear-gradient(90deg, #818CF8, #C084FC, #F472B6) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
        }
        .hero-banner p {
            color: #E2E8F0 !important;
            font-size: 1.18rem !important;
            max-width: 880px !important;
            margin: 0 auto 26px auto !important;
            line-height: 1.7 !important;
        }

        /* KPI Card Styling di Welcoming Page */
        .kpi-card {
            background: rgba(15, 23, 42, 0.85) !important;
            backdrop-filter: blur(12px) !important;
            border: 1px solid rgba(99, 102, 241, 0.3) !important;
            border-radius: 16px !important;
            padding: 24px 16px !important;
            text-align: center;
            transition: all 0.3s ease !important;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4) !important;
        }
        .kpi-card:hover {
            transform: translateY(-5px) !important;
            border-color: rgba(129, 140, 248, 0.6) !important;
            box-shadow: 0 15px 35px rgba(99, 102, 241, 0.3) !important;
        }
        .kpi-card p {
            color: #94A3B8 !important;
        }

        /* Pipeline Step Cards di Welcoming Page dengan Aksen Berwarna */
        .pipeline-card-step1 {
            background: linear-gradient(145deg, rgba(99, 102, 241, 0.22) 0%, rgba(15, 23, 42, 0.88) 100%) !important;
            border: 1px solid rgba(129, 140, 248, 0.5) !important;
            border-left: 6px solid #6366F1 !important;
            border-radius: 16px !important;
            padding: 24px 20px !important;
            box-shadow: 0 10px 28px rgba(99, 102, 241, 0.25) !important;
            height: 100% !important;
            transition: transform 0.25s ease, box-shadow 0.25s ease !important;
        }
        .pipeline-card-step1:hover {
            transform: translateY(-4px) !important;
            box-shadow: 0 16px 36px rgba(99, 102, 241, 0.4) !important;
        }

        .pipeline-card-step2 {
            background: linear-gradient(145deg, rgba(6, 182, 212, 0.22) 0%, rgba(15, 23, 42, 0.88) 100%) !important;
            border: 1px solid rgba(56, 189, 248, 0.5) !important;
            border-left: 6px solid #06B6D4 !important;
            border-radius: 16px !important;
            padding: 24px 20px !important;
            box-shadow: 0 10px 28px rgba(6, 182, 212, 0.25) !important;
            height: 100% !important;
            transition: transform 0.25s ease, box-shadow 0.25s ease !important;
        }
        .pipeline-card-step2:hover {
            transform: translateY(-4px) !important;
            box-shadow: 0 16px 36px rgba(6, 182, 212, 0.4) !important;
        }

        .pipeline-card-step3 {
            background: linear-gradient(145deg, rgba(236, 72, 153, 0.22) 0%, rgba(15, 23, 42, 0.88) 100%) !important;
            border: 1px solid rgba(244, 114, 182, 0.5) !important;
            border-left: 6px solid #EC4899 !important;
            border-radius: 16px !important;
            padding: 24px 20px !important;
            box-shadow: 0 10px 28px rgba(236, 72, 153, 0.25) !important;
            height: 100% !important;
            transition: transform 0.25s ease, box-shadow 0.25s ease !important;
        }
        .pipeline-card-step3:hover {
            transform: translateY(-4px) !important;
            box-shadow: 0 16px 36px rgba(236, 72, 153, 0.4) !important;
        }

        /* Badge Tahap Alur Kerja */
        .pipeline-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.82rem;
            margin-bottom: 12px;
            letter-spacing: 0.5px;
        }
        .pipeline-badge-1 {
            background: rgba(99, 102, 241, 0.35);
            color: #C7D2FE;
            border: 1px solid rgba(129, 140, 248, 0.6);
        }
        .pipeline-badge-2 {
            background: rgba(6, 182, 212, 0.35);
            color: #A5F3FC;
            border: 1px solid rgba(56, 189, 248, 0.6);
        }
        .pipeline-badge-3 {
            background: rgba(236, 72, 153, 0.35);
            color: #FBCFE8;
            border: 1px solid rgba(244, 114, 182, 0.6);
        }

        .pipeline-list {
            list-style: none !important;
            padding-left: 0 !important;
            margin: 12px 0 0 0 !important;
        }
        .pipeline-list li {
            padding: 6px 0 !important;
            font-size: 0.93rem !important;
            display: flex !important;
            align-items: flex-start !important;
            line-height: 1.5 !important;
        }
        .pipeline-list-bullet {
            margin-right: 8px;
            font-size: 1rem;
        }

        /* Teks subheader & judul di Welcoming Page */
        .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp p, .stApp li {
            color: #F8FAFC !important;
        }

        /* Tombol Mulai yang Menonjol dan Berkilau */
        div.stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 50%, #EC4899 100%) !important;
            color: #FFFFFF !important;
            border: 1px solid rgba(255, 255, 255, 0.4) !important;
            border-radius: 14px !important;
            padding: 18px 36px !important;
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            box-shadow: 0 10px 30px rgba(124, 58, 237, 0.55) !important;
            transition: all 0.3s ease !important;
        }
        div.stButton > button[kind="primary"]:hover {
            transform: translateY(-3px) scale(1.02) !important;
            box-shadow: 0 16px 40px rgba(236, 72, 153, 0.7) !important;
        }
    </style>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div class="hero-banner">
        <h1>🛡️ Phishing Shield: Intelligent Web Threat Defense</h1>
        <p>
            Sistem Deteksi Dini Ancaman Tautan Phishing Berbasis <b>Machine Learning (HistGradientBoosting)</b> dan 
            <b>Arsitektur Pertahanan Berlapis (Defense-in-Depth)</b>. Mampu mengeksekusi inspeksi pasif sub-milidetik 
            tanpa membocorkan lalu lintas jaringan ke server penyerang.
        </p>
        <div style="display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; margin-bottom: 28px;">
            <span class="pill-badge pill-safe">✨ 31 Fitur Leksikal Murni</span>
            <span class="pill-badge pill-safe">🎯 PR-AUC 0.997 / Recall 97.7%</span>
            <span class="pill-badge pill-warning">⚡ Inferensi &lt; 1 ms</span>
            <span class="pill-badge pill-danger">🛡️ Zero Domain Leakage Validation</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Tombol Mulai di Tengah Halaman
    col_c1, col_c2, col_c3 = st.columns([1, 1.8, 1])
    with col_c2:
        if st.button("🚀 Mulai Deteksi URL Sekarang", use_container_width=True, type="primary"):
            st.session_state["current_page"] = "app"
            st.rerun()

    st.markdown("---")

    # KPI Summary Cards
    st.subheader("📌 Metrik Kinerja & Parameter Kunci Sistem")
    col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)
    with col_kpi1:
        st.markdown("""
        <div class="kpi-card">
            <h2 style="color: #6366F1;">504.932</h2>
            <p><b>Total Dataset Latih & Uji</b><br>Tanpa undersampling buatan (31.5% Phish)</p>
        </div>
        """, unsafe_allow_html=True)
    with col_kpi2:
        st.markdown("""
        <div class="kpi-card">
            <h2 style="color: #22C55E;">99.75%</h2>
            <p><b>Tingkat Presisi Test Set</b><br>False Positive hanya 59 dari 72.029 URL sah</p>
        </div>
        """, unsafe_allow_html=True)
    with col_kpi3:
        st.markdown("""
        <div class="kpi-card">
            <h2 style="color: #F59E0B;">97.73%</h2>
            <p><b>Recall Operasional (THR = 0.880)</b><br>Menjamin pencegahan kebocoran data</p>
        </div>
        """, unsafe_allow_html=True)
    with col_kpi4:
        st.markdown("""
        <div class="kpi-card">
            <h2 style="color: #EC4899;">&lt; 1 ms</h2>
            <p><b>Kecepatan Inferensi Pasif</b><br>Ukuran artefak hanya 0.21 MB (Ringan)</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Alur Kerja 3-Langkah dengan List Berwarna
    st.subheader("🔄 Alur Kerja Sistem Deteksi (3-Stage Defense Pipeline)")
    c_step1, c_step2, c_step3 = st.columns(3)
    with c_step1:
        st.markdown("""
        <div class="pipeline-card-step1">
            <span class="pipeline-badge pipeline-badge-1">⚡ TAHAP 1: EKSTRAKSI</span>
            <h4 style="color: #A5B4FC; margin: 0 0 10px 0; font-size: 1.15rem;">Ekstraksi Pasif 31 Fitur</h4>
            <p style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.5; margin-bottom: 10px;">
                URL diurai secara murni dari struktur teks tanpa koneksi HTTP aktif ke server tujuan (menjaga kerahasiaan / <i>zero data leak</i>).
            </p>
            <ul class="pipeline-list">
                <li style="color: #E0E7FF;"><span class="pipeline-list-bullet" style="color: #818CF8;">🟣</span> <b>Entropi Shannon:</b> Menghitung tingkat keacakan string path & query</li>
                <li style="color: #E0E7FF;"><span class="pipeline-list-bullet" style="color: #818CF8;">🟣</span> <b>Struktur Simbol:</b> Frekuensi karakter mencurigakan (<code>@</code>, <code>-</code>, <code>//</code>)</li>
                <li style="color: #E0E7FF;"><span class="pipeline-list-bullet" style="color: #818CF8;">🟣</span> <b>Kata Kunci Phishing:</b> Pola perbankan, login, dan token verifikasi</li>
                <li style="color: #E0E7FF;"><span class="pipeline-list-bullet" style="color: #818CF8;">🟣</span> <b>Deteksi Host IP:</b> Mengidentifikasi alamat IP mentah tanpa domain</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with c_step2:
        st.markdown("""
        <div class="pipeline-card-step2">
            <span class="pipeline-badge pipeline-badge-2">🛡️ TAHAP 2: LAYER WHITELIST</span>
            <h4 style="color: #67E8F9; margin: 0 0 10px 0; font-size: 1.15rem;">Filter Reputasi Whitelist</h4>
            <p style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.5; margin-bottom: 10px;">
                Domain dicocokkan dengan basis data reputasi entitas resmi terpercaya untuk mengeliminasi risiko salah blokir.
            </p>
            <ul class="pipeline-list">
                <li style="color: #CFFAFE;"><span class="pipeline-list-bullet" style="color: #06B6D4;">🔵</span> <b>Domain Terpercaya:</b> Google, Wikipedia, GitHub, BCA, Mandiri, dll.</li>
                <li style="color: #CFFAFE;"><span class="pipeline-list-bullet" style="color: #06B6D4;">🔵</span> <b>Proteksi Availability:</b> Menjamin ketersediaan akses tanpa False Positive</li>
                <li style="color: #CFFAFE;"><span class="pipeline-list-bullet" style="color: #06B6D4;">🔵</span> <b>Inspeksi Subdomain:</b> Validasi hierarki nama host resmi</li>
                <li style="color: #CFFAFE;"><span class="pipeline-list-bullet" style="color: #06B6D4;">🔵</span> <b>Kustomisasi Fleksibel:</b> Dapat diaktifkan/dinonaktifkan di lab</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with c_step3:
        st.markdown("""
        <div class="pipeline-card-step3">
            <span class="pipeline-badge pipeline-badge-3">🎯 TAHAP 3: ML INFERENCE</span>
            <h4 style="color: #F472B6; margin: 0 0 10px 0; font-size: 1.15rem;">Klasifikasi Machine Learning</h4>
            <p style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.5; margin-bottom: 10px;">
                Algoritma <b>HistGradientBoosting</b> mengevaluasi probabilitas bahaya terhadap ambang batas terkalibrasi.
            </p>
            <ul class="pipeline-list">
                <li style="color: #FCE7F3;"><span class="pipeline-list-bullet" style="color: #EC4899;">🔴</span> <b>HistGradientBoosting:</b> Algoritma pohon keputusan mutakhir</li>
                <li style="color: #FCE7F3;"><span class="pipeline-list-bullet" style="color: #EC4899;">🔴</span> <b>Threshold 0.880:</b> Ambang terkalibrasi menjamin recall 98%</li>
                <li style="color: #FCE7F3;"><span class="pipeline-list-bullet" style="color: #EC4899;">🔴</span> <b>Skor Risiko 3 Tingkat:</b> Status AMAN, WASPADA, dan PHISHING</li>
                <li style="color: #FCE7F3;"><span class="pipeline-list-bullet" style="color: #EC4899;">🔴</span> <b>Tindakan Mitigasi:</b> Panduan respon insiden keamanan & CIA Triad</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Wawasan Ancaman & CIA Triad dengan List Berwarna
    col_threat1, col_threat2 = st.columns([1.2, 1])
    with col_threat1:
        st.markdown("""
        <div style="background: linear-gradient(145deg, rgba(245, 158, 11, 0.18) 0%, rgba(15, 23, 42, 0.88) 100%); border: 1px solid rgba(245, 158, 11, 0.45); border-left: 6px solid #F59E0B; border-radius: 16px; padding: 22px 20px; height: 100%;">
            <span class="pipeline-badge" style="background: rgba(245, 158, 11, 0.3); color: #FDE68A; border: 1px solid rgba(245, 158, 11, 0.6);">⚠️ THREAT LANDSCAPE</span>
            <h4 style="color: #FDE68A; margin: 0 0 10px 0; font-size: 1.15rem;">Modus Kejahatan Siber & Phishing Modern</h4>
            <ul class="pipeline-list">
                <li style="color: #FEF3C7;"><span class="pipeline-list-bullet" style="color: #F59E0B;">🟠</span> <b>Penyalahgunaan SSL (HTTPS):</b> Situs penipu lazim menggunakan sertifikat SSL gratis untuk mengelabui korban. Model 31 fitur leksikal tetap membongkar kedoknya.</li>
                <li style="color: #FEF3C7;"><span class="pipeline-list-bullet" style="color: #F59E0B;">🟠</span> <b>Typosquatting & Punycode:</b> Manipulasi huruf visual serupa (<code>xn--</code>) atau tanda hubung ganda (<code>paypal-verify-secure.com</code>).</li>
                <li style="color: #FEF3C7;"><span class="pipeline-list-bullet" style="color: #F59E0B;">🟠</span> <b>Penyamaran via URL Shortener:</b> Eksploitasi <code>bit.ly</code> atau <code>tinyurl</code> untuk menyembunyikan domain host penyerang.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    with col_threat2:
        st.markdown("""
        <div style="background: linear-gradient(145deg, rgba(16, 185, 129, 0.18) 0%, rgba(15, 23, 42, 0.88) 100%); border: 1px solid rgba(16, 185, 129, 0.45); border-left: 6px solid #10B981; border-radius: 16px; padding: 22px 20px; height: 100%;">
            <span class="pipeline-badge" style="background: rgba(16, 185, 129, 0.3); color: #A7F3D0; border: 1px solid rgba(16, 185, 129, 0.6);">🛡️ SECURITY PILLARS</span>
            <h4 style="color: #A7F3D0; margin: 0 0 10px 0; font-size: 1.15rem;">Keterkaitan dengan CIA Triad</h4>
            <ul class="pipeline-list">
                <li style="color: #D1FAE5;"><span class="pipeline-list-bullet" style="color: #EF4444;">🔴</span> <b>Kerahasiaan (Confidentiality):</b> Mencegah kebocoran kata sandi, token 2FA, PIN, dan data kartu perbankan.</li>
                <li style="color: #D1FAE5;"><span class="pipeline-list-bullet" style="color: #F59E0B;">🟡</span> <b>Integritas (Integrity):</b> Melindungi integritas sesi pengguna dari injeksi formulir palsu dan skrip eksploitasi.</li>
                <li style="color: #D1FAE5;"><span class="pipeline-list-bullet" style="color: #10B981;">🟢</span> <b>Ketersediaan (Availability):</b> Whitelist reputasi menjamin domain resmi tidak terblokir salah (*Zero False Positive*).</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# 5B. MAIN APPLICATION DASHBOARD (TABS 1 - 5)
# ------------------------------------------------------------------------------
else:
    col_head1, col_head2 = st.columns([4, 1])
    with col_head1:
        st.caption("Aplikasi Deteksi Ancaman Phishing URL • HistGradientBoosting 31 Fitur")
    with col_head2:
        if st.button("⬅️ Halaman Depan", use_container_width=True):
            st.session_state["current_page"] = "welcome"
            st.rerun()

    tab_predict, tab_checklist, tab_batch, tab_analytics, tab_qa_whitelist = st.tabs([
        "🔍 Pindai URL Real-Time",
        "🎛️ Laboratorium Kustomisasi & Checklist Fitur",
        "📁 Pemindaian Massal (Batch)",
        "📊 Analisis Model & Data",
        "🧪 Validasi QA & Whitelist"
    ])

    # --------------------------------------------------------------------------
    # TAB 1: DETEKSI URL REAL-TIME (SMOOTH & ANIMATED UX)
    # --------------------------------------------------------------------------
    with tab_predict:
        st.title("Deteksi Ancaman Phishing URL Real-Time")
        st.write(f"Klasifikasi ancaman URL menggunakan **HistGradientBoosting** (31 Fitur Leksikal) {'+ Filter Whitelist' if enable_whitelist else '(Mode Murni ML)'}.")

        if "input_url_val" not in st.session_state:
            st.session_state["input_url_val"] = ""

        def load_preset_url(u):
            st.session_state["input_url_val"] = u

        # Preset Cepat 8 Skenario
        st.write("##### ⚡ Uji Cepat dengan Contoh Skenario:")
        col_p1, col_p2, col_p3, col_p4 = st.columns(4)
        with col_p1:
            st.button("🌐 Google (Resmi)", use_container_width=True, on_click=load_preset_url, args=("https://www.google.com",))
            st.button("🚨 IP Phishing Mentah", use_container_width=True, on_click=load_preset_url, args=("http://192.168.10.5/secure-login/verify-account.php?id=1",))
        with col_p2:
            st.button("📖 Wikipedia (Resmi)", use_container_width=True, on_click=load_preset_url, args=("https://www.wikipedia.org/wiki/Keamanan_komputer",))
            st.button("🚨 Typosquatting Paypal", use_container_width=True, on_click=load_preset_url, args=("http://paypal-secure-update.example.com/webscr/login?confirm=1",))
        with col_p3:
            st.button("💻 GitHub (Platform Dev)", use_container_width=True, on_click=load_preset_url, args=("https://www.github.com/torvalds/linux",))
            st.button("🚨 Shortener URL Bitly", use_container_width=True, on_click=load_preset_url, args=("http://bit.ly/claim-bank-bonus-now",))
        with col_p4:
            st.button("🏛️ Archive.org (HTTP Lama)", use_container_width=True, on_click=load_preset_url, args=("http://archive.org/web/",))
            st.button("🚨 Punycode Homograph", use_container_width=True, on_click=load_preset_url, args=("http://xn--pypal-4ve.com/account-update",))

        # Form Input URL
        with st.form("url_scan_form_smooth"):
            user_url = st.text_input(
                "Masukkan Tautan / Link URL yang ingin diperiksa:",
                value=st.session_state["input_url_val"],
                placeholder="Contoh: https://en.wikipedia.org/wiki/Main_Page atau http://paypal-verify-account.com/login",
                help="Ketik URL lengkap beserta protokol http/https untuk akurasi ekstraksi leksikal terbaik."
            )
            submit_btn = st.form_submit_button("🚀 Pindai & Analisis URL", use_container_width=True, type="primary")

        if submit_btn or st.session_state["input_url_val"]:
            target_eval_url = user_url.strip() if user_url else st.session_state["input_url_val"].strip()

            if not target_eval_url:
                st.warning("⚠️ Silakan masukkan tautan URL terlebih dahulu sebelum memindai.")
            elif len(target_eval_url) < 4 or (not "." in target_eval_url and not "localhost" in target_eval_url):
                st.error("❌ Format input tidak valid! Harap masukkan string tautan URL atau alamat domain yang benar.")
            else:
                clean_url = target_eval_url

                # Progressive Scanning Animation
                with st.status("🔍 Menganalisis Keamanan Tautan...", expanded=True) as status_box:
                    st.write("1️⃣ Mengurai struktur string URL & parsing sintaks...")
                    time.sleep(0.12)
                    st.write("2️⃣ Mengekstrak 31 fitur leksikal murni (entropi Shannon, parameter, rasio)...")
                    time.sleep(0.12)
                    if enable_whitelist:
                        st.write("3️⃣ Memverifikasi basis data Trusted Whitelist (Layer 1 Defense-in-Depth)...")
                        time.sleep(0.12)
                    st.write("4️⃣ Menjalankan inferensi model HistGradientBoosting (Layer 2)...")
                    time.sleep(0.12)
                    status_box.update(label="✅ Analisis Keamanan Selesai!", state="complete", expanded=False)

                # Ekstraksi Fitur Leksikal
                start_inference_time = time.time()
                vec = ekstrak_satu(clean_url)
                features_df = pd.DataFrame([vec], columns=model_artefak["fitur"], dtype="float32")

                # Cek Whitelist
                is_trusted, matched_domain, org_desc = (False, None, None)
                if enable_whitelist:
                    is_trusted, matched_domain, org_desc = check_domain_whitelist(clean_url)

                # Prediksi Model
                p_phish = float(model_artefak["model"].predict_proba(features_df)[:, 1][0])
                p_legit = float(1.0 - p_phish)
                thr = calibrated_threshold

                if p_phish >= thr:
                    ml_risk_level = "TINGGI (blokir)"
                    raw_ml_phishing = True
                elif p_phish >= (thr / 2):
                    ml_risk_level = "WASPADA"
                    raw_ml_phishing = False
                else:
                    ml_risk_level = "RENDAH"
                    raw_ml_phishing = False

                inference_latency = (time.time() - start_inference_time) * 1000

                # Keputusan Akhir
                if enable_whitelist and is_trusted:
                    final_is_phishing = False
                    final_risk_label = "AMAN (Terverifikasi Whitelist)"
                    is_hybrid_override = raw_ml_phishing or (ml_risk_level != "RENDAH")
                else:
                    final_is_phishing = raw_ml_phishing
                    final_risk_label = ml_risk_level
                    is_hybrid_override = False

                # Reasoning Engine
                r = features_df.iloc[0]
                alasan = []
                if r.host_is_ip: alasan.append("Domain berupa alamat IP langsung (menghindari registrasi domain resmi)")
                if r.n_keyword >= 2: alasan.append(f"Memuat {int(r.n_keyword)} kata kunci sensitif perbankan/login")
                elif r.n_keyword == 1: alasan.append("Memuat kata kunci sensitif (login/verify/update)")
                if r.host_hyphens >= 2: alasan.append(f"Hostname memuat {int(r.host_hyphens)} tanda hubung (-) (indikasi typosquatting)")
                if r.n_subdomain >= 3: alasan.append(f"Subdomain bertingkat ({int(r.n_subdomain)} level)")
                if r.has_shortener: alasan.append("Menggunakan layanan pemendek tautan (URL Shortener)")
                if r.has_punycode: alasan.append("Domain punycode xn-- (potensi serangan IDN Homograph)")
                if r.n_at: alasan.append("Mengandung simbol '@' untuk mengelabui pembacaan host")
                if r.url_len > 100: alasan.append(f"URL sangat panjang ({int(r.url_len)} karakter)")
                if r.ext_risky: alasan.append("Mengarah ke file berekstensi skrip berisiko (.php, .exe, dll)")
                if r.has_https == 0: alasan.append("Tidak menggunakan protokol aman HTTPS")
                if not alasan:
                    alasan = ["Struktur leksikal URL bersih dan tidak menunjukkan indikator anomali mencurigakan."]

                # Tampilan Hasil Evaluasi
                st.markdown("---")
                st.subheader("🎯 Hasil Evaluasi Sistem Deteksi")

                col_res_card, col_res_gauge = st.columns([1.2, 1])

                with col_res_card:
                    if final_is_phishing:
                        st.markdown(f"""
                        <div class="status-card-danger">
                            <h3>🚨 BAHAYA: INDIKASI PHISHING ({final_risk_label})</h3>
                            <p style="margin: 8px 0 0 0; font-size: 1.05rem;">
                                Tautan ini memiliki probabilitas ancaman melampaui ambang operasional (p = {p_phish:.3f} &ge; {thr:.3f}). 
                                Akses ke alamat ini disarankan <b>DIBLOKIR SEGERA</b> untuk mencegah pencurian kredensial.
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                    elif is_hybrid_override:
                        st.markdown(f"""
                        <div class="status-card-hybrid">
                            <h3>🛡️ AMAN (DIVERIFIKASI OLEH WHITELIST REPUTASI)</h3>
                            <p style="margin: 8px 0 0 0; font-size: 1.05rem;">
                                <b>Domain Resmi Terverifikasi:</b> {matched_domain} ({org_desc}).<br>
                                <i>Layer Whitelist memproteksi domain ini dari kesalahan prediksi False Positive model leksikal demi menjamin Availability.</i>
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                    elif ml_risk_level == "WASPADA":
                        st.markdown(f"""
                        <div class="status-card-warning">
                            <h3>⚠️ STATUS: WASPADA (RISIKO MODERAT)</h3>
                            <p style="margin: 8px 0 0 0; font-size: 1.05rem;">
                                Probabilitas berada di rentang waspada ({thr/2:.2f} &le; p &lt; {thr:.2f}). 
                                Pengguna disarankan memeriksa ulang keabsahan situs sebelum memasukkan data pribadi.
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="status-card-safe">
                            <h3>✅ AMAN: RISIKO RENDAH (LEGITIMATE)</h3>
                            <p style="margin: 8px 0 0 0; font-size: 1.05rem;">
                                Tautan memiliki struktur leksikal yang wajar dan menyerupai karakteristik situs resmi/aman (p = {p_phish:.3f} &lt; {thr/2:.2f}).
                            </p>
                        </div>
                        """, unsafe_allow_html=True)

                    c_sub1, c_sub2 = st.columns(2)
                    c_sub1.metric("Probabilitas Phishing", f"{p_phish * 100:.1f}%", f"Ambang: {thr * 100:.1f}%")
                    c_sub2.metric("Latensi Inferensi Pasif", f"{inference_latency:.1f} ms", "Sub-milidetik (Ultra-Cepat)")

                with col_res_gauge:
                    # Speedometer Gauge Chart (Plotly)
                    fig_gauge = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=round(p_phish * 100, 1),
                        domain={'x': [0, 1], 'y': [0, 1]},
                        title={'text': "Speedometer Risiko Phishing", 'font': {'size': 18, 'color': '#6366F1'}},
                        number={'suffix': "%", 'font': {'size': 36}},
                        gauge={
                            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "gray"},
                            'bar': {'color': "#EF4444" if final_is_phishing else ("#F59E0B" if ml_risk_level == "WASPADA" else "#22C55E"), 'thickness': 0.3},
                            'bgcolor': "rgba(128,128,128,0.1)",
                            'borderwidth': 1,
                            'bordercolor': "gray",
                            'steps': [
                                {'range': [0, (thr/2) * 100], 'color': "rgba(34, 197, 94, 0.25)"},
                                {'range': [(thr/2) * 100, thr * 100], 'color': "rgba(245, 158, 11, 0.25)"},
                                {'range': [thr * 100, 100], 'color': "rgba(239, 68, 68, 0.25)"}
                            ],
                            'threshold': {
                                'line': {'color': "red", 'width': 3},
                                'thickness': 0.75,
                                'value': thr * 100
                            }
                        }
                    ))
                    fig_gauge.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=10))
                    st.plotly_chart(fig_gauge, use_container_width=True)

                # Indikator Heuristik Deteksi (Pill Badges)
                st.write("##### 🔍 Indikator Heuristik Deteksi (Reasoning Engine):")
                for ind in alasan:
                    if "IP" in ind or "punycode" in ind or "@" in ind or "sensitif" in ind:
                        st.markdown(f'<span class="pill-badge pill-danger">🔴 {ind}</span>', unsafe_allow_html=True)
                    elif "pendek" in ind or "panjang" in ind or "HTTPS" in ind or "subdomain" in ind:
                        st.markdown(f'<span class="pill-badge pill-warning">🟡 {ind}</span>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<span class="pill-badge pill-safe">🟢 {ind}</span>', unsafe_allow_html=True)

                st.write("")
                c_lay1, c_lay2 = st.columns(2)
                with c_lay1:
                    st.markdown(f"""
                    <div class="metric-box">
                        <b>Layer 1: Filter Reputasi Domain (Whitelist)</b><br>
                        Status: {'🟢 Terdaftar Resmi' if is_trusted else '⚪ Domain Publik / Unverified'}<br>
                        Detail: {org_desc if is_trusted else 'Evaluasi diserahkan sepenuhnya ke Model Machine Learning.'}
                    </div>
                    """, unsafe_allow_html=True)
                with c_lay2:
                    st.markdown(f"""
                    <div class="metric-box">
                        <b>Layer 2: Model Machine Learning (HistGradientBoosting)</b><br>
                        Status Mentah ML: <b>{'🚨 Phishing' if raw_ml_phishing else ('⚠️ Waspada' if ml_risk_level == 'WASPADA' else '✅ Legitimate')}</b><br>
                        Probabilitas: Phishing {p_phish*100:.1f}% | Legitimate {p_legit*100:.1f}% (Threshold: {thr:.3f})
                    </div>
                    """, unsafe_allow_html=True)

                # Ekspor Laporan Keamanan
                report_text = f"""======================================================================
LAPORAN AUDIT FORENSIK KEAMANAN URL - PHISHING SHIELD
======================================================================
Waktu Pemindaian   : {time.strftime('%Y-%m-%d %H:%M:%S')}
Target URL         : {clean_url}
Status Klasifikasi : {'PHISHING' if final_is_phishing else ('AMAN (WHITELIST)' if is_hybrid_override else 'AMAN')}
Probabilitas Phish : {p_phish*100:.2f}%
Ambang Operasional : {thr*100:.1f}%
Latensi Inferensi  : {inference_latency:.2f} ms
Whitelist Status   : {'Terdaftar (' + str(org_desc) + ')' if is_trusted else 'Tidak Terdaftar'}
Indikator Risiko   :
{chr(10).join(['- ' + a for a in alasan])}

Rekomendasi CIA    :
{'JANGAN MASUKKAN KREDENSIAL. Blokir akses segera.' if final_is_phishing else 'Tautan dinilai aman. Tetap terapkan Zero Trust.'}
======================================================================"""

                st.download_button(
                    label="📄 Unduh Laporan Audit Keamanan (.txt)",
                    data=report_text,
                    file_name=f"Security_Report_{int(time.time())}.txt",
                    mime="text/plain"
                )

                # Tabel 31 Fitur Lengkap
                with st.expander("📋 Tampilkan Rincian Ekstraksi 31 Fitur Leksikal URL", expanded=False):
                    feat_table = []
                    for col_name in model_artefak["fitur"]:
                        val = features_df[col_name].values[0]
                        friendly_name, cat, desc = FEATURE_META.get(col_name, (col_name, "Fitur", "-"))

                        risk_level = "Wajar"
                        if col_name == 'host_is_ip' and val == 1: risk_level = "🚨 Alamat IP Langsung"
                        elif col_name == 'has_punycode' and val == 1: risk_level = "🚨 Domain Punycode (xn--)"
                        elif col_name == 'n_at' and val > 0: risk_level = "🚨 Mengandung Simbol @"
                        elif col_name == 'has_shortener' and val == 1: risk_level = "⚠️ Layanan Pemendek URL"
                        elif col_name == 'n_keyword' and val >= 2: risk_level = "🚨 Banyak Kata Sensitif"
                        elif col_name == 'host_hyphens' and val >= 2: risk_level = "⚠️ Banyak Tanda Hubung (-)"
                        elif col_name == 'n_subdomain' and val >= 3: risk_level = "⚠️ Subdomain Bertingkat"
                        elif col_name == 'url_len' and val > 100: risk_level = "⚠️ URL Sangat Panjang"
                        elif col_name == 'has_https' and val == 0: risk_level = "⚠️ Non-HTTPS (HTTP Biasa)"

                        feat_table.append({
                            "Fitur": friendly_name,
                            "Kategori": cat,
                            "Nilai": val,
                            "Indikator Pola": risk_level,
                            "Deskripsi": desc
                        })
                    st.dataframe(pd.DataFrame(feat_table), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # TAB 2: KUSTOMISASI CHECKLIST FITUR (DYNAMIC MASKING & DROPDOWN EXPANDER)
    # --------------------------------------------------------------------------
    with tab_checklist:
        st.title("🎛️ Laboratorium Kustomisasi & Checklist Fitur (Ablasi Interaktif)")
        st.markdown("""
        Fitur ini memungkinkan Anda **mengonfigurasi ambang batas (threshold), memodifikasi layer whitelist, serta mengaktifkan/menonaktifkan 31 fitur leksikal** guna menguji sensitivitas model:
        - *Bagaimana jika fitur `has_https` dan `has_www` dimatikan? Apakah model tetap mampu mendeteksi phishing modern ber-SSL?*
        - *Bagaimana jika indikator kata kunci sensitif diabaikan?*
        Ketika fitur dinonaktifkan, nilainya akan **dinetralkan ke baseline aman** (*feature masking*).
        """)

        st.markdown("---")

        # 1. Parameter Deteksi Global dalam Dropdown (Threshold & Whitelist)
        st.write("##### 🎛️ Parameter Deteksi Operasional:")
        col_param1, col_param2 = st.columns(2)
        with col_param1:
            with st.expander("🎯 Pengaturan Ambang Batas Klasifikasi (Threshold)", expanded=False):
                st.markdown("""
                Sesuaikan sensitivitas ambang probabilitas klasifikasi (*decision threshold*):
                - **Ambang Rendah (< 0.50)**: Sangat sensitif (*high recall*), namun berisiko memicu *False Positive*.
                - **Ambang Terkalibrasi (0.880)**: Nilai optimal rekomendasi sistem (Recall 98% pada OOF).
                - **Ambang Tinggi (> 0.90)**: Konservatif, memprioritaskan kepastian (*high precision*).
                """)

                def _sync_tab_thr():
                    st.session_state["current_threshold"] = st.session_state["tab_thresh_slider"]

                tab_thr = st.slider(
                    "Pilih Ambang Batas (Threshold):",
                    min_value=0.10,
                    max_value=0.98,
                    value=float(st.session_state["current_threshold"]),
                    step=0.01,
                    key="tab_thresh_slider",
                    on_change=_sync_tab_thr,
                    help=f"Ambang bawaan terkalibrasi: {calibrated_thr:.3f}"
                )
                if tab_thr == calibrated_thr:
                    st.success(f"🎯 Ambang Terkalibrasi Aktif: `{tab_thr:.3f}` (Recall: {target_rec * 100:.0f}%)")
                else:
                    st.warning(f"⚠️ Ambang Kustom Aktif: `{tab_thr:.3f}` (Bawaan: `{calibrated_thr:.3f}`)")

        with col_param2:
            with st.expander("🛡️ Pengaturan Mode Whitelist Domain Terpercaya (Defense-in-Depth)", expanded=False):
                st.markdown("""
                Konfigurasi lapisan keamanan **Layer 1: Trusted Whitelist Reputation**:
                - **OFF (Default Bawaan)**: Deteksi **100% murni model Machine Learning** leksikal tanpa bantuan filter reputasi eksternal.
                - **ON**: Mode *Hybrid Defense-in-Depth*. Domain resmi terverifikasi (misal: `google.com`, `paypal.com`) langsung dilindungi dari *False Positive*.
                """)

                def _sync_tab_wl():
                    st.session_state["use_whitelist"] = st.session_state["tab_wl_toggle"]

                tab_wl = st.toggle(
                    "Aktifkan Whitelist Domain Resmi:",
                    value=bool(st.session_state["use_whitelist"]),
                    key="tab_wl_toggle",
                    on_change=_sync_tab_wl
                )
                if tab_wl:
                    st.info("🟢 **Mode Whitelist ON**: Domain resmi terverifikasi diproteksi oleh layer reputasi.")
                else:
                    st.caption("⚪ **Mode Whitelist OFF (Default)**: Model murni mengevaluasi fitur leksikal URL secara independen.")

        st.markdown("---")

        # 2. Inisialisasi State Checkbox untuk setiap fitur
        for feat in FITUR:
            if f"chk_{feat}" not in st.session_state:
                st.session_state[f"chk_{feat}"] = True

        def apply_preset(active_features_list):
            for f in FITUR:
                st.session_state[f"chk_{f}"] = (f in active_features_list)
            st.rerun()

        # Tombol Preset Cepat (Otomatis Sinkron dengan Checkbox)
        st.write("##### ⚡ Pilih Preset Konfigurasi Fitur:")
        c_btn1, c_btn2, c_btn3, c_btn4 = st.columns(4)
        with c_btn1:
            if st.button("🟢 Semua Fitur Aktif (31 Fitur)", use_container_width=True):
                apply_preset(FITUR)
        with c_btn2:
            if st.button("🛡️ Tanpa HTTPS & WWW (29 Fitur)", use_container_width=True):
                apply_preset([f for f in FITUR if f not in ["has_https", "has_www"]])
        with c_btn3:
            if st.button("⚡ HANYA HTTPS & WWW (2 Fitur)", use_container_width=True):
                apply_preset(["has_https", "has_www"])
        with c_btn4:
            if st.button("🚨 Hanya Indikator Bahaya Tinggi", use_container_width=True):
                apply_preset(FEATURE_GROUPS["🚨 Indikator Bahaya Tingkat Tinggi & Rekayasa Sosial"])

        # Menghitung Fitur yang Sedang Aktif
        current_active_features = [f for f in FITUR if st.session_state.get(f"chk_{f}", True)]
        active_count = len(current_active_features)

        st.markdown(f"""
        <div class="metric-box">
            <b>Status Konfigurasi Fitur:</b> <code>{active_count} dari 31 Fitur Aktif</code><br>
            Fitur yang dinonaktifkan akan dinetralkan (*masked*) ke nilai baseline aman saat evaluasi dijalankan.
        </div>
        """, unsafe_allow_html=True)

        # Dropdown Expander untuk 31 Checklist Fitur agar Tidak Perlu Scroll Panjang
        with st.expander("⚙️ Buka / Tutup Pengaturan Checklist 31 Fitur Leksikal (Klik untuk Memilih Fitur)", expanded=False):
            st.caption("Centang untuk mengaktifkan fitur. Hapus centang untuk menonaktifkan/menetralkan fitur:")
            col_chk1, col_chk2 = st.columns(2)
            group_items = list(FEATURE_GROUPS.items())

            for idx, (group_name, group_features) in enumerate(group_items):
                target_col = col_chk1 if idx % 2 == 0 else col_chk2
                with target_col:
                    st.markdown(f"**{group_name}**")
                    for feat in group_features:
                        f_label = FEATURE_META.get(feat, (feat, "", ""))[0]
                        st.checkbox(
                            f"{f_label} (`{feat}`)",
                            key=f"chk_{feat}"
                        )
                    st.write("")

        # 3. Evaluasi Uji Coba Dampak Masking Fitur
        st.markdown("---")
        st.subheader("🧪 Uji Coba Dampak Masking Fitur pada URL Tertentu")
        st.markdown("""
        Uji dampak penonaktifan fitur (*ablation study*) terhadap tautan kustom pilihan Anda.
        Sistem akan menganalisis probabilitas model penuh vs model kustom, mengklasifikasikan status ancaman (**Phishing** atau **Legit / Aman**), serta memberikan panduan **tindakan mitigasi keamanan**.
        """)

        # Tombol preset URL contoh untuk uji ablasi
        st.write("##### ⚡ Pilih Contoh URL Cepat untuk Pengujian Ablasi:")
        c_ex1, c_ex2, c_ex3 = st.columns(3)
        with c_ex1:
            if st.button("🚨 Paypal Spoof (Phishing)", key="btn_abl_phish", use_container_width=True):
                st.session_state["abl_test_input"] = "http://paypal-secure-update.example.com/webscr/login?confirm=1"
        with c_ex2:
            if st.button("🚨 IP Login Portal (Phishing)", key="btn_abl_ip", use_container_width=True):
                st.session_state["abl_test_input"] = "http://192.168.10.5/secure-login/verify-account.php?id=1"
        with c_ex3:
            if st.button("🌐 Wikipedia Artikel (Legit)", key="btn_abl_legit", use_container_width=True):
                st.session_state["abl_test_input"] = "https://www.wikipedia.org/wiki/Keamanan_komputer"

        test_abl_url = st.text_input(
            "Masukkan URL untuk diuji perbandingannya:",
            value=st.session_state.get("abl_test_input", "http://paypal-secure-update.example.com/webscr/login?confirm=1"),
            key="abl_test_input"
        )

        if test_abl_url:
            raw_vec = ekstrak_satu(test_abl_url)
            df_full = pd.DataFrame([raw_vec], columns=model_artefak["fitur"], dtype="float32")
            prob_full = float(model_artefak["model"].predict_proba(df_full)[:, 1][0])

            # Mengambil daftar fitur aktif terbaru
            active_now = [f for f in FITUR if st.session_state.get(f"chk_{f}", True)]
            masked_vec = []
            for i, col_name in enumerate(model_artefak["fitur"]):
                if col_name in active_now:
                    masked_vec.append(raw_vec[i])
                else:
                    masked_vec.append(NEUTRAL_BASELINE[col_name])

            df_masked = pd.DataFrame([masked_vec], columns=model_artefak["fitur"], dtype="float32")
            prob_masked = float(model_artefak["model"].predict_proba(df_masked)[:, 1][0])

            cur_thr = float(st.session_state.get("current_threshold", calibrated_thr))
            cur_wl = bool(st.session_state.get("use_whitelist", False))

            # Whitelist check jika layer whitelist diaktifkan
            is_wl, w_domain, w_org = check_domain_whitelist(test_abl_url) if cur_wl else (False, None, None)

            # Klasifikasi Model Penuh (31 Fitur)
            if cur_wl and is_wl:
                status_full = "AMAN (WHITELIST)"
                is_phish_full = False
            elif prob_full >= cur_thr:
                status_full = "PHISHING"
                is_phish_full = True
            elif prob_full >= 0.50:
                status_full = "WASPADA"
                is_phish_full = False
            else:
                status_full = "LEGIT (AMAN)"
                is_phish_full = False

            # Klasifikasi Model Masked (Kustom)
            if cur_wl and is_wl:
                status_masked = "AMAN (WHITELIST)"
                is_phish_masked = False
            elif prob_masked >= cur_thr:
                status_masked = "PHISHING"
                is_phish_masked = True
            elif prob_masked >= 0.50:
                status_masked = "WASPADA"
                is_phish_masked = False
            else:
                status_masked = "LEGIT (AMAN)"
                is_phish_masked = False

            # Tampilkan metrik perbandingan
            col_comp1, col_comp2, col_comp3 = st.columns(3)
            with col_comp1:
                st.metric(
                    "Skor Model Penuh (31 Fitur)",
                    f"{prob_full * 100:.1f}%",
                    f"Status: {status_full}"
                )
            with col_comp2:
                st.metric(
                    f"Skor Model Masked ({len(active_now)} Fitur)",
                    f"{prob_masked * 100:.1f}%",
                    f"Status: {status_masked}"
                )
            with col_comp3:
                delta_val = (prob_masked - prob_full) * 100
                st.metric("Pergeseran Probabilitas (Shift)", f"{delta_val:+.1f}%", "Dampak Masking")

            if len(active_now) < 31:
                disabled_feats = [f for f in FITUR if f not in active_now]
                st.caption(f"🔧 **Fitur yang dinonaktifkan:** {', '.join(disabled_feats)}")

            # Visual Status Banner untuk Hasil Deteksi URL Kustom
            st.markdown("#### 🎯 Hasil Klasifikasi & Status Keamanan URL:")
            if status_full == "PHISHING":
                st.markdown(f"""
                <div class="status-card-danger">
                    <h3>🚨 STATUS: TERINDIKASI SEBAGAI TAUTAN PHISHING</h3>
                    <p style="margin: 6px 0 0 0; font-size: 1.05rem;">
                        Model memprediksi probabilitas ancaman sebesar <b>{prob_full*100:.1f}%</b> (melebihi ambang batas bahaya <b>{cur_thr:.3f}</b>). 
                        Tautan ini terdeteksi memiliki karakteristik leksikal mencurigakan yang dirancang untuk mengelabui korban atau mencuri data sensitif.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            elif status_full == "WASPADA":
                st.markdown(f"""
                <div class="status-card-warning">
                    <h3>⚠️ STATUS: WASPADA / ANOMALI LEKSIKAL TERDETEKSI</h3>
                    <p style="margin: 6px 0 0 0; font-size: 1.05rem;">
                        Probabilitas ancaman sebesar <b>{prob_full*100:.1f}%</b> (berada di zona transisi antara 50% dan ambang batas <b>{cur_thr:.3f}</b>). 
                        Struktur URL menunjukkan pola tidak wajar meskipun belum secara definitif memenuhi kriteria pemblokiran otomatis.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            elif status_full == "AMAN (WHITELIST)":
                st.markdown(f"""
                <div class="status-card-hybrid">
                    <h3>🛡️ STATUS: AMAN (TERVERIFIKASI BASIS DATA WHITELIST)</h3>
                    <p style="margin: 6px 0 0 0; font-size: 1.05rem;">
                        Domain terdaftar resmi dalam whitelist reputasi terpercaya: <b>{w_org}</b>. Tautan dilindungi dari False Positive demi menjamin Availability.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="status-card-safe">
                    <h3>✅ STATUS: TAUTAN AMAN / LEGITIMATE (RISIKO RENDAH)</h3>
                    <p style="margin: 6px 0 0 0; font-size: 1.05rem;">
                        Probabilitas ancaman hanya <b>{prob_full*100:.1f}%</b> (jauh di bawah ambang batas risiko <b>{cur_thr:.3f}</b>). 
                        Tidak ditemukan anomali atau tanda-tanda manipulasi leksikal yang mengindikasikan rekayasa sosial phishing.
                    </p>
                </div>
                """, unsafe_allow_html=True)

            # Evasion Insight Alert jika masking mengubah hasil prediksi
            if status_full != status_masked:
                st.warning(f"""
                ⚠️ **Wawasan Evasion (Dampak Masking Fitur):**
                Penonaktifan fitur mengubah status dari **{status_full}** menjadi **{status_masked}** (pergeseran {delta_val:+.1f}%).
                Hal ini membuktikan bahwa fitur yang dinonaktifkan memegang peranan krusial bagi model dalam mengidentifikasi taktik penyamaran penyerang pada tautan ini.
                """)

            # Panduan Tindakan Mitigasi
            st.markdown("#### 🛡️ Rekomendasi Tindakan Mitigasi Keamanan:")
            if is_phish_full or status_full == "PHISHING":
                st.error("""
                **Tindakan Mitigasi Ancaman Phishing Segera (Immediate Action):**
                1. 🛑 **JANGAN KLIK / HINDARI AKSES**: Jangan membuka tautan ini pada browser normal untuk menghindari pengunduhan malware diam-diam (*drive-by download*) atau rekayasa sosial.
                2. 🔒 **JANGAN MASUKKAN DATA PRIBADI**: Jangan pernah mengisi kolom login, email, password, nomor kartu debit/kredit, PIN, atau kode OTP pada halaman tujuan.
                3. 🛡️ **Blokir pada Tingkat Jaringan (SOC / Network Admin)**:
                   - Masukkan domain/IP ini ke dalam *DNS Sinkhole* atau *Firewall Blacklist* perusahaan/kampus.
                   - Pasang aturan pemblokiran pada *Secure Web Gateway (SWG)* atau *Web Application Firewall (WAF)*.
                   - Laporkan URL ke penyedia perlindungan publik: *Google Safe Browsing*, *Microsoft SmartScreen*, dan *PhishTank*.
                4. 🚨 **Langkah Darurat (Jika Sudah Terlanjur Diklik / Menginput Kredensial)**:
                   - **Reset Password Segera**: Ubah kata sandi akun terkait melalui kanal resmi dan perangkat lain yang aman.
                   - **Revoke Active Sessions**: Hentikan/putuskan semua sesi login aktif pada pengaturan keamanan akun.
                   - **Aktifkan MFA**: Aktifkan verifikasi 2 langkah (Multi-Factor Authentication) menggunakan aplikasi Authenticator atau Security Key (FIDO2).
                   - **Pemindaian Perangkat**: Jalankan pemindaian antivirus / anti-malware lengkap pada perangkat Anda.
                """)
            elif status_full == "WASPADA":
                st.warning("""
                **Tindakan Mitigasi Tautan Waspada / Anomali (Precautionary Action):**
                1. 🔍 **Verifikasi Nama Domain**: Periksa dengan seksama ejaan domain. Waspadai huruf pengganti (*typosquatting*) atau subdomain panjang berkedok nama brand terkenal.
                2. 🕵️ **Cek Usia Domain (WHOIS)**: Domain phishing biasanya baru didaftarkan dalam waktu beberapa hari/minggu.
                3. 🧪 **Analisis Terisolasi**: Jika tautan wajib dibuka untuk keperluan riset, gunakan *Browser Sandbox* atau lingkungan mesin virtual (VM) terisolasi tanpa akses ke data pribadi.
                4. 🚫 **Hindari Mengunduh Berkas**: Jangan mengeksekusi file dengan ekstensi ganda atau mencurigakan (seperti `.exe`, `.zip`, `.scr`, `.html`) yang diunduh dari situs tersebut.
                """)
            else:
                st.success("""
                **Pedoman Keamanan Tautan Legit / Aman (Cyber Hygiene Best Practices):**
                1. 🔒 **Pertahankan Prinsip Zero-Trust**: Meskipun tautan terindikasi aman secara leksikal, selalu pastikan situs menggunakan protokol HTTPS dengan sertifikat SSL/TLS terbitan Certificate Authority (CA) resmi.
                2. 🌐 **Verifikasi Alamat Resmi**: Selalu akses layanan perbankan, media sosial, atau portal kampus melalui *bookmark* pribadi atau aplikasi resmi, bukan melalui tautan acak di SMS, WhatsApp, atau email promosi.
                3. 💡 **Edukasi Anti-Phishing**: Tetap waspada terhadap permintaan transfer uang, perubahan kata sandi mendadak, atau pesan bernada mendesak (*urgency-based social engineering*).
                """)

    # --------------------------------------------------------------------------
    # TAB 3: PEMINDAIAN MASSAL (BATCH SCANNER DENGAN TEMPLATE & STATUS BERSIH)
    # --------------------------------------------------------------------------
    with tab_batch:
        st.title("📁 Pemindaian Massal (Batch URL Security Scanner)")
        st.markdown("""
        Fitur ini dirancang untuk operasional **Security Operations Center (SOC)**: Pindai puluhan hingga ratusan tautan 
        secara serentak dalam hitungan milidetik tanpa koneksi jaringan pasif, lalu unduh hasilnya sebagai berkas audit CSV bersih.
        """)

        # Tombol Download Template CSV
        template_csv_content = "url\nhttps://www.google.com\nhttps://www.wikipedia.org/wiki/Keamanan_komputer\nhttp://192.168.10.5/secure-login/verify.php\nhttp://paypal-secure-update.example.com/login\nhttp://bit.ly/claim-bank-bonus-now\nhttp://xn--pypal-4ve.com/account-update\nhttp://archive.org/web/\n"
        st.download_button(
            label="📥 Unduh Berkas Template CSV Contoh (template_url.csv)",
            data=template_csv_content.encode("utf-8-sig"),
            file_name="template_url.csv",
            mime="text/csv",
            help="Unduh template format CSV yang tepat untuk menginput daftar URL."
        )

        st.markdown("---")

        batch_input_method = st.radio("Pilih Metode Input URL Massal:", ["Tempel Daftar URL (Teks Multi-Baris)", "Unggah Berkas CSV"], horizontal=True)

        urls_to_scan = []

        if batch_input_method == "Tempel Daftar URL (Teks Multi-Baris)":
            default_batch_urls = """https://www.google.com
https://www.wikipedia.org/wiki/Keamanan_komputer
http://192.168.10.5/secure-login/verify.php
http://paypal-secure-update.example.com/login
http://bit.ly/claim-bank-bonus-now
http://xn--pypal-4ve.com/account-update
http://archive.org/web/"""
            raw_text = st.text_area("Masukkan daftar URL (satu URL per baris):", value=default_batch_urls, height=180)
            if raw_text:
                urls_to_scan = [line.strip() for line in raw_text.splitlines() if line.strip()]
        else:
            uploaded_file = st.file_uploader("Unggah berkas CSV (harus memuat kolom 'url'):", type=["csv"])
            if uploaded_file is not None:
                try:
                    df_up = pd.read_csv(uploaded_file)
                    if 'url' in df_up.columns:
                        urls_to_scan = df_up['url'].dropna().astype(str).str.strip().tolist()
                    else:
                        st.error("Kolom 'url' tidak ditemukan dalam file CSV! Harap unduh template di atas.")
                except Exception as e:
                    st.error(f"Gagal membaca file CSV: {e}")

        if st.button("🚀 Eksekusi Pemindaian Massal", type="primary"):
            if not urls_to_scan:
                st.warning("⚠️ Tidak ada URL yang valid untuk dipindai.")
            else:
                with st.spinner(f"Memindai {len(urls_to_scan)} URL..."):
                    t_batch_start = time.time()
                    batch_results = []
                    thr_b = calibrated_threshold

                    for u in urls_to_scan:
                        vec = ekstrak_satu(u)
                        is_wl, w_dom, w_org = check_domain_whitelist(u) if enable_whitelist else (False, None, None)
                        batch_results.append({
                            "url": u,
                            "vec": vec,
                            "is_wl": is_wl,
                            "w_dom": w_dom,
                            "w_org": w_org
                        })

                    # Bulk inference
                    matrix = [b["vec"] for b in batch_results]
                    df_features_batch = pd.DataFrame(matrix, columns=model_artefak["fitur"], dtype="float32")
                    probs = model_artefak["model"].predict_proba(df_features_batch)[:, 1]

                    t_batch_elapsed = (time.time() - t_batch_start) * 1000

                    final_records = []
                    phish_count = 0
                    safe_count = 0

                    for i, b in enumerate(batch_results):
                        p_val = float(probs[i])
                        is_trusted = b["is_wl"]

                        # Label status bersih tanpa karakter aneh / emoji rusak di Excel
                        if is_trusted:
                            status = "AMAN (WHITELIST)"
                            safe_count += 1
                        elif p_val >= thr_b:
                            status = "PHISHING"
                            phish_count += 1
                        elif p_val >= (thr_b / 2):
                            status = "WASPADA"
                            safe_count += 1
                        else:
                            status = "AMAN"
                            safe_count += 1

                        final_records.append({
                            "No": i + 1,
                            "Target URL": b["url"],
                            "Probabilitas Phishing": f"{p_val * 100:.1f}%",
                            "Status Deteksi": status,
                            "Layer Whitelist": b["w_org"] if is_trusted else "Non-Whitelist"
                        })

                    df_batch_res = pd.DataFrame(final_records)

                    st.success(f"Pemindaian {len(urls_to_scan)} URL selesai dalam {t_batch_elapsed:.1f} ms ({t_batch_elapsed/len(urls_to_scan):.2f} ms/URL)!")

                    c_b1, c_b2, c_b3 = st.columns(3)
                    c_b1.metric("Total URL Dipindai", len(urls_to_scan))
                    c_b2.metric("Terdeteksi Phishing", phish_count, f"{phish_count/len(urls_to_scan)*100:.1f}%")
                    c_b3.metric("Tautan Aman / Whitelist", safe_count, f"{safe_count/len(urls_to_scan)*100:.1f}%")

                    st.dataframe(df_batch_res, use_container_width=True, hide_index=True)

                    # Export CSV bersih dengan encoding UTF-8 dengan BOM agar dibuka di Excel Windows rapi tanpa rusak
                    csv_buffer = io.StringIO()
                    df_batch_res.to_csv(csv_buffer, index=False)
                    st.download_button(
                        label="📥 Unduh Hasil Pemindaian Massal (.csv)",
                        data=csv_buffer.getvalue().encode("utf-8-sig"),
                        file_name=f"Batch_Scan_Results_{int(time.time())}.csv",
                        mime="text/csv"
                    )

    # --------------------------------------------------------------------------
    # TAB 4: ANALISIS MODEL ML & DATA LATIH (VISUALISASI EMPIRIS NOTEBOOK)
    # --------------------------------------------------------------------------
    with tab_analytics:
        st.title("Visualisasi Data Latih & Evaluasi Model Machine Learning")
        st.write("Audit komprehensif dataset, benchmark validasi silang (GroupKFold), dan ketahanan model terhadap bias.")

        # 1. Ringkasan Dataset Alami
        st.subheader("1. Karakteristik & Distribusi Dataset Alami (504.932 URL)")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total URL Unik", "504,932", "0 Duplikasi & 0 Konflik")
        c2.metric("Train Set (80% per Domain)", "408,901", "33.1% Phishing")
        c3.metric("Test Set (20% per Domain)", "96,031", "25.0% Phishing")
        c4.metric("Kebocoran Domain (Leakage)", "0 Domain", "100% Disjoint (GroupShuffleSplit)")

        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            fig_donut = go.Figure(data=[go.Pie(
                labels=['Legitimate (Aman - 68.5%)', 'Phishing (Bahaya - 31.5%)'],
                values=[345738, 159194],
                hole=.4,
                marker_colors=['#22C55E', '#EF4444']
            )])
            fig_donut.update_layout(
                title_text="Distribusi Kelas Alami (345.738 Legitimate vs 159.194 Phishing)",
                margin=dict(t=40, b=0, l=0, r=0)
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_chart2:
            fi_data = {
                "has_https": 0.5809,
                "has_www": 0.0634,
                "path_len": 0.0024,
                "tld_len": 0.0014,
                "n_keyword": 0.0009,
                "n_slash": 0.0005,
                "host_is_ip": 0.0004,
                "host_hyphens": 0.0003,
                "longest_label": 0.0003,
                "path_depth": 0.0002,
                "url_len": 0.0002,
                "special_ratio": 0.0002
            }
            fi_df = pd.DataFrame(list(fi_data.items()), columns=["Fitur", "Penurunan PR-AUC"]).sort_values("Penurunan PR-AUC", ascending=True)
            fig_fi = px.bar(
                fi_df,
                x="Penurunan PR-AUC",
                y="Fitur",
                orientation="h",
                color="Penurunan PR-AUC",
                color_continuous_scale="Blues",
                title="12 Fitur Terpenting (Permutation Importance pada Test Set)"
            )
            fig_fi.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_fi, use_container_width=True)

        st.markdown("---")

        # 2. Confusion Matrix Test Set
        st.subheader("2. Matriks Konfusi & Kinerja pada Test Set Independen (96.031 URL)")
        st.caption("Hasil pengujian akhir pada ambang operasional 0.880 dengan pembagian data per domain (Zero Domain Leakage):")

        c_cm1, c_cm2 = st.columns([1.2, 1])
        with c_cm1:
            cm_z = [[71970, 59], [544, 23458]]
            cm_x = ['Prediksi Legitimate', 'Prediksi Phishing']
            cm_y = ['Aktual Legitimate', 'Aktual Phishing']
            cm_annotations = [
                [f"True Negative (TN)<br><b>{71970:,}</b> (99.9%)", f"False Positive (FP)<br><b>{59:,}</b> (0.1%)"],
                [f"False Negative (FN)<br><b>{544:,}</b> (2.3%)", f"True Positive (TP)<br><b>{23458:,}</b> (97.7%)"]
            ]
            fig_cm = go.Figure(data=go.Heatmap(
                z=cm_z, x=cm_x, y=cm_y,
                colorscale='Blues',
                text=cm_annotations,
                texttemplate="%{text}",
                textfont={"size": 14},
                showscale=False
            ))
            fig_cm.update_layout(
                title="Confusion Matrix Test Set (Ambang = 0.880)",
                yaxis=dict(autorange="reversed"),
                height=320,
                margin=dict(t=40, b=0, l=0, r=0)
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with c_cm2:
            st.markdown("""
            <div class="metric-box">
                <b>📊 Ringkasan Metrik Test Set (Ambang 0.880):</b><br><br>
                • <b>PR-AUC:</b> <code>0.9966</code> (~0.997)<br>
                • <b>ROC-AUC:</b> <code>0.9976</code> (~0.998)<br>
                • <b>Precision:</b> <code>0.9975</code> (99.75%)<br>
                • <b>Recall:</b> <code>0.9773</code> (97.73% target &ge; 98%)<br>
                • <b>F1-Score:</b> <code>0.9873</code> (98.73%)<br>
                • <b>Akurasi Keseluruhan:</b> <code>0.9937</code> (99.37%)<br><br>
                <i>Phishing lolos (FN) hanya 544 dari 24.002 data.<br>
                URL aman terblokir (FP) hanya 59 dari 72.029 data.</i>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # 3. Tabel Benchmark GroupKFold
        st.subheader("3. Tabel Benchmark Kinerja Model (GroupKFold 3 Lipatan pada 100.000 Sampel)")
        bench_data = [
            {"Model": "TF-IDF karakter + LogReg", "PR-AUC": 0.9982, "ROC-AUC": 0.9986, "F1@0.5": 0.9909, "Recall@0.5": 0.9871, "Std PR-AUC": 0.0004, "Waktu (dtk)": 32.89},
            {"Model": "HistGradientBoosting (Winner)", "PR-AUC": 0.9975, "ROC-AUC": 0.9980, "F1@0.5": 0.9910, "Recall@0.5": 0.9871, "Std PR-AUC": 0.0005, "Waktu (dtk)": 6.16},
            {"Model": "Extra Trees Classifier", "PR-AUC": 0.9974, "ROC-AUC": 0.9979, "F1@0.5": 0.9911, "Recall@0.5": 0.9875, "Std PR-AUC": 0.0004, "Waktu (dtk)": 9.32},
            {"Model": "Random Forest", "PR-AUC": 0.9972, "ROC-AUC": 0.9978, "F1@0.5": 0.9910, "Recall@0.5": 0.9878, "Std PR-AUC": 0.0005, "Waktu (dtk)": 17.41},
            {"Model": "Logistic Regression (Linear)", "PR-AUC": 0.9957, "ROC-AUC": 0.9964, "F1@0.5": 0.9831, "Recall@0.5": 0.9722, "Std PR-AUC": 0.0005, "Waktu (dtk)": 0.40},
            {"Model": "Baseline k-NN (Eksperimen Awal)", "PR-AUC": 0.6672, "ROC-AUC": 0.7410, "F1@0.5": 0.6631, "Recall@0.5": 0.6710, "Std PR-AUC": 0.0120, "Waktu (dtk)": 12.50}
        ]
        bench_df = pd.DataFrame(bench_data)
        st.dataframe(
            bench_df.style.highlight_max(subset=["PR-AUC", "ROC-AUC", "F1@0.5", "Recall@0.5"], color="rgba(34, 197, 94, 0.25)")
                         .highlight_min(subset=["Waktu (dtk)"], color="rgba(59, 130, 246, 0.25)"),
            use_container_width=True,
            hide_index=True
        )

        # 4. Base Rate Fallacy
        st.markdown("---")
        st.subheader("4. Simulasi Prevalensi Dunia Nyata & Teorema Bayes (Base Rate Fallacy)")
        prev_data = [
            {"Prevalensi Phishing di Jaringan": "50% (Skenario Lab)", "Precision": "99.9%", "Peringatan Palsu (False Alarm)": "0%", "Tingkat Kepercayaan": "Sangat Tinggi"},
            {"Prevalensi Phishing di Jaringan": "30% (Kondisi Dataset)", "Precision": "99.8%", "Peringatan Palsu (False Alarm)": "0%", "Tingkat Kepercayaan": "Sangat Tinggi"},
            {"Prevalensi Phishing di Jaringan": "10% (Gateway Korporat)", "Precision": "99.3%", "Peringatan Palsu (False Alarm)": "1%", "Tingkat Kepercayaan": "Tinggi"},
            {"Prevalensi Phishing di Jaringan": "5% (Trafik Email Umum)", "Precision": "98.4%", "Peringatan Palsu (False Alarm)": "2%", "Tingkat Kepercayaan": "Tinggi"},
            {"Prevalensi Phishing di Jaringan": "1% (Lalu Lintas Web Luas)", "Precision": "92.3%", "Peringatan Palsu (False Alarm)": "8%", "Tingkat Kepercayaan": "Cukup (Perlu Whitelist)"}
        ]
        st.dataframe(pd.DataFrame(prev_data), use_container_width=True, hide_index=True)

        # 5. Studi Ablasi
        st.markdown("---")
        st.subheader("5. Studi Ablasi: Uji Ketergantungan terhadap Fitur Jalan Pintas (`has_https` & `has_www`)")
        abl_data = [
            {"Varian Model": "Semua Fitur (31 Fitur Leksikal Penuh)", "PR-AUC": 0.9966, "ROC-AUC": 0.9976, "Precision": 0.9975, "Recall": 0.9773, "F1-Score": 0.9873},
            {"Varian Model": "HANYA has_https & has_www (2 Fitur)", "PR-AUC": 0.9852, "ROC-AUC": 0.9905, "Precision": 0.9949, "Recall": 0.9813, "F1-Score": 0.9881},
            {"Varian Model": "Tanpa has_https & has_www (29 Fitur Murni)", "PR-AUC": 0.9715, "ROC-AUC": 0.9848, "Precision": 0.9936, "Recall": 0.7586, "F1-Score": 0.8603}
        ]
        st.dataframe(pd.DataFrame(abl_data), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # TAB 5: VALIDASI PENGUJIAN (QA), WHITELIST & CIA TRIAD
    # --------------------------------------------------------------------------
    with tab_qa_whitelist:
        st.title("🧪 Dokumentasi Pengujian Kasus (QA), Basis Data Whitelist & CIA Triad")

        # 1. QA Testing 12 Kasus
        st.subheader("1. Dokumentasi Pengujian Sistem (12 Skenario QA - 100% PASS)")
        qa_cases = [
            {"No": 1, "Kategori": "Legitimate (Whitelist)", "Contoh URL": "https://www.google.com", "Ekspektasi": "Aman", "Hasil Prediksi": "Aman (p = 0.000)", "Status QA": "✅ PASS", "Catatan": "Terverifikasi layer Whitelist & fitur leksikal normal"},
            {"No": 2, "Kategori": "Legitimate (Ensiklopedia)", "Contoh URL": "https://www.wikipedia.org/wiki/Keamanan_komputer", "Ekspektasi": "Aman", "Hasil Prediksi": "Aman (p = 0.001)", "Status QA": "✅ PASS", "Catatan": "Domain edukasi resmi ber-HTTPS dan struktur path normal"},
            {"No": 3, "Kategori": "Legitimate (Developer)", "Contoh URL": "https://www.github.com/torvalds/linux", "Ekspektasi": "Aman", "Hasil Prediksi": "Aman (p = 0.002)", "Status QA": "✅ PASS", "Catatan": "Platform developer terpercaya, terdaftar di whitelist"},
            {"No": 4, "Kategori": "Phishing IP Langsung", "Contoh URL": "http://192.168.10.5/secure-login/verify.php", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 1.000)", "Status QA": "✅ PASS", "Catatan": "Host berupa IP mentah + kata kunci sensitif login/verify"},
            {"No": 5, "Kategori": "Phishing Typosquatting", "Contoh URL": "http://paypal-secure-update.example.com/login", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 0.998)", "Status QA": "✅ PASS", "Catatan": "Banyak tanda hubung hostname + target kata kunci perbankan"},
            {"No": 6, "Kategori": "Phishing URL Shortener", "Contoh URL": "http://bit.ly/claim-bank-bonus-now", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 0.996)", "Status QA": "✅ PASS", "Catatan": "Deteksi pemendek tautan bit.ly & kata bonus finansial"},
            {"No": 7, "Kategori": "Phishing Subdomain Bertingkat", "Contoh URL": "http://bca.klik.login.account-verification.xyz/auth", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 1.000)", "Status QA": "✅ PASS", "Catatan": "Subdomain 4 level + TLD berisiko .xyz + impersonasi brand"},
            {"No": 8, "Kategori": "Phishing Evasion Simbol @", "Contoh URL": "http://www.google.com@phishing-target.ru/signin", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 1.000)", "Status QA": "✅ PASS", "Catatan": "Pengaburan host sebenarnya menggunakan simbol @"},
            {"No": 9, "Kategori": "Phishing IDN Homograph", "Contoh URL": "http://xn--pypal-4ve.com/account-update", "Ekspektasi": "Phishing", "Hasil Prediksi": "Phishing (p = 0.994)", "Status QA": "✅ PASS", "Catatan": "Domain Punycode xn-- menyerupai paypal secara visual"},
            {"No": 10, "Kategori": "Legitimate Non-HTTPS Lama", "Contoh URL": "http://archive.org/web/", "Ekspektasi": "Aman (Waspada)", "Hasil Prediksi": "Aman (p = 0.240)", "Status QA": "✅ PASS", "Catatan": "HTTP murni tanpa HTTPS, masuk rentang waspada tetapi di bawah threshold"},
            {"No": 11, "Kategori": "Error Handling: Skema Saja", "Contoh URL": "https://", "Ekspektasi": "Validasi Gagal", "Hasil Prediksi": "Format Invalid (Ditolak)", "Status QA": "✅ PASS", "Catatan": "Sistem menolak string URL tidak lengkap secara elegan"},
            {"No": 12, "Kategori": "Error Handling: Teks Acak", "Contoh URL": "random_text_without_dot", "Ekspektasi": "Validasi Gagal", "Hasil Prediksi": "Format Invalid (Ditolak)", "Status QA": "✅ PASS", "Catatan": "Sistem mewajibkan format domain/URL valid sebelum prediksi"}
        ]
        st.dataframe(pd.DataFrame(qa_cases), use_container_width=True, hide_index=True)

        st.markdown("---")

        # 2. Basis Data Whitelist
        st.subheader("2. Basis Data Domain Terpercaya (Trusted Whitelist)")
        df_wl = pd.DataFrame(whitelist_entries)

        col_w1, col_w2, col_w3 = st.columns(3)
        col_w1.metric("Total Domain Terverifikasi", f"{len(df_wl)} Domain")
        col_w2.metric("Kategori Layanan", f"{df_wl['category'].nunique()} Kategori")
        col_w3.metric("Standar Keamanan", "TLS 1.3 / EV SSL")

        search_query = st.text_input("🔎 Cari Domain dalam Basis Data Whitelist:", placeholder="Contoh: google, bca, wikipedia, github")
        if search_query:
            filtered_df = df_wl[
                df_wl['domain'].str.contains(search_query, case=False) |
                df_wl['organization'].str.contains(search_query, case=False) |
                df_wl['category'].str.contains(search_query, case=False)
            ]
        else:
            filtered_df = df_wl

        st.dataframe(
            filtered_df.rename(columns={
                "domain": "Nama Domain Resmi",
                "organization": "Entitas / Organisasi Pemilik",
                "category": "Kategori Layanan",
                "status": "Status Verifikasi",
                "ssl_default": "Enkripsi Default"
            }),
            use_container_width=True,
            hide_index=True
        )

        st.markdown("---")

        # 3. Edukasi CIA Triad
        st.subheader("3. Edukasi Keamanan Data & Relevansi CIA Triad")
        col_cia1, col_cia2, col_cia3 = st.columns(3)
        with col_cia1:
            st.markdown("""
            <div class="metric-box" style="border-left-color: #EF4444;">
                <h4 style="color: #EF4444; margin-top: 0;">1. Kerahasiaan (Confidentiality)</h4>
                <p>Pencegahan pencurian kredensial akun, kode OTP, dan PIN perbankan sebelum pengguna menyerahkan data rahasia.</p>
            </div>
            """, unsafe_allow_html=True)
        with col_cia2:
            st.markdown("""
            <div class="metric-box" style="border-left-color: #F59E0B;">
                <h4 style="color: #F59E0B; margin-top: 0;">2. Integritas (Integrity)</h4>
                <p>Mencegah manipulasi alur formulir transaksi dan penyusupan muatan skrip eksploit lokal.</p>
            </div>
            """, unsafe_allow_html=True)
        with col_cia3:
            st.markdown("""
            <div class="metric-box" style="border-left-color: #3B82F6;">
                <h4 style="color: #3B82F6; margin-top: 0;">3. Ketersediaan (Availability)</h4>
                <p>Layer Whitelist reputasi menjamin domain sah tidak terblokir salah (*False Positive*), menjaga ketersediaan layanan publik.</p>
            </div>
            """, unsafe_allow_html=True)
