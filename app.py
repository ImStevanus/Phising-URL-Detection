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

# Inisialisasi State Halaman Utama (Welcome vs App)
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "welcome"

# ==============================================================================
# 4. SIDEBAR: NAVIGASI, IDENTITAS & KONTROL SISTEM
# ==============================================================================
with st.sidebar:
    st.title("🛡️ Phishing Shield")
    st.caption("Intelligent Web Threat Defense • HistGradientBoosting")
    st.markdown("---")

    # Kontrol Navigasi Halaman Utama
    st.subheader("🧭 Navigasi Halaman")
    nav_index = 0 if st.session_state["current_page"] == "welcome" else 1
    selected_nav = st.radio(
        "Pilih Halaman:",
        ["🏠 Halaman Depan (Banner)", "🚀 Aplikasi Deteksi (Dashboard)"],
        index=nav_index,
        label_visibility="collapsed"
    )
    target_page = "welcome" if "Halaman Depan" in selected_nav else "app"
    if target_page != st.session_state["current_page"]:
        st.session_state["current_page"] = target_page
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

    calibrated_thr = float(model_artefak.get("threshold", 0.880))
    target_rec = float(model_artefak.get("target_recall", 0.98))

    thr_slider = st.slider(
        "Ambang Batas Klasifikasi (Threshold):",
        min_value=0.10,
        max_value=0.98,
        value=calibrated_thr,
        step=0.01,
        help=f"Ambang default terkalibrasi adalah {calibrated_thr:.3f} (menjamin recall {target_rec*100:.0f}% pada OOF data latih)."
    )

    if thr_slider == calibrated_thr:
        st.success(f"🎯 Ambang Terkalibrasi: `{thr_slider:.3f}` (Recall: {target_rec * 100:.0f}%)")
    else:
        st.warning(f"⚠️ Ambang Kustom: `{thr_slider:.3f}` (Bawaan: `{calibrated_thr:.3f}`)")

    st.markdown("---")
    st.subheader("🛡️ Arsitektur Pertahanan (Hybrid)")
    enable_whitelist = st.toggle(
        "Aktifkan Whitelist Domain (Defense-in-Depth)",
        value=True,
        help="Memadukan reputasi domain resmi bersama model ML leksikal untuk mengeliminasi False Positive pada situs populer."
    )

    if enable_whitelist:
        st.caption("🟢 **Mode Hybrid Aktif:** Domain resmi terverifikasi diproteksi via Trusted Whitelist layer.")
    else:
        st.caption("⚪ **Mode Murni ML Aktif:** Deteksi 100% bergantung pada model fitur leksikal.")

    st.markdown("---")
    st.markdown("📌 **Fokus Utama (CIA Triad):**")
    st.caption("Melindungi **Confidentiality** dari pencurian kredensial, **Integrity** dari manipulasi form, dan **Availability** dari pemblokiran salah.")

# ==============================================================================
# 5. HALAMAN UTAMA (KONDISIONAL: WELCOMING PAGE VS MAIN DASHBOARD)
# ==============================================================================

# ------------------------------------------------------------------------------
# 5A. WELCOMING PAGE (HALAMAN DEPAN DENGAN BANNER & TOMBOL MULAI DI TENGAH)
# ------------------------------------------------------------------------------
if st.session_state["current_page"] == "welcome":
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

    # Alur Kerja 3-Langkah
    st.subheader("🔄 Alur Kerja Sistem Deteksi (3-Stage Defense Pipeline)")
    c_step1, c_step2, c_step3 = st.columns(3)
    with c_step1:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #6366F1;">
            <h4 style="color: #6366F1; margin-top: 0;">Langkah 1: Ekstraksi Pasif 31 Fitur</h4>
            <p>URL diurai secara murni dari struktur teks tanpa melakukan koneksi HTTP ke server tujuan. Parameter seperti entropi Shannon, kata kunci sensitif, tanda hubung host, dan ekstensi file diekstrak secara instan.</p>
        </div>
        """, unsafe_allow_html=True)
    with c_step2:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #3B82F6;">
            <h4 style="color: #3B82F6; margin-top: 0;">Langkah 2: Layer 1 Whitelist Verification</h4>
            <p>Domain dicocokkan dengan basis data reputasi entitas resmi (Google, Wikipedia, GitHub, BCA, Mandiri, dll.). Jika terdaftar dan valid, tautan otomatis dilindungi dari salah blokir demi menjaga <b>Availability</b>.</p>
        </div>
        """, unsafe_allow_html=True)
    with c_step3:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #EF4444;">
            <h4 style="color: #EF4444; margin-top: 0;">Langkah 3: Layer 2 Machine Learning Triage</h4>
            <p>Algoritma <b>HistGradientBoosting</b> mengevaluasi probabilitas bahaya terhadap ambang terkalibrasi (<code>0.880</code>). Sistem memberikan skoring risiko 3 tingkat dan rekomendasi mitigasi CIA Triad.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Wawasan Ancaman & CIA Triad
    col_threat1, col_threat2 = st.columns([1.2, 1])
    with col_threat1:
        st.subheader("⚠️ Fenomena Kejahatan Siber & Modus Phishing Modern")
        st.markdown("""
        - **Penyalahgunaan Sertifikat SSL Gratis (Let's Encrypt):** Penyerang kini lazim memasang gembok hijau HTTPS pada situs phishing untuk mengelabui korban. Sistem ini membuktikan bahwa 29 fitur leksikal lainnya mampu mendeteksi phishing meskipun ber-HTTPS.
        - **Typosquatting & IDN Homograph:** Penggunaan huruf visual serupa (*punycode* `xn--`) atau penambahan tanda hubung (misal: `paypal-security-update.com`) untuk meniru brand resmi.
        - **Penyembunyian Domain via Shortener:** Memanfaatkan layanan `bit.ly` atau `tinyurl` untuk menyembunyikan alamat server palsu.
        """)
    with col_threat2:
        st.subheader("🛡️ Keterkaitan dengan CIA Triad")
        st.markdown("""
        - 🔴 **Kerahasiaan (Confidentiality):** Mencegah pencurian kredensial akun, password, PIN, dan kode OTP perbankan.
        - 🟡 **Integritas (Integrity):** Melindungi pengguna dari manipulasi alur sesi dan injeksi muatan skrip eksploit.
        - 🟢 **Ketersediaan (Availability):** Whitelist reputasi menjamin domain sah tidak terblokir (*zero disruption*).
        """)

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
        "🎛️ Kustomisasi Checklist Fitur",
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
                thr = float(thr_slider)

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
        Fitur ini memungkinkan Anda **mengaktifkan atau menonaktifkan fitur leksikal tertentu** guna menguji sensitivitas model:
        - *Bagaimana jika fitur `has_https` dan `has_www` dimatikan? Apakah model tetap mampu mendeteksi phishing modern ber-SSL?*
        - *Bagaimana jika indikator kata kunci sensitif diabaikan?*
        Ketika fitur dinonaktifkan, nilainya akan **dinetralkan ke baseline aman** (*feature masking*).
        """)

        st.markdown("---")

        # Inisialisasi State Checkbox untuk setiap fitur
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

        # Evaluasi Uji Coba Dampak Masking Fitur
        st.markdown("---")
        st.subheader("🧪 Uji Coba Dampak Masking Fitur pada URL Tertentu")

        test_abl_url = st.text_input(
            "Masukkan URL untuk diuji perbandingannya:",
            value="http://paypal-secure-update.example.com/webscr/login?confirm=1",
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

            col_comp1, col_comp2, col_comp3 = st.columns(3)
            with col_comp1:
                st.metric("Skor Model Penuh (31 Fitur)", f"{prob_full * 100:.1f}%", "100% Fitur Aktif")
            with col_comp2:
                st.metric("Skor Model Masked (Kustom)", f"{prob_masked * 100:.1f}%", f"{len(active_now)} Fitur Aktif")
            with col_comp3:
                delta_val = (prob_masked - prob_full) * 100
                st.metric("Pergeseran Probabilitas (Shift)", f"{delta_val:+.1f}%", "Dampak Masking")

            if len(active_now) < 31:
                disabled_feats = [f for f in FITUR if f not in active_now]
                st.caption(f"Fitur yang dinonaktifkan: {', '.join(disabled_feats)}")

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
                    thr_b = float(thr_slider)

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
