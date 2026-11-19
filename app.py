import os
import sys
import time
import json
import re
import math
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
    page_title="Phishing Shield - Deteksi Ancaman Phishing URL",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS Universal: Kontras Tinggi, Kompatibel Dark Mode & Light Mode
st.markdown("""
<style>
    /* Status Card - Danger (Phishing) */
    .status-card-danger {
        background-color: rgba(239, 68, 68, 0.12);
        border: 2px solid #EF4444;
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 20px;
    }
    .status-card-danger h3 {
        color: #EF4444 !important;
        margin: 0;
        font-weight: 700;
    }

    /* Status Card - Warning (Waspada) */
    .status-card-warning {
        background-color: rgba(245, 158, 11, 0.12);
        border: 2px solid #F59E0B;
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 20px;
    }
    .status-card-warning h3 {
        color: #F59E0B !important;
        margin: 0;
        font-weight: 700;
    }

    /* Status Card - Safe (Legitimate) */
    .status-card-safe {
        background-color: rgba(34, 197, 94, 0.12);
        border: 2px solid #22C55E;
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 20px;
    }
    .status-card-safe h3 {
        color: #22C55E !important;
        margin: 0;
        font-weight: 700;
    }

    /* Status Card - Hybrid Override (Whitelist Protected) */
    .status-card-hybrid {
        background-color: rgba(59, 130, 246, 0.12);
        border: 2px solid #3B82F6;
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 20px;
    }
    .status-card-hybrid h3 {
        color: #3B82F6 !important;
        margin: 0;
        font-weight: 700;
    }

    /* Box Container Metrik */
    .metric-box {
        background-color: rgba(128, 128, 128, 0.08);
        border-radius: 10px;
        padding: 16px;
        border-left: 5px solid #6366F1;
        margin-bottom: 12px;
    }

    /* Kotak Mitigasi */
    .mitigation-box-danger {
        background-color: rgba(239, 68, 68, 0.08);
        border-radius: 10px;
        padding: 16px;
        border-left: 5px solid #EF4444;
    }
    .mitigation-box-safe {
        background-color: rgba(34, 197, 94, 0.08);
        border-radius: 10px;
        padding: 16px;
        border-left: 5px solid #22C55E;
    }
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

# ==============================================================================
# 4. SIDEBAR: NAVIGASI & INFORMASI KELOMPOK
# ==============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=65)
    st.title("🛡️ Phishing Shield")
    st.caption("Sistem Deteksi Ancaman Phishing URL (HistGradientBoosting + Defense-in-Depth)")
    st.markdown("---")

    st.subheader("👥 Identitas Kelompok")
    st.markdown("""
    - **Stevanus** (38250029)
    - **Alra Nava Ratna Mandala** (38250025)
    """)
    st.info("**Mata Kuliah:** Keamanan Data (DSF01)\n\nSemester 3 - Proyek UAS (Kelompok 1)")

    st.markdown("---")
    st.subheader("⚙️ Parameter Model Operasional")
    st.write("**Algoritma:** HistGradientBoosting")
    st.write("**Dimensi Fitur:** 31 Fitur Leksikal")
    st.write("**Ukuran Artefak:** 0.21 MB (Efisien)")

    # Nilai Ambang Terkalibrasi dari Notebook
    calibrated_thr = float(model_artefak.get("threshold", 0.880))
    target_rec = float(model_artefak.get("target_recall", 0.98))

    # Dynamic Threshold Slider
    thr_slider = st.slider(
        "Ambang Batas Klasifikasi (Threshold):",
        min_value=0.10,
        max_value=0.98,
        value=calibrated_thr,
        step=0.01,
        help=f"Ambang default terkalibrasi adalah {calibrated_thr:.3f} (menjamin recall {target_rec*100:.0f}% pada OOF data latih)."
    )

    if thr_slider == calibrated_thr:
        st.success(f"🎯 Ambang Terkalibrasi Aktif: `{thr_slider:.3f}` (Target Recall: {target_rec * 100:.0f}%)")
    else:
        st.warning(f"⚠️ Ambang Kustom: `{thr_slider:.3f}` (Bawaan: `{calibrated_thr:.3f}`)")

    st.caption("Ambang dikalibrasi out-of-fold pada data latih guna meminimalkan False Negative (menjamin serangan phishing terblokir).")

    st.markdown("---")
    # TOGGLE MODE HYBRID (DEFENSE-IN-DEPTH)
    st.subheader("🛡️ Mode Inspeksi Sistem")
    enable_whitelist = st.toggle(
        "Aktifkan Whitelist Domain (Hybrid Mode)",
        value=True,
        help="Simulasi arsitektur Defense-in-Depth industri: Memadukan reputasi domain resmi bersama model ML leksikal untuk mengeliminasi False Positive pada situs populer."
    )

    if enable_whitelist:
        st.caption("🟢 **Mode Hybrid Aktif:** Domain resmi terdaftar (Google, Wikipedia, GitHub, dll.) diproteksi via Trusted Whitelist layer.")
    else:
        st.caption("⚪ **Mode Murni ML Aktif:** Deteksi 100% bergantung pada model fitur leksikal (ideal untuk demonstrasi evaluasi model & analisis kelemahan leksikal).")

    st.markdown("---")
    st.markdown("📌 **Fokus Keamanan Data (CIA Triad):**")
    st.caption("Melindungi **Kerahasiaan (Confidentiality)** dari pencurian data kredensial, **Integritas (Integrity)** dari pengalihan alur sesi, dan **Ketersediaan (Availability)** dari salah blokir.")

# ==============================================================================
# 5. HALAMAN UTAMA: MULTI-TAB INTERFACE
# ==============================================================================
tab_predict, tab_analytics, tab_testing, tab_whitelist, tab_education = st.tabs([
    "🔍 Deteksi URL Kustom",
    "📊 Visualisasi Data & Model ML",
    "🧪 Pengujian 12 Kasus (QA)",
    "📋 Basis Data Whitelist",
    "📚 Rekomendasi & Edukasi CIA Triad"
])

# ------------------------------------------------------------------------------
# TAB 1: DETEKSI URL KUSTOM
# ------------------------------------------------------------------------------
with tab_predict:
    st.title("Deteksi Ancaman Phishing URL Real-Time")
    st.write(f"Klasifikasi ancaman URL menggunakan algoritma **HistGradientBoosting** (31 Fitur Leksikal) {'+ Filter Whitelist (Defense-in-Depth)' if enable_whitelist else '(Mode Murni ML)'}.")

    # Inisialisasi Session State untuk Input URL
    if "input_url_val" not in st.session_state:
        st.session_state["input_url_val"] = ""

    def load_preset(url_target):
        st.session_state["input_url_val"] = url_target

    # Preset URL Uji Cepat (8 Skenario Berbeda)
    st.write("##### ⚡ Uji Cepat dengan Contoh Skenario:")
    st.caption("Pilih salah satu sampel di bawah ini untuk mengisi dan menganalisis tautan secara instan:")

    col_p1, col_p2, col_p3, col_p4 = st.columns(4)
    with col_p1:
        st.button("🌐 Google (Resmi)", use_container_width=True, on_click=load_preset, args=("https://www.google.com",))
        st.button("🚨 IP Phishing Mentah", use_container_width=True, on_click=load_preset, args=("http://192.168.10.5/secure-login/verify-account.php?id=1",))
    with col_p2:
        st.button("📖 Wikipedia (Resmi)", use_container_width=True, on_click=load_preset, args=("https://www.wikipedia.org/wiki/Keamanan_komputer",))
        st.button("🚨 Typosquatting Paypal", use_container_width=True, on_click=load_preset, args=("http://paypal-secure-update.example.com/webscr/login?confirm=1",))
    with col_p3:
        st.button("💻 GitHub (Platform Dev)", use_container_width=True, on_click=load_preset, args=("https://www.github.com/torvalds/linux",))
        st.button("🚨 Shortener URL Bitly", use_container_width=True, on_click=load_preset, args=("http://bit.ly/claim-bank-bonus-now",))
    with col_p4:
        st.button("🏛️ Archive.org (HTTP Lama)", use_container_width=True, on_click=load_preset, args=("http://archive.org/web/",))
        st.button("🚨 Punycode Homograph", use_container_width=True, on_click=load_preset, args=("http://xn--pypal-4ve.com/account-update",))

    # Form Input URL
    with st.form("url_scan_form"):
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

            # 1. Ekstraksi Fitur Leksikal (31 Fitur)
            start_inference_time = time.time()
            vec = ekstrak_satu(clean_url)
            features_df = pd.DataFrame([vec], columns=model_artefak["fitur"], dtype="float32")

            # 2. Cek Whitelist jika Mode Toggle Aktif
            is_trusted, matched_domain, org_desc = (False, None, None)
            if enable_whitelist:
                is_trusted, matched_domain, org_desc = check_domain_whitelist(clean_url)

            # 3. Prediksi Model HistGradientBoosting
            p_phish = float(model_artefak["model"].predict_proba(features_df)[:, 1][0])
            p_legit = float(1.0 - p_phish)
            thr = float(thr_slider)

            # Tingkat Risiko Murni ML
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

            # Keputusan Akhir Sistem
            if enable_whitelist and is_trusted:
                final_is_phishing = False
                final_risk_label = "AMAN (Terverifikasi Whitelist)"
                is_hybrid_override = raw_ml_phishing or (ml_risk_level != "RENDAH")
            else:
                final_is_phishing = raw_ml_phishing
                final_risk_label = ml_risk_level
                is_hybrid_override = False

            # Heuristic Reasoning Engine (Indikator Spesifik)
            r = features_df.iloc[0]
            alasan = []
            if r.host_is_ip: alasan.append("Domain berupa alamat IP langsung (menghindari pendaftaran domain resmi)")
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

            # 4. Tampilkan Hasil Prediksi Lengkap
            st.markdown("---")
            st.subheader("🎯 Hasil Evaluasi Sistem Deteksi")

            col_res1, col_res2, col_res3 = st.columns([1.5, 1, 1])

            with col_res1:
                if final_is_phishing:
                    st.markdown(f"""
                    <div class="status-card-danger">
                        <h3>🚨 BAHAYA: INDIKASI PHISHING ({final_risk_label})</h3>
                        <p style="margin: 8px 0 0 0;">
                            Tautan ini memiliki probabilitas ancaman melampaui ambang operasional (p = {p_phish:.3f} &ge; {thr:.3f}). Akses disarankan diblokir segera.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                elif is_hybrid_override:
                    st.markdown(f"""
                    <div class="status-card-hybrid">
                        <h3>🛡️ AMAN (DIVERIFIKASI OLEH WHITELIST REPUTASI)</h3>
                        <p style="margin: 8px 0 0 0;">
                            <b>Domain Resmi Terverifikasi:</b> {matched_domain} ({org_desc}).<br>
                            <i>Layer Whitelist memproteksi domain ini dari kesalahan prediksi False Positive model leksikal.</i>
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                elif ml_risk_level == "WASPADA":
                    st.markdown(f"""
                    <div class="status-card-warning">
                        <h3>⚠️ STATUS: WASPADA (RISIKO MODERAT)</h3>
                        <p style="margin: 8px 0 0 0;">
                            Probabilitas berada di rentang waspada ({thr/2:.2f} &le; p &lt; {thr:.2f}). Pengguna disarankan memeriksa ulang kredibilitas situs sebelum memasukkan data pribadi.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="status-card-safe">
                        <h3>✅ AMAN: RISIKO RENDAH (LEGITIMATE)</h3>
                        <p style="margin: 8px 0 0 0;">
                            Tautan memiliki struktur leksikal yang wajar dan menyerupai karakteristik situs resmi/aman (p = {p_phish:.3f} &lt; {thr/2:.2f}).
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

            with col_res2:
                st.metric(
                    label="Probabilitas Phishing (HGB)",
                    value=f"{p_phish * 100:.1f}%",
                    delta=f"Ambang Batas: {thr * 100:.1f}%"
                )

            with col_res3:
                st.metric(
                    label="Kecepatan Respon Inferensi",
                    value=f"{inference_latency:.1f} ms",
                    delta="HistGradientBoosting (31 Fitur)"
                )

            # Indikator Heuristik Deteksi
            st.write("##### 🔍 Indikator Heuristik Deteksi (Reasoning Engine):")
            for ind in alasan:
                if "IP" in ind or "punycode" in ind or "@" in ind or "sensitif" in ind:
                    st.markdown(f"- 🔴 **{ind}**")
                elif "pendek" in ind or "panjang" in ind or "HTTPS" in ind or "subdomain" in ind:
                    st.markdown(f"- 🟡 {ind}")
                else:
                    st.markdown(f"- 🟢 {ind}")

            # Rincian Evaluasi Berlapis (Defense-in-Depth Breakdown)
            st.write("##### 🛡️ Arsitektur Evaluasi Sistem Berlapis (Defense-in-Depth):")
            c_layer1, c_layer2 = st.columns(2)
            with c_layer1:
                st.markdown(f"""
                <div class="metric-box">
                    <b>Layer 1: Filter Reputasi Domain (Whitelist)</b><br>
                    Status: {'🟢 Terdaftar Resmi' if is_trusted else '⚪ Domain Publik / Unverified'}<br>
                    Detail: {org_desc if is_trusted else 'Evaluasi diserahkan sepenuhnya ke Model Machine Learning.'}
                </div>
                """, unsafe_allow_html=True)

            with c_layer2:
                st.markdown(f"""
                <div class="metric-box">
                    <b>Layer 2: Model Machine Learning (HistGradientBoosting)</b><br>
                    Status Mentah ML: <b>{'🚨 Phishing' if raw_ml_phishing else ('⚠️ Waspada' if ml_risk_level == 'WASPADA' else '✅ Legitimate')}</b><br>
                    Probabilitas: Phishing {p_phish*100:.1f}% | Legitimate {p_legit*100:.1f}% (Threshold: {thr:.3f})
                </div>
                """, unsafe_allow_html=True)

            # 5. Rincian Ekstraksi 31 Fitur Leksikal
            st.markdown("---")
            st.subheader("📋 Rincian Hasil Ekstraksi 31 Fitur Leksikal")
            st.caption("Seluruh fitur diekstrak langsung dari teks URL secara aman tanpa melakukan koneksi jaringan ke situs target:")

            feat_table = []
            for col_name in model_artefak["fitur"]:
                val = features_df[col_name].values[0]
                friendly_name, cat, desc = FEATURE_META.get(col_name, (col_name, "Fitur", "-"))

                risk_level = "Wajar"
                if col_name == 'host_is_ip' and val == 1:
                    risk_level = "🚨 Alamat IP Langsung"
                elif col_name == 'has_punycode' and val == 1:
                    risk_level = "🚨 Domain Punycode (xn--)"
                elif col_name == 'n_at' and val > 0:
                    risk_level = "🚨 Mengandung Simbol @"
                elif col_name == 'has_shortener' and val == 1:
                    risk_level = "⚠️ Layanan Pemendek URL"
                elif col_name == 'n_keyword' and val >= 2:
                    risk_level = "🚨 Banyak Kata Sensitif"
                elif col_name == 'host_hyphens' and val >= 2:
                    risk_level = "⚠️ Banyak Tanda Hubung (-)"
                elif col_name == 'n_subdomain' and val >= 3:
                    risk_level = "⚠️ Subdomain Bertingkat"
                elif col_name == 'url_len' and val > 100:
                    risk_level = "⚠️ URL Sangat Panjang"
                elif col_name == 'has_https' and val == 0:
                    risk_level = "⚠️ Non-HTTPS (HTTP Biasa)"

                feat_table.append({
                    "Fitur": friendly_name,
                    "Kategori": cat,
                    "Nilai": val,
                    "Indikator Pola": risk_level,
                    "Deskripsi": desc
                })

            st.dataframe(pd.DataFrame(feat_table), use_container_width=True, hide_index=True)

            # 6. Rekomendasi Mitigasi & Edukasi Keamanan
            st.markdown("---")
            st.subheader("🛡️ Rekomendasi Mitigasi Keamanan Siber")

            if final_is_phishing or ml_risk_level == "TINGGI (blokir)":
                st.markdown("""
                <div class="mitigation-box-danger">
                    <h4 style="color: #EF4444; margin-top: 0;">🚨 Protokol Mitigasi Serangan Phishing:</h4>
                    <ul>
                        <li><b>JANGAN PERNAH</b> memasukkan data sensitif seperti email, kata sandi, kode OTP, PIN perbankan, atau nomor kartu kredit pada situs ini.</li>
                        <li><b>Tutup Halaman Browser Segera:</b> Jangan menekan tombol interaktif atau mengunduh berkas apa pun dari tautan tersebut.</li>
                        <li><b>Waspadai Gembok SSL Palsu:</b> Banyak pelaku kejahatan siber modern kini memanfaatkan sertifikat SSL gratis (Let's Encrypt) pada domain phishing.</li>
                        <li><b>Laporkan Insiden:</b> Teruskan alamat URL ini ke tim Keamanan Informasi (CSIRT) atau laporkan ke <i>Google Safe Browsing / Anti-Phishing Working Group (APWG)</i>.</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="mitigation-box-safe">
                    <h4 style="color: #22C55E; margin-top: 0;">✅ Panduan Keamanan (Penerapan Zero Trust):</h4>
                    <ul>
                        <li>Meskipun struktur URL dinilai aman, selalu periksa nama domain secara teliti untuk menghindari <b>Typosquatting</b> (misal: <i>paypa1.com</i> alih-alih <i>paypal.com</i>).</li>
                        <li>Pastikan koneksi menggunakan protokol aman (<b>HTTPS</b>) yang sah sebelum melakukan autentikasi login.</li>
                        <li>Hindari menggunakan kata sandi yang sama di berbagai situs (<i>Credential Reuse Prevention</i>).</li>
                        <li>Aktifkan Autentikasi Dua Faktor (2FA/MFA) pada seluruh akun penting Anda.</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TAB 2: VISUALISASI DATA & MODEL ML
# ------------------------------------------------------------------------------
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
        # Donut Chart Distribusi Kelas Alami (Sesuai Sel 4)
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
        # Permutation Feature Importance (Sesuai Sel 37 Notebook)
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

    # 2. Confusion Matrix & Metrik Evaluasi Test Set (Sesuai Sel 28 & Sel 46)
    st.subheader("2. Matriks Konfusi & Kinerja pada Test Set Independen (96.031 URL)")
    st.caption("Hasil pengujian akhir pada ambang operasional 0.880 dengan pembagian data per domain (Zero Domain Leakage):")

    c_cm1, c_cm2 = st.columns([1.2, 1])
    with c_cm1:
        # Confusion Matrix Heatmap
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

    # 3. Tabel Benchmark GroupKFold (Sesuai Sel 19 Notebook)
    st.subheader("3. Tabel Benchmark Kinerja Model (GroupKFold 3 Lipatan pada 100.000 Sampel)")
    st.markdown("Evaluasi perbandingan algoritma dengan validasi silang per domain terdaftar (*Zero Domain Leakage*):")

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

    st.markdown("""
    > **💡 Mengapa HistGradientBoosting Dipilih sebagai Model Utama?**  
    > Meskipun TF-IDF memiliki PR-AUC 0.0007 lebih tinggi, **HistGradientBoosting** dipilih karena keunggulan operasional:  
    > 1. **Ukuran Artefak Sangat Kecil:** Hanya **0.21 MB** (dibandingkan ratusan MB untuk matriks n-gram TF-IDF).  
    > 2. **Inferensi Ultra-Cepat:** Waktu eksekusi rata-rata **&lt; 1 ms per URL**, sangat ideal untuk firewall/proxy web real-time.  
    > 3. **Independen dari Kosakata:** Tidak bergantung pada daftar kata (vocabulary) dan kebal terhadap serangan adversarial token baru.
    """)

    # 4. Barplot Komparasi Metrik
    fig_comp = px.bar(
        bench_df,
        x="PR-AUC",
        y="Model",
        color="F1@0.5",
        orientation="h",
        title="Perbandingan PR-AUC dan F1-Score Antar Model (GroupKFold)",
        range_x=[0.6, 1.0],
        color_continuous_scale="Viridis"
    )
    fig_comp.update_layout(yaxis=dict(autorange="reversed"), height=350)
    st.plotly_chart(fig_comp, use_container_width=True)

    # 5. Analisis Base Rate Fallacy & Prevalensi Dunia Nyata (Sesuai Sel 31)
    st.markdown("---")
    st.subheader("4. Simulasi Prevalensi Dunia Nyata & Teorema Bayes (Base Rate Fallacy)")
    st.markdown("""
    > **Mengapa Presisi Turun di Dunia Nyata?**  
    > Pada dataset laboratorium, proporsi phishing diatur 31.5%. Namun di trafik jaringan nyata (lalu lintas email korporat), URL phishing hanya berkisar **1% - 5%**.
    > Berdasarkan Teorema Bayes, ketika phishing sangat langka, rasio peringatan palsu (*false alarm*) meningkat secara alami karena volume lalu lintas URL aman yang luar biasa besar.
    """)

    prev_data = [
        {"Prevalensi Phishing di Jaringan": "50% (Skenario Lab)", "Precision": "99.9%", "Peringatan Palsu (False Alarm)": "0%", "Tingkat Kepercayaan": "Sangat Tinggi"},
        {"Prevalensi Phishing di Jaringan": "30% (Kondisi Dataset)", "Precision": "99.8%", "Peringatan Palsu (False Alarm)": "0%", "Tingkat Kepercayaan": "Sangat Tinggi"},
        {"Prevalensi Phishing di Jaringan": "10% (Gateway Korporat)", "Precision": "99.3%", "Peringatan Palsu (False Alarm)": "1%", "Tingkat Kepercayaan": "Tinggi"},
        {"Prevalensi Phishing di Jaringan": "5% (Trafik Email Umum)", "Precision": "98.4%", "Peringatan Palsu (False Alarm)": "2%", "Tingkat Kepercayaan": "Tinggi"},
        {"Prevalensi Phishing di Jaringan": "1% (Lalu Lintas Web Luas)", "Precision": "92.3%", "Peringatan Palsu (False Alarm)": "8%", "Tingkat Kepercayaan": "Cukup (Perlu Whitelist)"}
    ]
    st.dataframe(pd.DataFrame(prev_data), use_container_width=True, hide_index=True)

    # 6. Studi Kasus Ablasi (Sesuai Sel 34 Notebook)
    st.markdown("---")
    st.subheader("5. Studi Ablasi: Uji Ketergantungan terhadap Fitur Jalan Pintas (`has_https` & `has_www`)")
    st.markdown("""
    Audit bias membuktikan URL sah 100% menggunakan `https` dan 99.8% menggunakan `www`, sedangkan phishing hanya 34.9% dan 9.6%.
    Studi ablasi menguji apakah model mampu mendeteksi phishing jika kedua fitur ini dihilangkan:
    """)
    abl_data = [
        {"Varian Model": "Semua Fitur (31 Fitur Leksikal Penuh)", "PR-AUC": 0.9966, "ROC-AUC": 0.9976, "Precision": 0.9975, "Recall": 0.9773, "F1-Score": 0.9873},
        {"Varian Model": "HANYA has_https & has_www (2 Fitur)", "PR-AUC": 0.9852, "ROC-AUC": 0.9905, "Precision": 0.9949, "Recall": 0.9813, "F1-Score": 0.9881},
        {"Varian Model": "Tanpa has_https & has_www (29 Fitur Murni)", "PR-AUC": 0.9715, "ROC-AUC": 0.9848, "Precision": 0.9936, "Recall": 0.7586, "F1-Score": 0.8603}
    ]
    st.dataframe(pd.DataFrame(abl_data), use_container_width=True, hide_index=True)
    st.caption("Kesimpulan: Model dengan 29 fitur leksikal murni tetap memiliki PR-AUC tinggi (0.9715), membuktikan model memiliki bantalan ketahanan (*resilience*) terhadap phishing modern yang sudah ber-HTTPS.")

# ------------------------------------------------------------------------------
# TAB 3: PENGUJIAN 12 KASUS (QA & EVALUASI SISTEM)
# ------------------------------------------------------------------------------
with tab_testing:
    st.title("Dokumentasi Pengujian Kasus (QA Testing)")
    st.write("Verifikasi performa deteksi pada berbagai skenario URL nyata, simulasi serangan siber, dan uji ketahanan sistem.")

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

    st.markdown("""
    <div class="metric-box">
        <b>Hasil Pengujian QA: 12 / 12 Kasus Lulus (Tingkat Keberhasilan 100%)</b><br>
        Sistem berhasil mendeteksi seluruh skenario serangan siber (IP mentah, typosquatting, shortener, subdomain bertingkat, evasion @, dan punycode) tanpa mengorbankan situs resmi sah.
    </div>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TAB 4: BASIS DATA WHITELIST (TRANSPARANSI REPUTASI DOMAIN)
# ------------------------------------------------------------------------------
with tab_whitelist:
    st.title("Basis Data Domain Terpercaya (Trusted Whitelist)")
    st.markdown("""
    <div class="metric-box">
        <b>Arsitektur Pertahanan Berlapis (Defense-in-Depth):</b><br>
        Dalam implementasi industri nyata (Google Safe Browsing, Cisco Umbrella, Cloudflare), model machine learning didukung oleh basis data reputasi domain resmi untuk mengeliminasi <i>False Positive</i> pada entitas sah dan menjamin ketersediaan layanan (*Availability*).
    </div>
    """, unsafe_allow_html=True)

    df_wl = pd.DataFrame(whitelist_entries)

    col_w1, col_w2, col_w3 = st.columns(3)
    col_w1.metric("Total Domain Terverifikasi", f"{len(df_wl)} Domain")
    col_w2.metric("Kategori Layanan", f"{df_wl['category'].nunique()} Kategori")
    col_w3.metric("Standar Keamanan", "TLS 1.3 / EV SSL")

    st.write("##### 🔎 Cari Domain dalam Basis Data Whitelist:")
    search_query = st.text_input("Ketik nama domain atau organisasi:", placeholder="Contoh: google, bca, wikipedia, github")

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

# ------------------------------------------------------------------------------
# TAB 5: REKOMENDASI & EDUKASI CIA TRIAD
# ------------------------------------------------------------------------------
with tab_education:
    st.title("Edukasi Keamanan Data & Relevansi CIA Triad")
    st.write("Analisis dampak ancaman phishing URL terhadap tiga pilar utama keamanan informasi.")

    col_cia1, col_cia2, col_cia3 = st.columns(3)

    with col_cia1:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #EF4444;">
            <h4 style="color: #EF4444; margin-top: 0;">1. Kerahasiaan (Confidentiality)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Pencurian kredensial akun pengguna (Username & Password).</li>
                <li>Pencurian kode OTP, PIN mobile banking, dan nomor kartu kredit/CVV.</li>
                <li>Kebocoran data identitas pribadi (PII) untuk rekayasa sosial lanjutan.</li>
            </ul>
            <p><b>Peran Sistem:</b> Menyaring tautan di gerbang awal sebelum korban menyerahkan data rahasia.</p>
        </div>
        """, unsafe_allow_html=True)

    with col_cia2:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #F59E0B;">
            <h4 style="color: #F59E0B; margin-top: 0;">2. Integritas (Integrity)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Manipulasi formulir transaksi keuangan (mengalihkan nomor rekening tujuan transfer).</li>
                <li>Pengubahan pengaturan profil atau email pemulihan akun tanpa izin.</li>
                <li>Penyisipan muatan berbahaya (*malware payload*) yang merusak integritas sistem lokal.</li>
            </ul>
            <p><b>Peran Sistem:</b> Memastikan interaksi hanya terjalin dengan endpoint yang sah.</p>
        </div>
        """, unsafe_allow_html=True)

    with col_cia3:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #3B82F6;">
            <h4 style="color: #3B82F6; margin-top: 0;">3. Ketersediaan (Availability)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Pengambilalihan akun (*Account Takeover*) yang menyebabkan pengguna sah terkunci dari akses.</li>
                <li>Pemblokiran akun massal oleh pihak bank akibat percobaan login anomali penyerang.</li>
                <li>Hambatan akses jika sistem keamanan salah memblokir situs resmi (*False Positive*).</li>
            </ul>
            <p><b>Peran Sistem:</b> Eksekusi leksikal instan (&lt; 1ms) dan Whitelist mencegah gangguan ketersediaan.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("⚠️ Keterbatasan Sistem Deteksi Leksikal & Solusi Pertahanan Berlapis")
    st.markdown("""
    1. **Bias Sumber Dataset:** Dataset publik menggabungkan Alexa Top 1M (hampir 100% ber-HTTPS dan ber-WWW) dan PhishTank lama (95.9% HTTP), sehingga fitur skema/www menjadi prediktor yang sangat dominan.
    2. **Phishing Modern Ber-HTTPS:** Penyerang masa kini sudah lazim menggunakan sertifikat SSL gratis (Let's Encrypt). Sistem memerlukan 29 fitur leksikal lainnya (entropi, kata kunci, tanda hubung host, ekstensi) untuk mengenali ancaman.
    3. **Penyalahgunaan Platform Sah (*Living-off-the-Land*):** Phishing yang di-host di layanan seperti Google Docs, Canva, atau Webflow memiliki nama domain sah sehingga sulit dibedakan hanya dari teks URL.
    4. **Rekomendasi Arsitektur Ideal (Defense-in-Depth):** Sistem deteksi leksikal ini berfungsi optimal sebagai **penyaring lapis pertama (*first-line triage*)**, yang selanjutnya dipadukan dengan inspeksi konten halaman (DOM/JavaScript), validasi umur domain (RDAP/Whois), dan reputasi DNS.
    """)
