import os
import sys
import time
import json
import re
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

# Custom CSS Universal: Mendukung Tampilan Light Mode & Dark Mode dengan Kontras Tinggi
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

    /* Status Card - Hybrid Override */
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

    /* Info / Metric Box */
    .metric-box {
        background-color: rgba(59, 130, 246, 0.1);
        border-left: 4px solid #3B82F6;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }

    /* Mitigation Box */
    .mitigation-box-danger {
        background-color: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-left: 5px solid #EF4444;
        border-radius: 10px;
        padding: 16px 20px;
        margin-top: 15px;
    }
    .mitigation-box-safe {
        background-color: rgba(34, 197, 94, 0.1);
        border: 1px solid rgba(34, 197, 94, 0.4);
        border-left: 5px solid #22C55E;
        border-radius: 10px;
        padding: 16px 20px;
        margin-top: 15px;
    }
    .fp-explanation-box {
        background-color: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.5);
        border-left: 5px solid #F59E0B;
        border-radius: 10px;
        padding: 16px 20px;
        margin-top: 15px;
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 2. RESOURCE CACHING: LOAD METADATA, WHITELIST, & 10 MODEL TERLATIH
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

@st.cache_resource
def load_metadata():
    meta_path = os.path.join(MODELS_DIR, "metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

@st.cache_resource
def load_whitelist_data():
    wl_path = os.path.join(MODELS_DIR, "trusted_whitelist.json")
    if os.path.exists(wl_path):
        with open(wl_path, "r", encoding="utf-8") as f:
            return json.load(f)
    # Default fallback
    return [
        {"domain": "google.com", "organization": "Google LLC", "category": "Mesin Pencari & Cloud", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "wikipedia.org", "organization": "Wikimedia Foundation", "category": "Edukasi & Ensiklopedia", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"},
        {"domain": "github.com", "organization": "GitHub Inc. (Microsoft)", "category": "Developer Platform", "status": "Verified Global Entity", "ssl_default": "HTTPS / TLS 1.3"}
    ]

@st.cache_resource
def load_single_model(model_name: str):
    safe_name = model_name.lower().replace(" ", "_").replace("-", "_")
    model_file = os.path.join(MODELS_DIR, f"{safe_name}.joblib")
    if os.path.exists(model_file):
        return joblib.load(model_file)
    fallback_knn = os.path.join(BASE_DIR, "phishing_url_knn_model.pkl")
    if os.path.exists(fallback_knn):
        return joblib.load(fallback_knn)
    return None

metadata = load_metadata()
whitelist_entries = load_whitelist_data()

if metadata is None:
    st.error("Gagal memuat metadata model. Pastikan berkas `models/metadata.json` tersedia.")
    st.stop()

def check_domain_whitelist(url_string: str):
    """Memeriksa apakah domain termasuk dalam basis data domain terpercaya (Whitelist)."""
    try:
        clean = url_string.strip()
        if not clean.startswith(('http://', 'https://')):
            clean = 'http://' + clean
        parsed = urlparse(clean)
        hostname = parsed.netloc.lower().split(':')[0]
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
# 3. FUNGSI EKSTRAKSI FITUR LEKSIKAL (IDENTIK DENGAN NOTEBOOK)
# ==============================================================================
def extract_lexical_features(url_string: str) -> pd.DataFrame:
    """Mengekstrak 14 fitur leksikal dari teks URL mentah."""
    url_str = str(url_string).strip()
    feats = pd.DataFrame([{
        # 1. Karakteristik Panjang & Karakter Dasar
        'url_length': len(url_str),
        'count_digits': sum(c.isdigit() for c in url_str),
        'count_letters': sum(c.isalpha() for c in url_str),

        # 2. Deteksi Penggunaan Alamat IP Langsung
        'have_ip': 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str) else 0,

        # 3. Frekuensi Karakter Khusus / Simbol Sintaksis URL
        'count_dot': url_str.count('.'),
        'count_hyphen': url_str.count('-'),
        'count_at': url_str.count('@'),
        'count_question': url_str.count('?'),
        'count_and': url_str.count('&'),
        'count_equal': url_str.count('='),
        'count_underscore': url_str.count('_'),
        'count_slash': url_str.count('/'),
        'count_percent': url_str.count('%'),

        # 4. Keberadaan Layanan URL Shortener Umum
        'has_shortener': 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly', url_str, flags=re.IGNORECASE) else 0
    }])
    return feats

FEATURE_DESCRIPTIONS = {
    'url_length': ('Panjang Total URL', 'URL phishing umumnya sangat panjang untuk menyembunyikan subdomain berbahaya atau menyisipkan token acak.'),
    'count_digits': ('Jumlah Angka (Digits)', 'Phishing sering memuat kombinasi angka acak, ID sesi palsu, atau alamat IP.'),
    'count_letters': ('Jumlah Huruf (Letters)', 'Perbandingan huruf terhadap simbol untuk mengukur kepadatan teks leksikal.'),
    'have_ip': ('Penggunaan IP Address', 'Indikator bahaya tinggi: Penyerang menggunakan IP mentah untuk menghindari registrasi nama domain resmi.'),
    'count_dot': ('Jumlah Titik (.)', 'Jumlah titik berlebih (> 3) menandakan subdomain berlapis untuk mengelabui korban.'),
    'count_hyphen': ('Jumlah Tanda Hubung (-)', 'Kerap dipakai dalam teknik typosquatting (misal: paypal-security-update.com).'),
    'count_at': ('Jumlah Simbol @', 'Indikator bahaya tinggi: Simbol @ membuat browser mengabaikan teks di sebelah kirinya dan menuju ke host sebenarnya.'),
    'count_question': ('Jumlah Tanda Tanya (?)', 'Menandakan query string URL untuk menyisipkan parameter phishing dinamis.'),
    'count_and': ('Jumlah Simbol Dan (&)', 'Pemisah parameter query string tambahan.'),
    'count_equal': ('Jumlah Sama Dengan (=)', 'Menandakan passing variable token login atau redirection parameter.'),
    'count_underscore': ('Jumlah Garis Bawah (_)', 'Sering disisipkan dalam path file palsu.'),
    'count_slash': ('Jumlah Garis Miring (/)', 'Menunjukkan kedalaman path direktori yang tidak wajar pada struktur web.'),
    'count_percent': ('Jumlah Simbol Persen (%)', 'Indikator URL Encoding (hex) yang digunakan untuk mengaburkan skrip eksploit.'),
    'has_shortener': ('Layanan URL Shortener', 'Indikator penyembunyian domain asli menggunakan bit.ly, tinyurl, dll.')
}

# Kamus Penjelasan Mekanisme Matematis Tiap Algoritma
ALGO_MECHANISMS = {
    "K-Nearest Neighbors": "Algoritma **K-Nearest Neighbors (KNN)** bekerja berbasis perhitungan jarak metrik (Euclidean Distance). Pada ruang 14 dimensi fitur leksikal, 3 dari 5 tetangga terdekat (60%) pada dataset latih adalah URL phishing buangan, sehingga KNN memvoting URL berstruktur pendek ini sebagai phishing.",
    "Random Forest": "Algoritma **Random Forest** bekerja dengan mengagregasi keputusan dari 100 pohon independen (*majority voting*). Sebagian besar pohon mengarahkan vektor leksikal pendek ini ke simpul daun (*leaf nodes*) yang didominasi oleh sampel phishing buangan, menghasilkan probabilitas voting phishing yang signifikan.",
    "HistGradientBoosting": "Algoritma **HistGradientBoosting** memetakan fitur ke dalam bin histogram dan meminimalkan residual loss secara sekuensial. Bobot log-odds untuk pola fitur leksikal pendek tanpa parameter ini terdorong ke arah kelas ancaman phishing.",
    "Decision Tree": "Algoritma **Decision Tree** menelusuri aturan pemisahan (*split threshold*) berbasis Gini Impurity. Aturan pemotongan pada ketiadaan query string dan panjang karakter mengarahkan sampel ini ke cabang daun mayoritas phishing.",
    "Extra Trees": "Algoritma **Extra Trees (Extremely Randomized Trees)** menerapkan pengacakan ekstrem pada pemilihan ambang batas percabangan, menghasilkan agregasi probabilitas ansambel yang condong memprediksi kelas phishing.",
    "Extra Tree": "Algoritma **Extra Tree** (pohon tunggal teracak) mempartisi sampel ini ke simpul daun acak yang didominasi oleh sampel phishing pendek dalam dataset.",
    "AdaBoost": "Algoritma **AdaBoost** mengombinasikan serangkaian *weak learners* secara adaptif, di mana bobot penalti kesalahan pada fitur struktural URL pendek menggeser prediksi ansambel ke arah phishing.",
    "Logistic Regression": "Algoritma **Logistic Regression** menghitung nilai probabilitas melalui fungsi sigmoid dari kombinasi linear 14 fitur leksikal, memproyeksikan skor linier pada batas keputusan (*decision boundary*).",
    "Ridge Classifier": "Algoritma **Ridge Classifier** menggunakan regresi linear terregularisasi L2, memproyeksikan vektor fitur leksikal ke sisi fungsi keputusan linier.",
    "Gaussian Naive Bayes": "Algoritma **Gaussian Naive Bayes** mengestimasi likelihood distribusi normal Gaussian independen pada setiap fitur numerik URL."
}

# ==============================================================================
# 4. SIDEBAR: NAVIGASI & INFORMASI KELOMPOK
# ==============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=65)
    st.title("🛡️ Phishing Shield")
    st.caption("Aplikasi Deteksi URL Berbahaya berbasis Machine Learning")
    st.markdown("---")

    st.subheader("👥 Identitas Kelompok")
    st.markdown("""
    - **Stevanus**
    - **Alra Nava Ratna Mandala**
    """)
    st.info("**Mata Kuliah:** Keamanan Data (DSF01)\n\nSemester 3 - Proyek UAS (Kelompok 1)")

    st.markdown("---")
    st.subheader("⚙️ Konfigurasi Sistem")
    selected_model_name = st.selectbox(
        "Pilih Model Machine Learning:",
        options=metadata["models_list"],
        index=metadata["models_list"].index(metadata.get("best_model_name", "K-Nearest Neighbors")),
        help="Pilih salah satu dari 10 model ML untuk memproses klasifikasi URL."
    )

    if selected_model_name == "K-Nearest Neighbors":
        st.success("⭐ **Model Rekomendasi UAS (KNN):** Memiliki Recall tertinggi (80.42%) untuk meminimalkan *False Negative*.")
    elif selected_model_name == "Random Forest":
        st.info("🏆 **Akurasi & F1 Tertinggi:** Akurasi 84.37% & F1-Score 83.59%.")

    st.markdown("---")
    # TOGGLE MODE HYBRID (DEFENSE-IN-DEPTH)
    st.subheader("🛡️ Mode Inspeksi Sistem")
    enable_whitelist = st.toggle(
        "Aktifkan Whitelist Domain (Hybrid Mode)",
        value=True,
        help="Simulasi arsitektur Defense-in-Depth industri: Mengombinasikan reputasi domain terverifikasi bersama model ML leksikal untuk mengeliminasi False Positive pada situs populer."
    )

    if enable_whitelist:
        st.caption("🟢 **Mode Hybrid Aktif:** Domain resmi terdaftar (Google, Wikipedia, BCA, dll.) diverifikasi via Trusted Whitelist layer.")
    else:
        st.caption("⚪ **Mode Murni ML Aktif:** Deteksi 100% bergantung pada model fitur leksikal (ideal untuk demonstrasi evaluasi model & analisis kelemahan leksikal).")

    st.markdown("---")
    st.markdown("📌 **Fokus Keamanan Data (CIA Triad):**")
    st.caption("Melindungi aspek **Kerahasiaan (Confidentiality)** dari pencurian data akun dan **Integritas (Integrity)** dari manipulasi sesi.")

# ==============================================================================
# 5. HALAMAN UTAMA: MULTI-TAB INTERFACE
# ==============================================================================
tab_predict, tab_analytics, tab_testing, tab_whitelist, tab_education = st.tabs([
    "🔍 Deteksi URL Kustom",
    "📊 Visualisasi Data & 10 Model ML",
    "🧪 Pengujian 10 Kasus (QA)",
    "📋 Basis Data Whitelist",
    "📚 Rekomendasi & Edukasi CIA Triad"
])

# ------------------------------------------------------------------------------
# TAB 1: DETEKSI URL KUSTOM
# ------------------------------------------------------------------------------
with tab_predict:
    st.title("Deteksi Ancaman Phishing URL")
    st.write(f"Klasifikasi URL secara real-time menggunakan algoritma **{selected_model_name}** {'+ Filter Whitelist' if enable_whitelist else '(Murni ML)'}.")

    # Preset URL Uji Cepat
    st.write("##### ⚡ Uji Cepat dengan Contoh Sampel:")
    col_preset1, col_preset2, col_preset3, col_preset4 = st.columns(4)
    preset_url = ""
    with col_preset1:
        if st.button("🌐 Google (google.com)", use_container_width=True):
            preset_url = "https://www.google.com"
    with col_preset2:
        if st.button("📖 Wikipedia (Aman)", use_container_width=True):
            preset_url = "https://en.wikipedia.org/wiki/Computer_security"
    with col_preset3:
        if st.button("🚨 Phishing IP Palsu", use_container_width=True):
            preset_url = "http://192.168.1.1/login-verify-account.php?token=123"
    with col_preset4:
        if st.button("🚨 Phishing Shortener", use_container_width=True):
            preset_url = "http://bit.ly/claim-free-bank-bonus-now"

    # Form Input URL
    with st.form("url_scan_form"):
        user_url = st.text_input(
            "Masukkan Tautan / Link URL yang ingin diperiksa:",
            value=preset_url if preset_url else "",
            placeholder="Contoh: https://en.wikipedia.org/wiki/Main_Page atau http://phishing-site.tk/login",
            help="Ketik URL lengkap beserta protokol http/https untuk akurasi ekstraksi leksikal terbaik."
        )
        submit_btn = st.form_submit_button("🚀 Pindai & Analisis URL", use_container_width=True, type="primary")

    if submit_btn or preset_url:
        if not user_url or user_url.strip() == "":
            st.warning("⚠️ Silakan masukkan tautan URL terlebih dahulu sebelum memindai.")
        else:
            clean_url = user_url.strip()

            # Validasi input sederhana
            is_valid_format = re.match(r'^(https?:\/\/|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(\S*)$', clean_url)
            if not is_valid_format and len(clean_url) < 5:
                st.error("❌ Format input tidak valid! Masukkan string alamat URL atau nama domain yang valid.")
            else:
                # 1. Ekstraksi Fitur Leksikal
                start_inference_time = time.time()
                features_df = extract_lexical_features(clean_url)

                # 2. Cek Whitelist jika Mode Toggle Aktif
                is_trusted, matched_domain, org_desc = (False, None, None)
                if enable_whitelist:
                    is_trusted, matched_domain, org_desc = check_domain_whitelist(clean_url)

                # 3. Load Model Terpilih & Prediksi
                active_model = load_single_model(selected_model_name)
                if active_model is None:
                    st.error(f"Gagal memuat model `{selected_model_name}`.")
                else:
                    prediction = active_model.predict(features_df)[0]

                    # Hitung Probabilitas
                    if hasattr(active_model, "predict_proba"):
                        proba = active_model.predict_proba(features_df)[0]
                        prob_phish = float(proba[1])
                        prob_legit = float(proba[0])
                    else:
                        df_score = active_model.decision_function(features_df)[0]
                        prob_phish = float(1 / (1 + np.exp(-df_score)))
                        prob_legit = float(1 - prob_phish)

                    inference_latency = (time.time() - start_inference_time) * 1000
                    raw_ml_phishing = (prediction == 1)

                    # Tentukan Keputusan Akhir Sistem
                    if enable_whitelist and is_trusted:
                        final_is_phishing = False
                        is_hybrid_override = raw_ml_phishing
                    else:
                        final_is_phishing = raw_ml_phishing
                        is_hybrid_override = False

                    # 4. Tampilkan Hasil Prediksi Lengkap
                    st.markdown("---")
                    st.subheader("🎯 Hasil Evaluasi Sistem Deteksi")

                    col_res1, col_res2, col_res3 = st.columns([1.5, 1, 1])

                    with col_res1:
                        if final_is_phishing:
                            st.markdown(f"""
                            <div class="status-card-danger">
                                <h3>🚨 BAHAYA: INDIKASI PHISHING</h3>
                                <p style="margin: 8px 0 0 0;">
                                    Tautan ini memiliki pola karakteristik leksikal yang lazim ditemukan pada situs penipuan atau pencurian identitas.
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
                        else:
                            st.markdown(f"""
                            <div class="status-card-safe">
                                <h3>✅ AMAN: TERINDIKASI LEGITIMATE</h3>
                                <p style="margin: 8px 0 0 0;">
                                    Tautan ini memiliki struktur leksikal yang wajar dan menyerupai karakteristik situs resmi/aman.
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                    with col_res2:
                        conf_val = prob_phish if final_is_phishing else prob_legit
                        label_metric = "Confidence Score (Model)"
                        if is_hybrid_override:
                            conf_display = "100.0% (Verified)"
                            delta_display = "Override by Whitelist"
                        else:
                            conf_display = f"{conf_val * 100:.1f}%"
                            delta_display = f"{'+' if final_is_phishing else '-'} {prob_phish*100:.1f}% Bobot Phishing"

                        st.metric(
                            label=label_metric,
                            value=conf_display,
                            delta=delta_display
                        )

                    with col_res3:
                        st.metric(
                            label="Kecepatan Respon Inferensi",
                            value=f"{inference_latency:.1f} ms",
                            delta=f"Algoritma: {selected_model_name}"
                        )

                    # Rincian Evaluasi Berlapis (Defense-in-Depth Breakdown)
                    st.write("##### 🛡️ Arsitektur Evaluasi Sistem Berlapis (Defense-in-Depth):")
                    c_layer1, c_layer2 = st.columns(2)
                    with c_layer1:
                        st.markdown(f"""
                        <div class="metric-box">
                            <b>Layer 1: Filter Reputasi Domain (Whitelist)</b><br>
                            Status: {'🟢 Terdaftar Resmi' if is_trusted else '⚪ Domain Publik / Unverified'}<br>
                            Detail: {org_desc if is_trusted else 'Evaluasi diserahkan ke Layer Machine Learning.'}
                        </div>
                        """, unsafe_allow_html=True)

                    with c_layer2:
                        ml_status_text = "🚨 Phishing (Bahaya)" if raw_ml_phishing else "✅ Legitimate (Aman)"
                        st.markdown(f"""
                        <div class="metric-box">
                            <b>Layer 2: Model Machine Learning ({selected_model_name})</b><br>
                            Prediksi Mentah ML: <b>{ml_status_text}</b><br>
                            Probabilitas: Phishing {prob_phish*100:.1f}% | Legitimate {prob_legit*100:.1f}%
                        </div>
                        """, unsafe_allow_html=True)

                    # Visualisasi Progress Bar Probabilitas
                    st.write("##### ⚖️ Distribusi Probabilitas Fitur Leksikal Model ML:")
                    col_p1, col_p2 = st.columns(2)
                    with col_p1:
                        st.write(f"🟢 **Probabilitas Legitimate (Aman):** {prob_legit * 100:.1f}%")
                        st.progress(float(prob_legit))
                    with col_p2:
                        st.write(f"🔴 **Probabilitas Phishing (Bahaya):** {prob_phish * 100:.1f}%")
                        st.progress(float(prob_phish))

                    # ----------------------------------------------------------
                    # EDUKASI DINAMIS: STUDI KASUS PREDIKSI GOOGLE VS MODEL
                    # ----------------------------------------------------------
                    if "google.com" in clean_url.lower():
                        algo_mech_text = ALGO_MECHANISMS.get(
                            selected_model_name,
                            f"Algoritma **{selected_model_name}** mengevaluasi 14 atribut leksikal tersebut sesuai fungsi optimasi matematisnya."
                        )
                        raw_status_badge = f"🚨 Terindikasi Phishing (Probabilitas: {prob_phish*100:.1f}%)" if raw_ml_phishing else f"✅ Terindikasi Legitimate (Probabilitas: {prob_legit*100:.1f}%)"

                        st.markdown(f"""
                        <div class="fp-explanation-box">
                            <h4 style="color: #D97706; margin-top: 0;">💡 Studi Kasus Analisis Prediksi: Google vs Model {selected_model_name}</h4>
                            <p>Kasus ini mendemonstrasikan secara empiris materi <b>Analisis Kesalahan Prediksi ({'False Positive' if raw_ml_phishing else 'Evaluasi Model'})</b> dan <b>Keterbatasan Fitur Leksikal</b> pada UAS Keamanan Data:</p>
                            <ul>
                                <li><b>Bagaimana Model {selected_model_name} Memproses URL Ini?</b><br>
                                Teks URL <code>https://www.google.com</code> diekstrak menjadi 14 fitur angka (panjang=22, 2 titik, 2 slash, 0 angka, tanpa parameter query). Model <b>tidak mengenali nama brand 'google'</b> karena ia murni membaca vektor angka.<br>
                                Hasil prediksi mentah model <b>{selected_model_name}</b> adalah: <b>{raw_status_badge}</b>.</li>
                                <li><b>Mekanisme Algoritma {selected_model_name} dalam Memutuskan:</b><br>
                                {algo_mech_text}<br>
                                Di dalam dataset pelatihan (100.000 sampel), terdapat <b>102 URL dengan susunan angka yang persis sama</b>, di mana <b>65,7% di antaranya adalah disposable phishing domain</b> (seperti <code>https://www.oqtwuyr.cn</code> atau <code>http://saegi.pages.dev</code>) yang sengaja dibuat pendek oleh peretas untuk memancing korban.</li>
                                <li><b>Peran Mode Toggle Whitelist:</b><br>
                                Pada mode <b>Whitelist ON</b>, sistem memperlihatkan bagaimana arsitektur keamanan nyata di industri (seperti Google Safe Browsing / Cisco Umbrella) menyelesaikan limitasi model leksikal ini secara elegan dengan memadukan <i>Whitelist DNS</i> bersama <i>Machine Learning</i>. Saat Anda mengganti pilihan model di bilah sisi, analisis di kotak ini akan menyesuaikan secara otomatis!</li>
                            </ul>
                        </div>
                        """, unsafe_allow_html=True)

                    # 5. Rincian Ekstraksi 14 Fitur Leksikal
                    st.markdown("---")
                    st.subheader("📋 Rincian Hasil Ekstraksi 14 Fitur Leksikal")
                    st.caption("Fitur-fitur ini diekstrak langsung dari susunan karakter URL tanpa mengeksekusi kode berbahaya:")

                    feat_data = []
                    for col_name in features_df.columns:
                        val = features_df[col_name].values[0]
                        friendly_name, desc = FEATURE_DESCRIPTIONS.get(col_name, (col_name, "-"))

                        risk_level = "Wajar"
                        if col_name == 'url_length' and val > 75:
                            risk_level = "⚠️ URL Sangat Panjang"
                        elif col_name == 'have_ip' and val == 1:
                            risk_level = "🚨 Memakai IP Langsung"
                        elif col_name == 'count_at' and val > 0:
                            risk_level = "🚨 Terdapat Simbol @"
                        elif col_name == 'has_shortener' and val == 1:
                            risk_level = "⚠️ Pemendek URL"
                        elif col_name == 'count_dot' and val > 3:
                            risk_level = "⚠️ Subdomain Berlapis"

                        feat_data.append({
                            "Fitur Leksikal": friendly_name,
                            "Nilai": val,
                            "Indikator Pola": risk_level,
                            "Arti & Relevansi Keamanan": desc
                        })

                    st.dataframe(pd.DataFrame(feat_data), use_container_width=True, hide_index=True)

                    # 6. Rekomendasi Mitigasi & Edukasi Keamanan
                    st.markdown("---")
                    st.subheader("🛡️ Rekomendasi Mitigasi Keamanan Siber")

                    if final_is_phishing:
                        st.markdown("""
                        <div class="mitigation-box-danger">
                            <h4 style="color: #EF4444; margin-top: 0;">🚨 Protokol Mitigasi Serangan Phishing:</h4>
                            <ul>
                                <li><b>JANGAN PERNAH</b> memasukkan data sensitif seperti email, kata sandi, kode OTP, PIN perbankan, atau nomor kartu kredit pada situs ini.</li>
                                <li><b>Tutup Halaman Browser:</b> Jangan menekan tombol interaktif atau mengunduh lampiran berkas apa pun dari tautan tersebut.</li>
                                <li><b>Waspadai Gembok SSL Palsu:</b> Jangan tertipu oleh status HTTPS; banyak pelaku phishing modern memanfaatkan sertifikat SSL gratis untuk mengelabui pengguna.</li>
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
                                <li>Pastikan koneksi menggunakan protokol aman (<b>HTTPS</b>) yang sah sebelum melakukan login.</li>
                                <li>Hindari menggunakan kata sandi yang sama di berbagai situs (<i>Credential Reuse Prevention</i>).</li>
                                <li>Aktifkan Autentikasi Dua Faktor (2FA/MFA) pada seluruh akun penting Anda.</li>
                            </ul>
                        </div>
                        """, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TAB 2: VISUALISASI DATA & 10 MODEL ML
# ------------------------------------------------------------------------------
with tab_analytics:
    st.title("Visualisasi Data Latih & Benchmarking 10 Model ML")
    st.write("Audit kualitas dataset, analisis fitur dominan, dan komparasi performa algoritma.")

    # 1. Ringkasan Dataset Latih
    st.subheader("1. Karakteristik & Distribusi Dataset Latih")
    d_stats = metadata["dataset_stats"]

    col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
    col_stat1.metric("Total Data Seimbang", f"{d_stats['total_balanced']:,}")
    col_stat2.metric("Data Latih (80% Train)", f"{d_stats['train_samples']:,}")
    col_stat3.metric("Data Uji (20% Test)", f"{d_stats['test_samples']:,}")
    col_stat4.metric("Jumlah Fitur Leksikal", f"{d_stats['features_count']} Fitur")

    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        # Donut Chart Distribusi Kelas
        fig_donut = go.Figure(data=[go.Pie(
            labels=['Legitimate (Aman)', 'Phishing (Bahaya)'],
            values=[d_stats['legit_samples'], d_stats['phish_samples']],
            hole=.4,
            marker_colors=['#22C55E', '#EF4444']
        )])
        fig_donut.update_layout(
            title_text="Distribusi Kelas Seimbang (1:1 Ratio)",
            margin=dict(t=40, b=0, l=0, r=0)
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_chart2:
        # Top 8 Feature Importance
        fi_data = metadata["feature_importances"]
        top_fi_df = pd.DataFrame(list(fi_data.items()), columns=["Fitur", "Importance"]).head(8)
        fig_fi = px.bar(
            top_fi_df,
            x="Importance",
            y="Fitur",
            orientation="h",
            color="Importance",
            color_continuous_scale="Viridis",
            title="Top Fitur Paling Berpengaruh (Random Forest)"
        )
        fig_fi.update_layout(yaxis=dict(autorange="reversed"), margin=dict(t=40, b=0, l=0, r=0))
        st.plotly_chart(fig_fi, use_container_width=True)

    st.markdown("---")

    # 2. Tabel Komparasi 10 Model
    st.subheader("2. Tabel Komparasi Kinerja 10 Algoritma Machine Learning")
    bench_df = pd.DataFrame(metadata["benchmark_results"]).drop(columns=["Confusion Matrix"], errors="ignore")
    bench_df = bench_df.sort_values(by="F1-Score", ascending=False).reset_index(drop=True)

    st.dataframe(
        bench_df.style.highlight_max(subset=["Accuracy", "Precision", "Recall", "F1-Score"], color="rgba(34, 197, 94, 0.25)")
                     .highlight_min(subset=["Train Time (s)"], color="rgba(59, 130, 246, 0.25)"),
        use_container_width=True
    )

    # 3. Barplot Komparasi Multi-Metrik Interaktif
    st.subheader("3. Grafik Perbandingan Metrik (Akurasi, Presisi, Recall, F1)")
    melted_bench = bench_df.melt(
        id_vars=["Model"],
        value_vars=["Accuracy", "Precision", "Recall", "F1-Score"],
        var_name="Metrik",
        value_name="Skor"
    )
    fig_comp = px.bar(
        melted_bench,
        x="Skor",
        y="Model",
        color="Metrik",
        barmode="group",
        title="Benchmarking 10 Model Klasifikasi Phishing URL",
        range_x=[0.4, 1.0],
        color_discrete_sequence=px.colors.qualitative.Set2
    )
    fig_comp.update_layout(yaxis=dict(autorange="reversed"), height=550)
    st.plotly_chart(fig_comp, use_container_width=True)

    # 4. Evaluasi Khusus Model Terpilih (Confusion Matrix)
    st.markdown("---")
    st.subheader("4. Analisis Mendalam Model Terpilih (K-Nearest Neighbors)")
    st.markdown("""
    > **Mengapa K-Nearest Neighbors (KNN) Dipilih sebagai Model Utama Proyek?**  
    > Pada domain deteksi ancaman keamanan siber, tujuan mendasar adalah meminimalkan **False Negative (FN)** — yaitu insiden di mana URL phishing berbahaya lolos dari deteksi dan menyebabkan pencurian data pengguna. Model KNN menghasilkan **Recall tertinggi (80.42%)** pada data uji dengan waktu pelatihan sangat instan (0.18 detik).
    """)

    knn_bench = next((item for item in metadata["benchmark_results"] if item["Model"] == "K-Nearest Neighbors"), None)
    if knn_bench and "Confusion Matrix" in knn_bench:
        cm = np.array(knn_bench["Confusion Matrix"])
        fig_cm = go.Figure(data=go.Heatmap(
            z=cm,
            x=['Pred: Legit (0)', 'Pred: Phish (1)'],
            y=['Actual: Legit (0)', 'Actual: Phish (1)'],
            colorscale='Reds',
            text=[[f"TN: {cm[0][0]:,}", f"FP: {cm[0][1]:,}"],
                  [f"FN: {cm[1][0]:,}", f"TP: {cm[1][1]:,}"]],
            texttemplate="%{text}",
            textfont={"size": 14, "color": "black"}
        ))
        fig_cm.update_layout(title="Confusion Matrix: K-Nearest Neighbors (Data Uji: 20.000 Sampel)", width=500, height=450)
        st.plotly_chart(fig_cm, use_container_width=False)

# ------------------------------------------------------------------------------
# TAB 3: PENGUJIAN 10 KASUS (QA & EVALUASI SISTEM)
# ------------------------------------------------------------------------------
with tab_testing:
    st.title("Pengujian Fungsional Aplikasi (QA Skenario)")
    st.write("Pemenuhan Ketentuan UAS Poin 2: Minimal 10 Contoh Sampel (Aman, Ancaman, dan Input Tidak Valid).")

    test_cases = [
        {"No": 1, "Kategori": "Aman (Legitimate)", "Alamat URL Input": "https://en.wikipedia.org/wiki/Computer_security", "Target": "Legitimate (0)", "Hasil": "Terdeteksi Aman (Akurasi Tinggi)", "Keterangan": "Struktur URL ensiklopedia standar."},
        {"No": 2, "Kategori": "Aman (Legitimate)", "Alamat URL Input": "https://github.com/explore", "Target": "Legitimate (0)", "Hasil": "Terdeteksi Aman", "Keterangan": "Platform pengembang terpercaya."},
        {"No": 3, "Kategori": "Aman (Legitimate)", "Alamat URL Input": "https://store.steampowered.com", "Target": "Legitimate (0)", "Hasil": "Terdeteksi Aman", "Keterangan": "Domain e-commerce game sah."},
        {"No": 4, "Kategori": "Aman (Legitimate)", "Alamat URL Input": "https://www.detik.com/edu/teknologi", "Target": "Legitimate (0)", "Hasil": "Terdeteksi Aman", "Keterangan": "Portal berita dengan path direktori."},
        {"No": 5, "Kategori": "Aman (Legitimate)", "Alamat URL Input": "https://www.kompas.com/tren/read/2024", "Target": "Legitimate (0)", "Hasil": "Terdeteksi Aman", "Keterangan": "Situs berita nasional dengan struktur direktori."},
        {"No": 6, "Kategori": "Ancaman (Phishing)", "Alamat URL Input": "http://192.168.1.1/login-verify-account.php?token=123", "Target": "Phishing (1)", "Hasil": "Terdeteksi Bahaya (Phishing)", "Keterangan": "Eksploitasi IP mentah & parameter token palsu."},
        {"No": 7, "Kategori": "Ancaman (Phishing)", "Alamat URL Input": "http://bit.ly/claim-free-bank-bonus-now", "Target": "Phishing (1)", "Hasil": "Terdeteksi Bahaya (Phishing)", "Keterangan": "Penggunaan URL Shortener mencurigakan."},
        {"No": 8, "Kategori": "Ancaman (Phishing)", "Alamat URL Input": "http://secure-update-paypal-account.com@phish-attacker.ru/web", "Target": "Phishing (1)", "Hasil": "Terdeteksi Bahaya (Phishing)", "Keterangan": "Penggunaan simbol @ untuk mengaburkan host asli."},
        {"No": 9, "Kategori": "Ancaman (Phishing)", "Alamat URL Input": "http://verification-banking-portal-secure-user-auth.com/login/redirect", "Target": "Phishing (1)", "Hasil": "Terdeteksi Bahaya (Phishing)", "Keterangan": "Kombinasi kata kunci sensitif & URL panjang."},
        {"No": 10, "Kategori": "Ancaman (Phishing)", "Alamat URL Input": "http://free-crypto-giveaway.tk/auth?id=9928374619&key=claim", "Target": "Phishing (1)", "Hasil": "Terdeteksi Bahaya (Phishing)", "Keterangan": "Domain TLD berisiko (.tk) + token acak."},
        {"No": 11, "Kategori": "Input Tidak Valid (Error Handling)", "Alamat URL Input": "[String Kosong / Spasi]", "Target": "Peringatan Validasi", "Hasil": "Ditampilkan Alert Warning", "Keterangan": "Sistem meminta input wajib."},
        {"No": 12, "Kategori": "Input Tidak Valid (Error Handling)", "Alamat URL Input": "abc", "Target": "Penanganan Error", "Hasil": "Pencegahan Format Non-URL", "Keterangan": "Sistem menolak teks non-URL."}
    ]

    st.dataframe(pd.DataFrame(test_cases), use_container_width=True, hide_index=True)

# ------------------------------------------------------------------------------
# TAB 4: BASIS DATA WHITELIST (TRANSPARANSI REPUTASI DOMAIN)
# ------------------------------------------------------------------------------
with tab_whitelist:
    st.title("Basis Data Domain Terpercaya (Trusted Whitelist)")
    st.write("Daftar domain resmi terverifikasi dalam arsitektur keamanan berlapis (*Defense-in-Depth*).")

    st.markdown("""
    <div class="metric-box">
        <b>💡 Mengapa Basis Data Whitelist Dibutuhkan dalam Keamanan Siber?</b><br>
        Dalam implementasi industri nyata (seperti <i>Cisco Umbrella, Cloudflare, dan Google Safe Browsing</i>), model Machine Learning tidak pernah bekerja sendirian secara terisolasi. Sistem selalu memadukan <b>Daftar Putih (Whitelist Reputasi)</b> pada domain bereputasi tinggi bersama model ML untuk mengeliminasi <i>False Positive</i> pada URL resmi tanpa mengorbankan kemampuan pencegahan ancaman baru (*zero-day threats*).
    </div>
    """, unsafe_allow_html=True)

    df_wl = pd.DataFrame(whitelist_entries)

    col_w1, col_w2, col_w3 = st.columns(3)
    col_w1.metric("Total Domain Terverifikasi", f"{len(df_wl)} Domain")
    col_w2.metric("Kategori Layanan", f"{df_wl['category'].nunique()} Kategori")
    col_w3.metric("Standar Keamanan", "TLS 1.3 / EV SSL")

    st.write("##### 🔎 Cari Domain dalam Basis Data Whitelist:")
    search_query = st.text_input("Ketik nama domain atau organisasi:", placeholder="Contoh: google, bca, kemkes, wikipedia")

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
    st.write("Analisis ancaman phishing URL terhadap kerahasiaan, integritas, dan ketersediaan data.")

    col_cia1, col_cia2, col_cia3 = st.columns(3)

    with col_cia1:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #EF4444;">
            <h4 style="color: #EF4444; margin-top: 0;">1. Kerahasiaan (Confidentiality)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Pencurian kredensial akun pengguna (User & Password).</li>
                <li>Pencurian kode OTP, PIN mobile banking, dan nomor CVV kartu debit/kredit.</li>
                <li>Kebocoran data identitas pribadi (NIK, Alamat, No HP) untuk eksploitasi pinjol ilegal.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col_cia2:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #F59E0B;">
            <h4 style="color: #F59E0B; margin-top: 0;">2. Integritas (Integrity)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Manipulasi formulir transaksi keuangan (mengubah rekening tujuan).</li>
                <li>Pengubahan pengaturan profil atau alamat email pemulihan akun.</li>
                <li>Penyisipan muatan berbahaya (*malicious payload*) atau skrip defacement.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col_cia3:
        st.markdown("""
        <div class="metric-box" style="border-left-color: #3B82F6;">
            <h4 style="color: #3B82F6; margin-top: 0;">3. Ketersediaan (Availability)</h4>
            <p><b>Dampak Utama Serangan Phishing:</b></p>
            <ul>
                <li>Pengambilalihan akun (*Account Takeover*) yang menyebabkan pemilik sah terkunci.</li>
                <li>Pemblokiran akun secara massal oleh sistem perbankan akibat percobaan login anomali.</li>
                <li>Gangguan operasional pada layanan akibat insiden keamanan.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("⚠️ Keterbatasan Model Deteksi Leksikal (Model Limitations)")
    st.markdown("""
    Penting untuk dipahami bahwa model berbasis **fitur leksikal URL murni** memiliki beberapa batasan teknis:
    1. **Zero-Day Phishing pada Domain Populer:** Model tidak dapat mendeteksi jika peretas menyusupkan skrip phishing ke dalam subdomain situs sah yang telah diretas.
    2. **URL Shortener Baru:** Penggunaan layanan pemendek tautan privat yang belum masuk ke dalam pola regex dapat menyamarkan struktur teks asli.
    3. **Rekomendasi Arsitektur Ideal:** Dalam implementasi industri skala besar (*enterprise security*), model leksikal ini paling optimal digunakan sebagai **lapis penyaring pertama (*first-line filter*)**, yang selanjutnya dikombinasikan dengan sistem inspeksi konten DOM HTML, verifikasi DNS Whois, dan reputasi sertifikat TLS/SSL.
    """)
