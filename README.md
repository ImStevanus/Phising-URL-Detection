# Phishing Shield - Deteksi Phishing URL Berbasis Machine Learning
Proyek Ujian Akhir Semester (UAS) Mata Kuliah **Keamanan Data (DSF01)**  
Program Studi Artificial Intelligence - Semester 3

### 👥 Anggota Kelompok (Kelompok 1):
- **38250029** - Stevanus
- **38250025** - Alra Nava Ratna Mandala

---

## 📌 Deskripsi Proyek
Aplikasi web interaktif berbasis **Streamlit** dan **Machine Learning** yang dirancang untuk mendeteksi ancaman tautan *phishing URL* secara proaktif sebelum pengguna mengakses situs berbahaya. Aplikasi ini mengekstrak **31 atribut leksikal** dari teks URL mentah, mengimplementasikan model klasifikasi unggulan **HistGradientBoosting** (PR-AUC 0.997, ROC-AUC 0.999), serta menyajikan rekomendasi tindakan keamanan berbasis kerangka kerja **CIA Triad** (*Confidentiality*, *Integrity*, *Availability*).

Aplikasi juga dilengkapi dengan **Arsitektur Hybrid (Defense-in-Depth)** melalui *Trusted Domain Whitelist* yang dapat diaktifkan/dinonaktifkan (Mode Toggle) untuk memitigasi isu *False Positive* pada situs-situs populer global dan nasional tanpa mengorbankan kepekaan deteksi terhadap ancaman baru (*zero-day threats*).

---

## 🚀 Fitur Utama Aplikasi
1. **Deteksi URL Kustom Real-Time & Skoring Risiko Bertingkat:**
   - Pengguna dapat memasukkan URL apa pun untuk dianalisis oleh model **HistGradientBoosting**.
   - Menyajikan klasifikasi risiko 3-tingkat yang transparan: **AMAN (Risiko Rendah)**, **WASPADA (Risiko Moderat)**, dan **BAHAYA / TINGGI (Blokir)**.
   - Menampilkan metrik komprehensif: Probabilitas Phishing, Ambang Batas Terkalibrasi (Threshold), dan Latensi Inferensi instan dalam milidetik (ms).
   - Tombol preset sampel cepat untuk mempermudah demonstrasi.
2. **Slider Ambang Batas Interaktif & Mode Whitelist (Defense-in-Depth):**
   - Dilengkapi slider pengatur ambang probabilitas operasional secara dinamis (default terkalibrasi `0.880` untuk target recall &ge; 98%).
   - Mode pertahanan berlapis (*Defense-in-Depth*) yang memverifikasi domain resmi bereputasi tinggi bersama model ML leksikal untuk mengeliminasi *False Positive* pada situs-situs populer.
3. **Mesin Penalaran Heuristik (*Reasoning Engine*):**
   - Mengidentifikasi indikator ancaman spesifik pada URL, seperti penggunaan alamat IP langsung, keberadaan kata kunci sensitif perbankan, tanda hubung mencurigakan (*typosquatting*), subdomain bertingkat, pemendek URL, domain punycode (`xn--`), maupun ketiadaan HTTPS.
4. **Rincian Ekstraksi 31 Fitur Leksikal:**
   - Tabel visual interaktif yang menganalisis 31 karakteristik struktural URL lengkap beserta kategori fitur, nilai aktual, status indikator risiko, dan relevansi keamanannya.
5. **Visualisasi Data Latih & Evaluasi Model ML:**
   - Donut chart distribusi kelas alami (504.932 URL: 68.5% Legitimate vs 31.5% Phishing) tanpa *undersampling* buatan.
   - Heatmap interaktif *Confusion Matrix* pada data uji independen 96.031 URL (TN: 71.970, FP: 59, FN: 544, TP: 23.458) dengan Precision 99.75% dan Recall 97.73%.
   - Diagram *Permutation Feature Importance* (12 fitur paling berpengaruh pada data uji).
   - Tabel perbandingan komparatif validasi silang bebas kebocoran domain (*GroupKFold 3 lipatan*): HistGradientBoosting (Winner), Extra Trees, Random Forest, TF-IDF n-gram karakter + LogReg, Logistic Regression, dan Baseline k-NN.
   - Analisis *Base Rate Fallacy* & simulasi Teorema Bayes pada berbagai tingkat prevalensi dunia nyata (50%, 30%, 10%, 5%, 1%).
   - Studi kasus ablasi fitur jalan pintas (`has_https` & `has_www`).
6. **Dokumentasi Pengujian Kasus QA:**
   - Tabel 12 kasus pengujian komprehensif (sampel domain sah, sampel serangan phishing IP, typosquatting, shortener, subdomain, punycode, dan error handling).
7. **Basis Data Whitelist Terbuka:**
   - Tab transparan yang menampilkan seluruh basis data domain terpercaya beserta fitur pencarian instan.
8. **Modul Rekomendasi Mitigasi & Edukasi CIA Triad:**
   - Protokol mitigasi darurat bagi pengguna akhir dan analisis keterkaitan ancaman terhadap Kerahasiaan (*Confidentiality*), Integritas (*Integrity*), dan Ketersediaan (*Availability*) data.

---

## 🛠️ Cara Menjalankan Aplikasi Secara Lokal

Ikuti langkah-langkah berikut untuk menjalankan aplikasi pada komputer/laptop Anda:

### 1. Buka Terminal / PowerShell
Buka aplikasi **PowerShell** atau **Command Prompt** (Terminal).

### 2. Berpindah ke Direktori Proyek (dari Folder Downloads)
Buka terminal dan masuk ke folder hasil unduhan/ekstraksi dari GitHub:
- **Jika mengunduh via *Download ZIP*:**
  ```powershell
  cd "$HOME\Downloads\Phising-URL-Detection-main"
  ```
  *(Atau di Command Prompt / cmd.exe):*
  ```cmd
  cd /d "%USERPROFILE%\Downloads\Phising-URL-Detection-main"
  ```

- **Jika mengunduh via *git clone*:**
  ```powershell
  cd "$HOME\Downloads\Phising-URL-Detection"
  ```
  *(Atau di Command Prompt / cmd.exe):*
  ```cmd
  cd /d "%USERPROFILE%\Downloads\Phising-URL-Detection"
  ```

---

### 3. Instalasi Dependensi Pustaka (Requirements)
Pastikan Anda menggunakan Python 3.10+ lalu pasang seluruh pustaka yang dibutuhkan:
```powershell
pip install -r requirements.txt
```

### 4. Menjalankan Aplikasi Streamlit
Jalankan perintah berikut:
```powershell
streamlit run app.py
```
Aplikasi web akan otomatis terbuka di browser default Anda pada alamat:  
👉 **`http://localhost:8501`**

---

## 📁 Struktur Direktori
```text
Phising-URL-Detection-main/
├── app.py                          # Skrip utama antarmuka Streamlit (31 Fitur & HGB)
├── requirements.txt                # Daftar pustaka Python yang dibutuhkan
├── README.md                       # Dokumentasi dan panduan eksekusi
├── .gitignore                      # Konfigurasi file yang diabaikan Git
├── push_to_github.bat              # Skrip otomasi commit & push ke GitHub
├── Project_Keamanan_Data.ipynb     # Notebook utama analisis, EDA, dan pelatihan model
├── phishing_url_hgb_model.pkl      # Artefak model final HistGradientBoosting (0.21 MB)
├── trusted_whitelist.json          # Basis data domain reputasi resmi terverifikasi
├── URL dataset.csv                 # Dataset sumber URL utama (504.932 baris)
└── Phishing URLs.csv               # Dataset sumber Phishing tambahan
```
