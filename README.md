# Phishing Shield - Deteksi Phishing URL Berbasis Machine Learning
Proyek Ujian Akhir Semester (UAS) Mata Kuliah **Keamanan Data (DSF01)**  
Program Studi Data Science / Artificial Intelligence - Semester 3

### 👥 Anggota Kelompok (Kelompok 1):
- **38250029** - Stevanus
- **38250025** - Alra Nava Ratna Mandala

---

## 📌 Deskripsi Proyek
Aplikasi web interaktif berbasis **Streamlit** dan **Machine Learning** yang dirancang untuk mendeteksi ancaman tautan *phishing URL* secara proaktif sebelum pengguna mengakses situs berbahaya. Aplikasi ini mengekstrak 14 atribut leksikal dari teks URL mentah, membandingkan 10 arsitektur model klasifikasi machine learning, serta menyajikan rekomendasi tindakan keamanan berbasis kerangka kerja **CIA Triad** (*Confidentiality*, *Integrity*, *Availability*).

Aplikasi juga dilengkapi dengan **Arsitektur Hybrid (Defense-in-Depth)** melalui *Trusted Domain Whitelist* yang dapat diaktifkan/dinonaktifkan (Mode Toggle) untuk memitigasi isu *False Positive* pada situs-situs populer global dan nasional.

---

## 🚀 Fitur Utama Aplikasi
1. **Prediksi URL Kustom & Pilihan 10 Model ML:**
   - Pengguna dapat memasukkan URL apa pun dan memilih salah satu dari 10 model machine learning yang telah dilatih (K-Nearest Neighbors, Random Forest, HistGradientBoosting, Decision Tree, Extra Trees, AdaBoost, Logistic Regression, Ridge Classifier, Gaussian Naive Bayes, Extra Tree).
   - Menampilkan hasil prediksi lengkap: Status Keamanan (Aman vs Phishing), Skor Keyakinan (*Confidence Score*), dan latensi respon dalam milidetik (ms).
   - Tombol preset sampel cepat untuk mempermudah demonstrasi saat presentasi.
2. **Mode Toggle Whitelist (Arsitektur Hybrid):**
   - Mode pertahanan berlapis (*Defense-in-Depth*) yang memverifikasi domain resmi bereputasi tinggi bersama model ML.
3. **Rincian Ekstraksi 14 Fitur Leksikal:**
   - Tabel visual interaktif yang menganalisis karakteristik struktural URL (panjang teks, digit, huruf, deteksi IP mentah, simbol manipulasi sintaksis `@`, `/`, `?`, `=`, serta domain pemendek URL).
4. **Visualisasi Data Latih & Benchmarking 10 Model:**
   - Donut chart distribusi kelas seimbang (50.000 legitimate vs 50.000 phishing).
   - Grafik Feature Importance (bobot pengaruh fitur leksikal dari Random Forest).
   - Tabel komparasi lengkap (Akurasi, Presisi, Recall, F1-Score, Waktu Pelatihan) serta barplot interaktif multi-metrik.
   - Confusion Matrix interaktif dari model unggulan (KNN).
5. **Dokumentasi Pengujian 10 Skenario (QA):**
   - Tabel 12 kasus pengujian komprehensif (sampel aman, sampel ancaman phishing, dan pengujian error handling pada input tidak valid).
6. **Basis Data Whitelist Terbuka:**
   - Tab transparan yang menampilkan seluruh basis data domain terpercaya beserta fitur pencarian instan.
7. **Modul Rekomendasi Mitigasi & Edukasi CIA Triad:**
   - Protokol mitigasi darurat bagi pengguna akhir dan analisis keterkaitan ancaman terhadap Kerahasiaan, Integritas, dan Ketersediaan data.

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
├── app.py                          # Skrip utama antarmuka Streamlit
├── requirements.txt                # Daftar pustaka Python yang dibutuhkan
├── README.md                       # Dokumentasi dan panduan eksekusi
├── .gitignore                      # Konfigurasi file yang diabaikan Git
├── Project_Keamanan_Data.ipynb     # Notebook analisis, EDA, dan pelatihan model
├── phishing_url_knn_model.pkl      # Artefak pipeline model unggulan (KNN)
├── models/                         # Direktori model terlatih & basis data
│   ├── metadata.json               # Data metrik benchmark & feature importance
│   ├── trusted_whitelist.json      # Basis data domain reputasi resmi
│   ├── k_nearest_neighbors.joblib
│   ├── random_forest.joblib
│   ├── histgradientboosting.joblib
│   ├── decision_tree.joblib
│   ├── extra_trees.joblib
│   ├── adaboost.joblib
│   ├── logistic_regression.joblib
│   ├── ridge_classifier.joblib
│   ├── gaussian_naive_bayes.joblib
│   └── extra_tree.joblib
├── URL dataset.csv                 # Dataset sumber URL
└── Phishing URLs.csv               # Dataset sumber Phishing tambahan
```
