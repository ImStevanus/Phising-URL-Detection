#!/usr/bin/env bash
# Otomatisasi Git Push ke GitHub untuk macOS / Linux - Kelompok 1

cd "$(dirname "$0")" || exit 1

echo "======================================================================"
echo "      AUTOMATED GITHUB PUSH - PROYEK KEAMANAN DATA (KELOMPOK 1)"
echo "======================================================================"
echo ""

# 1. Cek ketersediaan Git
if ! command -v git &> /dev/null; then
    echo "[ERROR] Git belum terpasang di perangkat ini!"
    echo "Silakan pasang Git terlebih dahulu (misal via 'brew install git' di Mac atau 'sudo apt install git' di Linux)."
    exit 1
fi

# 2. Cek apakah folder merupakan repository git
if [ ! -d ".git" ]; then
    echo "[*] Folder ini belum terhubung dengan Git (.git belum ada)."
    echo "[*] Menyiapkan inisialisasi dan sinkronisasi ke repositori GitHub..."
    echo ""
    read -p "Masukkan URL GitHub repository [Tekan Enter untuk default: https://github.com/ImStevanus/Phising-URL-Detection.git]: " REPO_URL
    if [ -z "$REPO_URL" ]; then
        REPO_URL="https://github.com/ImStevanus/Phising-URL-Detection.git"
    fi
    git init
    git branch -M main
    git remote add origin "$REPO_URL"
    echo "[OK] Remote origin diatur ke: $REPO_URL"
    
    echo "[*] Mengambil informasi dan riwayat dari GitHub..."
    if git fetch origin main 2>/dev/null; then
        echo "[*] Menyelaraskan status awal dengan GitHub branch main..."
        git reset origin/main 2>/dev/null
    fi
    echo ""
fi

# 3. Tambahkan semua perubahan termasuk file yang dihapus
echo "[*] Memeriksa perubahan, file baru, dan file yang dihapus..."
git add -A

if git diff --cached --quiet; then
    echo ""
    echo "======================================================================"
    echo "  [INFO] Status repositori lokal sudah 100% sinkron dengan GitHub."
    echo "  Tidak ada file baru, file berubah, atau file sampah yang dihapus."
    echo "======================================================================"
    echo ""
    exit 0
fi

# Tampilkan rincian file yang berubah / dihapus
echo ""
echo "[*] Rincian file yang akan disinkronkan ke GitHub:"
echo "----------------------------------------------------------------------"
git status --short
echo "----------------------------------------------------------------------"
echo ""

# 4. Hitung nomor commit otomatis
COUNT=$(git rev-list --count HEAD 2>/dev/null || echo 0)
NEXT_NUM=$((COUNT + 1))

# 5. Meminta pesan commit
echo "Tekan [Enter] untuk menggunakan judul otomatis: 'Updated Project $NEXT_NUM'"
read -p "Atau ketik pesan commit kustom: " COMMIT_MSG
if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Updated Project $NEXT_NUM"
fi

echo ""
echo "[*] Menyimpan commit lokal: '$COMMIT_MSG'"
git commit -m "$COMMIT_MSG"

# 6. Push ke GitHub
echo ""
echo "[*] Mengunggah (Push) perubahan ke GitHub branch main..."
if git push origin main; then
    PUSH_OK=1
elif git pull --rebase origin main && git push -u origin main; then
    PUSH_OK=1
elif git push -u origin master; then
    PUSH_OK=1
else
    PUSH_OK=0
fi

if [ "$PUSH_OK" -eq 1 ]; then
    echo ""
    echo "======================================================================"
    echo "  [BERHASIL] Seluruh perubahan berhasil di-push ke GitHub!"
    echo "  - File baru dan perubahan telah terunggah."
    echo "  - File yang tidak ada di folder lokal telah dihapus dari GitHub."
    echo "  - Judul Commit: '$COMMIT_MSG'"
    echo "======================================================================"
else
    echo ""
    echo "======================================================================"
    echo "  [PERHATIAN] Terjadi kendala saat push ke GitHub."
    echo "  Pastikan koneksi internet aktif dan kredensial login tersedia."
    echo "======================================================================"
fi
echo ""
