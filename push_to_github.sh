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
    echo "[!] Repository lokal (.git) belum ditemukan."
    echo "Silakan masukkan URL repository GitHub Anda:"
    read -r REPO_URL
    if [ -z "$REPO_URL" ]; then
        echo "[ERROR] URL GitHub tidak boleh kosong!"
        exit 1
    fi
    git init
    git branch -M main
    git remote add origin "$REPO_URL"
    echo "[OK] Remote origin diatur ke: $REPO_URL"
fi

# 3. Tambahkan semua perubahan termasuk file yang dihapus
echo "[*] Memeriksa perubahan dan file terhapus (git add -A)..."
git add -A

if git diff --cached --quiet; then
    echo ""
    echo "[INFO] Tidak ada file baru, perubahan, atau penghapusan yang perlu di-push."
    echo "Status repositori sudah sinkron dengan GitHub!"
    exit 0
fi

# 4. Hitung nomor commit
COUNT=$(git rev-list --count HEAD 2>/dev/null || echo 0)
NEXT_NUM=$((COUNT + 1))

# 5. Pesan commit
echo ""
read -p "Masukkan pesan commit [Tekan Enter untuk 'Updated Project $NEXT_NUM']: " COMMIT_MSG
if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Updated Project $NEXT_NUM"
fi

echo "[*] Melakukan commit: '$COMMIT_MSG'"
git commit -m "$COMMIT_MSG"

# 6. Push ke GitHub
echo "[*] Mengunggah (Push) ke GitHub..."
if git push -u origin main; then
    echo "======================================================================"
    echo "  [BERHASIL] Seluruh perubahan berhasil di-push ke GitHub!"
    echo "  Commit: '$COMMIT_MSG'"
    echo "======================================================================"
else
    git push -u origin master
fi
