@echo off
setlocal enabledelayedexpansion
title Otomatisasi Git Push ke GitHub - Kelompok 1

cd /d "%~dp0"

echo ======================================================================
echo       AUTOMATED GITHUB PUSH - PROYEK KEAMANAN DATA [KELOMPOK 1]
echo ======================================================================
echo.

:: 1. Deteksi Lokasi Git di Windows
set "GIT_EXE="

:: Cek apakah git ada di PATH sistem
where git >nul 2>nul
if %errorlevel% equ 0 set "GIT_EXE=git"

:: Cek instalasi GitHub Desktop
if not defined GIT_EXE (
    for /d %%D in ("%LOCALAPPDATA%\GitHubDesktop\app-*") do (
        if exist "%%D\resources\app\git\cmd\git.exe" set "GIT_EXE=%%D\resources\app\git\cmd\git.exe"
    )
)

:: Cek Codex Runtime jika ada
if not defined GIT_EXE (
    if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe" (
        set "GIT_EXE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe"
    )
)

:: Cek folder program umum
if not defined GIT_EXE if exist "%ProgramFiles%\Git\cmd\git.exe" set "GIT_EXE=%ProgramFiles%\Git\cmd\git.exe"
if not defined GIT_EXE if exist "C:\Program Files\Git\cmd\git.exe" set "GIT_EXE=C:\Program Files\Git\cmd\git.exe"
if not defined GIT_EXE if exist "C:\Program Files (x86)\Git\cmd\git.exe" set "GIT_EXE=C:\Program Files (x86)\Git\cmd\git.exe"
if not defined GIT_EXE if exist "%LOCALAPPDATA%\Programs\Git\cmd\git.exe" set "GIT_EXE=%LOCALAPPDATA%\Programs\Git\cmd\git.exe"

:: Jika tetap tidak ditemukan, pergi ke handler error
if not defined GIT_EXE goto :no_git

echo [*] Menggunakan Git: "!GIT_EXE!"
echo [*] Direktori Kerja: "%CD%"
echo.

:: 2. Cek apakah folder sudah merupakan repository git
if exist ".git" goto :git_ready

echo [*] Folder ini belum terhubung dengan Git [.git belum ada].
echo [*] Menyiapkan inisialisasi dan sinkronisasi ke repositori GitHub...
echo.
echo Masukkan URL GitHub repository [Tekan Enter untuk default]:
echo Default: https://github.com/ImStevanus/Phising-URL-Detection.git
set "REPO_URL="
set /p REPO_URL="URL GitHub: "
if "!REPO_URL!"=="" set "REPO_URL=https://github.com/ImStevanus/Phising-URL-Detection.git"

echo.
echo [*] Menginisialisasi Git repository...
"!GIT_EXE!" init
"!GIT_EXE!" branch -M main
"!GIT_EXE!" remote add origin "!REPO_URL!"
echo [OK] Remote origin diatur ke: !REPO_URL!

echo [*] Mengambil informasi dan riwayat dari GitHub...
"!GIT_EXE!" fetch origin main 2>nul
if !errorlevel! equ 0 (
    echo [*] Menyelaraskan status awal dengan GitHub branch main...
    "!GIT_EXE!" reset origin/main 2>nul
)
echo.

:git_ready

:: 3. Tambahkan semua perubahan (file baru, file dimodifikasi, dan file yang dihapus)
echo [*] Memeriksa perubahan, file baru, dan file yang dihapus...
"!GIT_EXE!" add -A

:: Cek apakah ada perubahan yang perlu di-commit
set "HAS_CHANGES="
for /f "tokens=*" %%S in ('"!GIT_EXE!" status --porcelain') do (
    set "HAS_CHANGES=1"
)

if not defined HAS_CHANGES (
    echo.
    echo ======================================================================
    echo   [INFO] Status repositori lokal sudah 100%% sinkron dengan GitHub.
    echo   Tidak ada file baru, file berubah, atau file sampah yang dihapus.
    echo ======================================================================
    echo.
    pause
    exit /b 0
)

:: Tampilkan rincian file yang berubah / dihapus
echo.
echo [*] Rincian file yang akan disinkronkan ke GitHub:
echo ----------------------------------------------------------------------
for /f "tokens=1,2*" %%A in ('"!GIT_EXE!" status --porcelain') do (
    if "%%A"=="A"  echo   [+] File Baru Ditemukan : %%B %%C
    if "%%A"=="M"  echo   [*] File Telah Berubah  : %%B %%C
    if "%%A"=="D"  echo   [-] File Akan Dihapus   : %%B %%C [tidak ada di folder saat ini]
    if "%%A"=="R"  echo   [R] File Ganti Nama     : %%B %%C
    if "%%A"=="??" echo   [+] File Baru Ditemukan : %%B %%C
)
echo ----------------------------------------------------------------------
echo.

:: 4. Hitung nomor commit otomatis
set /a NEXT_NUM=1
for /f "tokens=*" %%C in ('"!GIT_EXE!" rev-list --count HEAD 2^>nul') do (
    set /a NEXT_NUM=%%C + 1
)

:: 5. Meminta pesan commit
echo Tekan [Enter] untuk menggunakan judul otomatis: 'Updated Project !NEXT_NUM!'
set "COMMIT_MSG="
set /p COMMIT_MSG="Atau ketik pesan commit kustom: "

:: Bersihkan spasi kosong; jika kosong pakai default
set "CHECK_EMPTY=!COMMIT_MSG: =!"
if "!CHECK_EMPTY!"=="" (
    set "COMMIT_MSG=Updated Project !NEXT_NUM!"
)

echo.
echo [*] Menyimpan commit lokal: "!COMMIT_MSG!"
"!GIT_EXE!" commit -m "!COMMIT_MSG!"
if !errorlevel! neq 0 (
    echo [ERROR] Gagal membuat commit lokal.
    pause
    exit /b 1
)

:: 6. Melakukan Push ke GitHub (dengan auto pull-rebase jika remote mendahului)
echo.
echo [*] Mengunggah [Push] perubahan ke GitHub branch main...
"!GIT_EXE!" push origin main
set "PUSH_STATUS=!errorlevel!"

if !PUSH_STATUS! neq 0 (
    echo.
    echo [*] Sinkronisasi dengan riwayat remote GitHub [pull --rebase]...
    "!GIT_EXE!" pull --rebase origin main
    echo [*] Mengunggah ulang ke branch main...
    "!GIT_EXE!" push origin main
    set "PUSH_STATUS=!errorlevel!"
)

if !PUSH_STATUS! neq 0 (
    echo [*] Mencoba alternatif push ke branch master...
    "!GIT_EXE!" push origin master
    set "PUSH_STATUS=!errorlevel!"
)

if !PUSH_STATUS! equ 0 (
    echo.
    echo ======================================================================
    echo   [BERHASIL] Seluruh perubahan berhasil di-push ke GitHub!
    echo   - File baru dan perubahan telah terunggah.
    echo   - File yang tidak ada di folder lokal telah dihapus dari GitHub.
    echo   - Judul Commit: "!COMMIT_MSG!"
    echo ======================================================================
) else (
    echo.
    echo ======================================================================
    echo   [PERHATIAN] Terjadi kendala saat push ke GitHub.
    echo   Kemungkinan penyebab:
    echo   1. Koneksi internet terputus.
    echo   2. Kredensial akun GitHub belum terhubung di komputer ini.
    echo ======================================================================
)

echo.
pause
exit /b 0

:no_git
echo ======================================================================
echo   [ERROR] Git tidak ditemukan pada komputer ini.
echo ======================================================================
echo   Agar skrip ini dapat berjalan:
echo   1. Unduh dan pasang Git for Windows dari: https://git-scm.com/
echo      atau pasang GitHub Desktop dari: https://desktop.github.com/
echo   2. Jalankan kembali berkas push_to_github.bat ini setelah instalasi.
echo ======================================================================
echo.
pause
exit /b 1
