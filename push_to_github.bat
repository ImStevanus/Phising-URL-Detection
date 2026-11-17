@echo off
setlocal enabledelayedexpansion
title Otomatisasi Git Push ke GitHub - Kelompok 1

cd /d "%~dp0"

echo ======================================================================
echo       AUTOMATED GITHUB PUSH - PROYEK KEAMANAN DATA (KELOMPOK 1)
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
echo.

:: 2. Cek apakah folder sudah merupakan repository git
if not exist ".git" (
    echo [*] Repository lokal .git belum ditemukan di folder ini.
    echo.
    echo Silakan masukkan URL repository GitHub Anda:
    echo Contoh: https://github.com/username/Phising-URL-Detection.git
    set /p REPO_URL="URL GitHub: "
    
    if "!REPO_URL!"=="" (
        echo [ERROR] URL GitHub tidak boleh kosong.
        pause
        exit /b 1
    )

    echo.
    echo [*] Menginisialisasi Git repository...
    "!GIT_EXE!" init
    "!GIT_EXE!" branch -M main
    "!GIT_EXE!" remote add origin "!REPO_URL!"
    echo [OK] Remote origin diatur ke: !REPO_URL!
    echo.
)

:: 3. Tambahkan semua perubahan termasuk file yang dihapus
echo [*] Memeriksa perubahan dan penghapusan file sampah...
"!GIT_EXE!" add -A

:: Cek apakah ada perubahan yang perlu di-commit
"!GIT_EXE!" status --porcelain > "%temp%\git_status.tmp"
set /p HAS_CHANGES=<"%temp%\git_status.tmp"
del "%temp%\git_status.tmp" 2>nul

if "!HAS_CHANGES!"=="" (
    echo.
    echo [INFO] Tidak ada file baru, perubahan, atau file yang dihapus.
    echo Status repositori Anda sudah sinkron dengan yang terbaru di GitHub.
    echo.
    pause
    exit /b 0
)

:: 4. Hitung nomor commit otomatis
set /a NEXT_NUM=1
for /f "tokens=*" %%C in ('"!GIT_EXE!" rev-list --count HEAD 2^>nul') do (
    set /a NEXT_NUM=%%C + 1
)

:: 5. Meminta pesan commit
echo.
set "COMMIT_MSG="
set /p COMMIT_MSG="Masukkan pesan commit [Tekan Enter untuk 'Updated Project !NEXT_NUM!']: "

if "!COMMIT_MSG!"=="" (
    set "COMMIT_MSG=Updated Project !NEXT_NUM!"
)

echo.
echo [*] Melakukan commit dengan pesan: "!COMMIT_MSG!"
"!GIT_EXE!" commit -m "!COMMIT_MSG!"

:: 6. Melakukan Push ke GitHub
echo.
echo [*] Mengunggah (Push) ke GitHub branch main...
"!GIT_EXE!" push -u origin main
if %errorlevel% neq 0 (
    echo.
    echo [*] Mencoba push ke branch master...
    "!GIT_EXE!" push -u origin master
)

if %errorlevel% equ 0 (
    echo.
    echo ======================================================================
    echo   [BERHASIL] Seluruh perubahan berhasil di-push ke GitHub.
    echo   File-file sampah yang telah dihapus lokal kini juga terhapus di GitHub.
    echo   Commit: "!COMMIT_MSG!"
    echo ======================================================================
) else (
    echo.
    echo ======================================================================
    echo   [PERHATIAN] Terjadi kendala saat push ke GitHub.
    echo   Pastikan koneksi internet aktif dan izin akses login GitHub tersedia.
    echo ======================================================================
)

echo.
pause
exit /b 0

:no_git
echo [ERROR] Git tidak ditemukan pada komputer ini.
echo ======================================================================
echo Agar skrip ini dapat berjalan:
echo 1. Unduh dan pasang Git for Windows dari: https://git-scm.com/
echo    atau pasang GitHub Desktop dari: https://desktop.github.com/
echo 2. Buka kembali file push_to_github.bat ini setelah instalasi selesai.
echo ======================================================================
echo.
pause
exit /b 1
