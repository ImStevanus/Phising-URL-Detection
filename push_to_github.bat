@echo off
setlocal enabledelayedexpansion
title Otomatisasi Git Push ke GitHub - Kelompok 1

cd /d "%~dp0"

echo ======================================================================
echo       AUTOMATED GITHUB PUSH - PROYEK KEAMANAN DATA (KELOMPOK 1)
echo ======================================================================
echo.

:: 1. Deteksi Lokasi Git
set "GIT_EXE=git"
where git >nul 2>nul
if %errorlevel% neq 0 (
    if exist "%LOCALAPPDATA%\GitHubDesktop\app-3.5.4\resources\app\git\cmd\git.exe" (
        set "GIT_EXE=%LOCALAPPDATA%\GitHubDesktop\app-3.5.4\resources\app\git\cmd\git.exe"
    ) else if exist "%ProgramFiles%\Git\cmd\git.exe" (
        set "GIT_EXE=%ProgramFiles%\Git\cmd\git.exe"
    ) else (
        for /d %%D in ("%LOCALAPPDATA%\GitHubDesktop\app-*") do (
            if exist "%%D\resources\app\git\cmd\git.exe" (
                set "GIT_EXE=%%D\resources\app\git\cmd\git.exe"
            )
        )
    )
)

echo [*] Menggunakan Git: "!GIT_EXE!"
echo.

:: 2. Cek apakah folder sudah merupakan repository git
if not exist ".git" (
    echo [!] Repository lokal belum diinisialisasi.
    echo.
    echo Silakan masukkan URL repository GitHub Anda
    echo (Contoh: https://github.com/username/uas-keamanan-data.git)
    set /p REPO_URL="URL GitHub: "
    
    if "!REPO_URL!"=="" (
        echo [ERROR] URL GitHub tidak boleh kosong!
        pause
        exit /b 1
    )

    echo.
    echo [*] Menginisialisasi Git repository...
    "!GIT_EXE!" init
    "!GIT_EXE!" branch -M main
    "!GIT_EXE!" remote add origin "!REPO_URL!"
    echo [OK] Remote origin berhasil diatur ke: !REPO_URL!
    echo.
)

:: 3. Tambahkan semua perubahan
echo [*] Memeriksa dan menambahkan file perubahan (git add)...
"!GIT_EXE!" add .

:: Cek status apakah ada perubahan
"!GIT_EXE!" status --porcelain > "%temp%\git_status.tmp"
set /p HAS_CHANGES=<"%temp%\git_status.tmp"
del "%temp%\git_status.tmp" 2>nul

if "!HAS_CHANGES!"=="" (
    echo.
    echo [INFO] Tidak ada file baru atau perubahan yang perlu di-push.
    echo Status repository Anda sudah sinkron dengan yang terbaru!
    echo.
    pause
    exit /b 0
)

:: 4. Hitung nomor commit otomatis (Updated Project 1, 2, 3, dst.)
set /a NEXT_NUM=1
for /f "tokens=*" %%C in ('"!GIT_EXE!" rev-list --count HEAD 2^>nul') do (
    set /a NEXT_NUM=%%C + 1
)

:: 5. Meminta pesan commit (opsional)
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
echo [*] Mengunggah (Push) ke GitHub (branch: main)...
"!GIT_EXE!" push -u origin main
if %errorlevel% neq 0 (
    echo.
    echo [*] Mencoba push ke branch master...
    "!GIT_EXE!" push -u origin master
)

if %errorlevel% equ 0 (
    echo.
    echo ======================================================================
    echo   [BERHASIL] Seluruh perubahan berhasil di-push ke GitHub!
    echo   Commit: "!COMMIT_MSG!"
    echo ======================================================================
) else (
    echo.
    echo ======================================================================
    echo   [GAGAL] Terjadi kendala saat push ke GitHub.
    echo   Pastikan koneksi internet aktif dan Anda telah login/memberi izin.
    echo ======================================================================
)

echo.
pause
