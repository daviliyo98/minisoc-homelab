# subir.ps1 - Sube los cambios del repositorio MINISOC a GitHub con control de secretos
# Uso manual:     .\subir.ps1 "Mensaje del commit"
# Uso programado: sin mensaje (usa fecha y hora)
param([string]$Mensaje = "Actualización MINISOC $(Get-Date -Format 'yyyy-MM-dd HH:mm')")

Set-Location $PSScriptRoot
Start-Transcript -Path "$PSScriptRoot\subir.log" -Append | Out-Null

git add -A
$archivos = @(git diff --cached --name-only)
if ($archivos.Count -eq 0) {
    Write-Host "Sin cambios que subir."
    Stop-Transcript | Out-Null
    exit 0
}

# --- Control de seguridad 1: tipos de archivo prohibidos ---
$prohibidos = $archivos | Where-Object {
    $_ -match '(\.env$|\.zip$|\.tar\.gz$|\.pem$|\.key$|\.kdbx$|\.db$|teleporter|backup)' -and
    $_ -notmatch '\.env\.example$'
}

# --- Control de seguridad 2: contenido con aspecto de secreto ---
$sospechoso = git diff --cached -U0 | Select-String -Pattern @(
    'BEGIN [A-Z ]*PRIVATE KEY',
    'password\s*[:=]\s*["'']?[^\s"''$]{6,}',
    'ghp_[A-Za-z0-9]{20,}',
    'tskey-[A-Za-z0-9-]{10,}'
) | Where-Object { $_.Line -notmatch 'cambia-esto' }

if ($prohibidos -or $sospechoso) {
    git reset -q
    Write-Host "BLOQUEADO: posible secreto detectado. No se ha subido nada." -ForegroundColor Red
    $prohibidos | ForEach-Object { Write-Host "  Archivo: $_" -ForegroundColor Red }
    $sospechoso | ForEach-Object { Write-Host "  Contenido: $($_.Line)" -ForegroundColor Red }
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host "Archivos que se van a subir:"
$archivos | ForEach-Object { Write-Host "  $_" }

git commit -q -m $Mensaje
git push -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "Subido a GitHub: $Mensaje" -ForegroundColor Green
} else {
    Write-Host "Error al hacer push (revisa la conexión o las credenciales)." -ForegroundColor Red
}
Stop-Transcript | Out-Null
