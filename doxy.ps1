if (!(Test-Path docs)) { New-Item -ItemType Directory -Path docs -Force | Out-Null }

Write-Host "Deploying documentation assets..." -ForegroundColor Cyan
Copy-Item -Path "doxygen/*" -Destination "docs/" -Force

if (!(Test-Path docs/doxygen-awesome-css)) {
    Write-Host "Doxygen Awesome CSS missing. Downloading..." -ForegroundColor Yellow
    git clone https://github.com/jothepro/doxygen-awesome-css.git docs/doxygen-awesome-css
}

Write-Host "Cleaning old documentation..." -ForegroundColor Cyan
if (Test-Path docs/gen) { Remove-Item -Recurse -Force docs/gen }
New-Item -ItemType Directory -Path docs/gen -Force | Out-Null

Write-Host "Running Doxygen..." -ForegroundColor Green
doxygen DOXYFILE

Write-Host "Documentation generated at: docs/gen/html/index.html" -ForegroundColor Green
Write-Host "Opening documentation..." -ForegroundColor Cyan
Start-Process "docs/gen/html/index.html"
