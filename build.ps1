# Neptune Scanner Build Script

# Create obj directory if it doesn't exist
if (-not (Test-Path -Path "obj")) {
    New-Item -Path "obj" -ItemType Directory -Force | Out-Null
    Write-Host "Created obj directory"
}

# Clean previous build
Write-Host "Cleaning previous build..."
Remove-Item -Path "obj\*.o" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "neptunescan.exe" -Force -ErrorAction SilentlyContinue

# Compile all source files
Write-Host "Compiling source files..."
$sourceFiles = Get-ChildItem -Path "src" -Filter "*.c"
$compileErrors = 0

foreach ($file in $sourceFiles) {
    $objFile = "obj\" + $file.BaseName + ".o"
    $command = "gcc -Wall -Wextra -g -I./include -c src/$($file.Name) -o $objFile"
    
    Write-Host "Compiling $($file.Name)..."
    $result = Invoke-Expression $command
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error compiling $($file.Name)" -ForegroundColor Red
        $compileErrors++
    }
}

# If there were compile errors, exit
if ($compileErrors -gt 0) {
    Write-Host "Build failed with $compileErrors error(s)" -ForegroundColor Red
    exit 1
}

# Link object files
Write-Host "Linking object files..."
$objFiles = (Get-ChildItem -Path "obj" -Filter "*.o" | ForEach-Object { "obj\" + $_.Name }) -join " "
$linkCommand = "gcc $objFiles -o neptunescan.exe -lws2_32 -liphlpapi"
$result = Invoke-Expression $linkCommand

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error linking object files" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Executable: neptunescan.exe" 