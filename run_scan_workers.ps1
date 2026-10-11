# Uruchamia 12 kontenerow skanujacych matrix_part_0..11.
# Wymaga: zbudowanego obrazu (domyslnie cia-scanner) oraz wczesniej:
#   docker run --rm -v "${PWD}:/app" -w /app cia-scanner python src/Scan.py freeze-db
#   python src/Scan.py split
#
# Uzycie:
#   .\run_scan_workers.ps1
#   .\run_scan_workers.ps1 -Image cia-scanner -Parts 12

param(
    [string]$Image = "cia-scanner",
    [int]$Parts = 12
)

$ErrorActionPreference = "Stop"
$Root = (Get-Location).Path

$names = @()
for ($i = 0; $i -lt $Parts; $i++) {
    $name = "cia-scan-$i"
    $names += $name

    # docker rm pisze na stderr gdy kontenera nie ma - nie przerywaj skryptu
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    docker rm -f $name 2>$null | Out-Null
    $ErrorActionPreference = $prev

    Write-Host "start $name (part $i)"
    # TMPDIR musi istniec w kontenerze - Trivy tworzy w nim cache warstw.
    docker run -d --name $name `
        -v "${Root}:/app" -w /app `
        -e "TMPDIR=/tmp/trivy" `
        $Image `
        bash -c "mkdir -p /tmp/trivy && python src/Scan.py run --part $i" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "docker run nie wystartowal $name (exit $LASTEXITCODE)"
    }
}

Write-Host "czekam na $($names.Count) kontenerow..."
docker wait @names | Out-Null

foreach ($name in $names) {
    $code = docker inspect $name --format "{{.State.ExitCode}}"
    Write-Host "$name exit=$code"
}

Write-Host "usuwam kontenery"
docker rm @names | Out-Null

Write-Host "scalanie wynikow"
# Logi Pythona na stderr nie moga zabijac skryptu przy $ErrorActionPreference=Stop
$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker run --rm -v "${Root}:/app" -w /app $Image python src/Scan.py merge --parts $Parts
$mergeExit = $LASTEXITCODE
docker run --rm -v "${Root}:/app" -w /app $Image python src/Scan.py status --parts $Parts
$ErrorActionPreference = $prev
if ($mergeExit -ne 0) {
    throw "merge zakonczyl sie kodem $mergeExit"
}
Write-Host "gotowe -> results/scans.jsonl"
Write-Host "CAMPAIGN_OK"
