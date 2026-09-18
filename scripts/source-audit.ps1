$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$excludedDirectories = @('.git', '.mooncakes', '_build')
$files = Get-ChildItem -LiteralPath $repository -Recurse -File -Filter '*.mbt' |
  Where-Object {
    $relative = [IO.Path]::GetRelativePath($repository, $_.FullName)
    $segments = $relative -split '[\\/]'
    $isExcludedDirectory = $false
    foreach ($directory in $excludedDirectories) {
      if ($segments -contains $directory) {
        $isExcludedDirectory = $true
        break
      }
    }
    -not $isExcludedDirectory -and
      $_.Name -notmatch '(_test|_wbtest)\.mbt$'
  } |
  Sort-Object FullName

$total = 0
foreach ($file in $files) {
  $effective = (Get-Content -LiteralPath $file.FullName -Encoding UTF8 |
    Where-Object {
      $line = $_.Trim()
      $line -ne '' -and -not $line.StartsWith('//')
    }).Count
  $total += $effective
  $relative = [IO.Path]::GetRelativePath($repository, $file.FullName)
  Write-Output ("{0}: {1}" -f $relative, $effective)
}

Write-Output ("Effective production MoonBit lines: {0}" -f $total)
if ($total -lt 1000) {
  Write-Error "Production MoonBit source must remain at or above 1000 effective lines."
  exit 1
}
