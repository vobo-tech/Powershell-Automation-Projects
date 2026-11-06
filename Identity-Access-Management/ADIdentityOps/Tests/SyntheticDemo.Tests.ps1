#Requires -Modules Pester
param()

Describe 'Invoke-SyntheticDemo.ps1' {
    It 'runs end to end in a separate process, passes its own self-checks, and writes JSON, CSV, and HTML evidence' {
        # A separate PowerShell process isolates the adapter's global stand-ins from the Pester host.
        $demo = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Demo/Invoke-SyntheticDemo.ps1'
        $out = Join-Path $TestDrive 'demo'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $sentinel = Join-Path $out 'keep.txt'
        Set-Content -Path $sentinel -Value 'preserve existing caller data'
        $exe = (Get-Process -Id $PID).Path
        $log = & $exe -NoProfile -NonInteractive -File $demo -OutputDirectory $out 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0 -Because $log
        $log | Should -Match 'SIMULATED'
        $log | Should -Not -Match 'self-check failed'
        (Get-Content -Path $sentinel -Raw).Trim() | Should -Be 'preserve existing caller data'

        # Existing caller data must survive, and each required evidence format must be produced.
        $runDirectory = Get-ChildItem -Path $out -Directory -Filter 'run-*' | Select-Object -First 1
        $reports = Join-Path $runDirectory.FullName 'reports'
        @(Get-ChildItem -Path $reports -Filter '*.json').Count | Should -Be 1
        @(Get-ChildItem -Path $reports -Filter '*-actions.csv').Count | Should -Be 1
        $html = Get-Content -Path (Get-ChildItem -Path $reports -Filter '*.html' | Select-Object -First 1).FullName -Raw
        $html | Should -Match 'SIMULATED'
        $html | Should -Not -Match '<script'
    }
}
