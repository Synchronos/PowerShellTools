#Requires -Version 2.0
# (c) 2014 James Coe. All rights reserved.

[bool] $isFullLanguage = $true
If ($host.Version.Major -ge 3) {
    Try {
        $isFullLanguage = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')
    }
    Catch {
        $isFullLanguage = $false
    }
}

If ($isFullLanguage -eq $false) {
    Write-Error "The language mode must be full language to use the ClipboardFileTransfer module."
    Exit 1
}

[bool] $IsSTAEnabled = $host.Runspace.ApartmentState -eq 'STA'
If ($IsSTAEnabled -eq $false) {
    Write-Error "PowerShell must be started with the -STA switch or inside ISE to use the ClipboardFileTransfer module."
    Exit 2
}
