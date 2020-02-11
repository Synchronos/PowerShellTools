#Requires -Version 2.0
# (c) 2014 James Coe. All rights reserved.

<#
.SYNOPSIS
    Writes a file to the Windows clipboard as Base-64Encoded text.
.DESCRIPTION
    Writes a file to the Windows clipboard as Base-64Encoded text.
.PARAMETER FileName
    The name of the file to encode and place on the Windows clipboard.
.EXAMPLE
    Write-Base64EncodedFileToClipboard MyZipFile.zip
#>
function Write-Base64EncodedFileToClipboard {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline = $false)]
        [string]$FileName
    )

    process {
        $FileName = [System.IO.Path]::Combine($(Get-Location), $FileName)
        $fileExists = Test-Path "$FileName"

        If ($fileExists -eq $true)
        {
            [PSCustomObject] $fileHash = $null
            If (($host.Version.Major -ge 4)) {
                $fileHash = Get-FileHash "$FileName"
            }

            [byte[]] $fileBytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($(Get-Location), $FileName))
            [string] $base64String = [Convert]::ToBase64String($fileBytes)
            [string] $header = "==Base64EncodedFile==`n$([System.IO.Path]::GetFileName($FileName))`n$($fileBytes.Length)`n$($base64String.Length)`n$($fileHash.Hash)`n"
            [System.Windows.Forms.Clipboard]::SetText($header + $base64String)

            Write-Verbose "Filename: $FileName"
            Write-Verbose "Bytes: $($fileBytes.Length)"
            Write-Verbose "Encoded Size: $($base64String.Length)"
            Write-Verbose "Hash: $($fileHash.Hash)"
        }
        Else {
            Write-Error "$FileName does not exist."
        }
    }
}

<#
.SYNOPSIS
    Gets a Base-64 encoded file from the Windows clipboard and decodes it.
.DESCRIPTION
    Gets a Base-64 encoded file from the Windows clipboard and decodes it. If no filename is specified the file is written to the current working directory with the original filename.
.PARAMETER FileName
    The name of the file.
.EXAMPLE
    Get-Base64EncodedFileFromClipboard
.EXAMPLE
    Get-Base64EncodedFileFromClipboard MyNewZipFile.zip
#>
function Get-Base64EncodedFileFromClipboard {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [string]$FileName = ''
    )

    process {
        [string[]] $clipboardStrings =  [System.Windows.Forms.Clipboard]::GetText().Split("`n")
        If ($clipboardStrings.Length -lt 6 -or $clipboardStrings[0] -ne '==Base64EncodedFile==') {
            Write-Error 'The clipboard did not contain the expected content.'
        }
        Else {
            [string] $originalFileName = $clipBoardStrings[1]
            [int]$expectedFileLength = $clipboardStrings[2]
            [int]$expectedBase64EncodedLength = $clipboardStrings[3]
            [string] $expectedFileHash = $clipboardStrings[4]
            [string] $base64String = [string]::Join("`n", $($clipBoardStrings | Select -Skip 5))

            Write-Verbose "Original Filename: $originalFileName"
            Write-Verbose "Expected Bytes: $expectedFileLength"
            Write-Verbose "Expected Encoded Size: $expectedBase64EncodedLength"
            Write-Verbose "Expected Hash: $expectedFileHash"

            If ($fileName -eq '') {
                $fileName = $originalFileName
            }

            $fileName = [System.IO.Path]::Combine($(Get-Location), $fileName)

            If ($base64String.Length -eq $expectedBase64EncodedLength) {
                [byte[]] $fileBytes = [Convert]::FromBase64String($base64String)

                If ($fileBytes.Length -eq $expectedFileLength) {
                    [System.IO.File]::WriteAllBytes($fileName, $fileBytes)

                    [PSCustomObject] $fileHash = $null
                    If (($host.Version.Major -ge 4) -and ($expectedFileHash -ne '')) {
                        $fileHash = Get-FileHash "$fileName"
                        If ($fileHash.Hash -eq $expectedFileHash) {
                            Write-Verbose "File hash verified."
                        }
                        Else {
                            del $fileName
                            Write-Error "The file hash did not match the expected value. The file has been deleted."
                        }
                    }
                    Else {
                        Write-Verbose "No file hash check was performed."
                    }

                    Write-Verbose "Filename: $fileName"
                    Write-Verbose "Bytes: $($fileBytes.Length)"
                    Write-Verbose "Encoded Size: $($base64String.Length)"
		    Write-Verbose "Hash: $($fileHash.Hash)"
                }
                Else {
                    Write-Error "The file content lengths did not match. No file was written."
                }
            }
            Else {
                Write-Error "The base-64 encoded lengths did not match. No file was written."
            }

            [System.Windows.Forms.Clipboard]::Clear()
        }
    }
}

<#
.SYNOPSIS
    Writes a script to create and import the ClipboardFileTransfer module to the Windows clipboard.
.DESCRIPTION
    Writes a script to create and import the ClipboardFileTransfer module to the Windows clipboard. Open a PowerShell Window on a remote system and paste the clipboard contents into it.
.EXAMPLE
    Write-BootstrapScriptToClipboard
#>
function Write-BootstrapScriptToClipboard {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
    )
    
    process {
        $script = "[HashTable] `$items = New-Object HashTable`n"
        $script += "cd `"`$([Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments))`"`n"
        $script += "If (`$(Test-Path WindowsPowerShell) -eq `$false) {`n"
        $script += "    mkdir WindowsPowerShell`n"
        $script += "}`n"
        $script += "cd WindowsPowerShell`n"
        $script += "If (`$(Test-Path Modules) -eq `$false) {`n"
        $script += "    mkdir Modules`n"
        $script += "}`n"
        $script += "cd Modules`n"
        $script += "If (`$(Test-Path ClipboardFileTransfer) -eq `$false) {`n"
        $script += "    mkdir ClipboardFileTransfer`n"
        $script += "}`n"
        $script += "cd ClipboardFileTransfer`n"
        $script += dir "$PSScriptRoot" | ForEach { "`$items.Add('$_', '$([System.IO.File]::ReadAllText([System.IO.Path]::Combine("$PSScriptRoot", "$_")).Replace("'", "''"))')`n" }
        $script += 'ForEach ($item In $items.GetEnumerator()) { [System.IO.File]::WriteAllText([System.IO.Path]::Combine($(Get-Location), $item.Key), $item.Value) }'
        $script += "`nImport-Module ClipboardFileTransfer`n"
        [System.Windows.Forms.Clipboard]::SetText($script)
        Write-Host "A script to create and import the ClipboardFileTransfer module has been placed on the clipboard."
        Write-Host "Open a PowerShell Window on the remote system and paste the clipboard contents into it."
    }
}
