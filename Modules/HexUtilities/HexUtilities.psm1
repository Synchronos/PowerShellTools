$encodingAutoCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $availableEncodings = ([System.Text.Encoding]::GetEncodings() | Select Name, CodePage, DisplayName) + @( [PSCustomObject] @{ CodePage = '20127'; Name = 'ascii'; DisplayName = 'US-ASCII' }, [PSCustomObject] @{ CodePage = '1200'; Name = 'unicode'; DisplayName = 'Unicode' } )
    $availableEncodings | ?{ $_.Name.StartsWith($wordToComplete) } | %{ New-Object System.Management.Automation.CompletionResult -ArgumentList $_.Name, $_.Name, 'ParameterValue', "$($_.DisplayName). Codpage $($_.CodePage)." }
}

function Format-BufferText([byte[]] $buffer, [System.Text.Encoding] $displayEncoding, [switch] $useControlPictures)
{
    $bufferChars = $displayEncoding.GetChars($buffer);
    $bufferText = (($bufferChars | %{ if ([char]::IsControl($_) -eq $true) { if ($useControlPictures -eq $false) { '.' } else { [char] ($_.ToInt16([cultureinfo]::InvariantCulture) + 0x2400) } } else { "$_" } }) -join "")

    $bufferText
}

function RemapCharactersForDisplay([char[]] $characters)
{
    $characters | %{ if ([char]::IsControl($_) -eq $true) { [char] (([int] $_) + 0x2400) } elseif ([char]::IsSeparator($_)) { ' ' } else { $_ } }
}

<#
    .SYNOPSIS
    Encodes a byte array to a base-64 (MIME) string.
    .DESCRIPTION
    Encodes a byte array to a base-64 (MIME) string.
    .EXAMPLE
    .PARAMETER Bytes
    An Array of bytes to be encoded.
#>
function Encode-Mime
{
    [CmdletBinding(SupportsShouldProcess = $False)]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $True)]
        [byte[]] $Bytes
    )

    process
    {
        return [Convert]::ToBase64String($Bytes)
    }
}

<#
    .SYNOPSIS
    Decodes a base-64 (MIME) string to a byte array.
    .DESCRIPTION
    Decodes a base-64 (MIME) string to a byte array.
    .EXAMPLE
    .PARAMETER MimeEncodedString
    A base-64 (MIME) encoded string to decode.
#>
function Decode-Mime
{
    [CmdletBinding(SupportsShouldProcess = $False)]
    [OutputType([byte[]])]
    param
    (
        [Parameter(Mandatory = $True)]
        [string] $MimeEncodedString
    )

    process
    {
        [Byte[]] $bytes = [Convert]::FromBase64String($MimeEncodedString)

        return $bytes
    }
}

function ConvertFrom-Hexadecimal
{
    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([byte[]])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]] $Hexadecimal
    )

    begin
    {
        [char[]] $digits = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
    }

    process
    {
        [byte[]] $data = @()

        foreach ($hexString in $Hexadecimal)
        {
            if ([string]::IsNullOrEmpty($Hexadecimal) -eq $true -or $hexString.Length % 2 -ne 0)
            {
                throw New-Object FormatException('Hexadecimal string must not be empty and must contain an even number of digits to be valid.');
            }

            $hexString = $hexString.Replace(' ', '').ToUpperInvariant()
            $data = New-Object byte[] -ArgumentList ($hexString.Length / 2)

            for ([int] $index = 0; $index -lt $hexString.Length; $index += 2)
            {
                [int] $highDigitValue = $digits.IndexOf($hexString[$index])
                [int] $lowDigitValue = $digits.IndexOf($hexString[$index + 1])

                if ($highDigitValue -lt 0 -or $lowDigitValue -lt 0)
                {
                    throw New-Object FormatException('An invalid digit was encountered. Valid hexadecimal digits are 0-9 and A-F.')
                }
                else
                {
                    [byte] $value = [byte](($highDigitValue -shl 4) -bor ($lowDigitValue -band 0x0F))
                    $data[$index / 2] = $value;
                }
            }
        }

        return ,$data
    }
}

function ConvertTo-Hexadecimal
{
    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]] $Byte,
        [Parameter()]
        [switch] $WithSpaces
    )

    begin
    {
        [char[]] $digits = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
        [string] $hexadecimal = ''
    }

    process
    {
        foreach ($byteValue in $Byte)
        {
            $hexadecimal += $digits[$byteValue -shr 4] + $digits[$byteValue -band 0x0F]

            if ($WithSpaces -eq $true)
            {
                $hexadecimal += ' '
            }
        }
    }

    end
    {
        return ,$hexadecimal
    }
}

<#
    .SYNOPSIS
    Displays binary data as a hexadecimal dump.

    .DESCRIPTION
        Displays binary data as a hexadecimal dump. Options are available to suppress displaying text and to display control characters 
        as Unicode Control Pictures instead of dots.

    .PARAMETER Bytes
    The bytes to be displayed.

    .PARAMETER Encoding
    The name of the text encoding to use. The default is ascii.

    .PARAMETER NoTextDisplay
    If specified the text display sidebar will be suppressed; otherwise, the display text sidebar will be present.

    .PARAMETER UseControlPictures
    If specified control characters will be displayed as Unicode Control pictures; otherwise, dots are used to represent control 
    characters.

    .EXAMPLE
    Format-HexDump -Encoding unicode $bytes

    .EXAMPLE
    Get-Content -Encoding Byte 'MyFile.bin' | Format-HexDump -Encoding unicode

    .EXAMPLE
    0..255 | Format-HexDump -NoTextDisplay
#>
function Format-HexDump
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [byte[]] $Bytes,
        [ValidateScript({ if (([System.Text.Encoding]::GetEncodings().Name + @('unicode', 'ascii')) -icontains $_) { return $true } else { Throw "Encoding must be one of the following: $([System.Text.Encoding]::GetEncodings().Name -join ', '), unicode, or ascii." } })]
        [Parameter(ValueFromPipeline = $false)]
        [string] $Encoding = "ASCII",
        [Parameter()]
        [switch] $NoTextDisplay,
        [Parameter()]
        [switch] $UseControlPictures
    )

    begin
    {
        $displayEncoding = [System.Text.Encoding]::GetEncoding($Encoding)

        $counter = 0
        $hexRow = ""
        [byte[]] $buffer = @()
    }

    process
    {
        foreach ($byte in $Bytes)
        {
            $buffer += $byte
            $hexValue = $byte.ToString("X2")

            if ($counter % 16 -eq 0)
            {
                $buffer = @($byte)
                $hexRow = "$($counter.ToString("X8")): $($hexValue) "
            }
            elseif ($counter % 16 -eq 15)
            {
                if ($NoTextDisplay -eq $true)
                {
                    $hexRow += "$($hexValue)"
                    $hexRow
                }
                else
                {
                    $bufferText = Format-BufferText $buffer $displayEncoding $UseControlPictures
                    $hexRow += "$($hexValue)   $($bufferText)"
                    $hexRow
                }
            }
            else
            {
                $hexRow += "$($hexValue) "
            }

            $counter++
        }
    }

    end
    {
        $counter--

        if ($counter % 16 -ne 15)
        {
            $hexRow += " " * (((16 - $counter % 16) * 3) - 1)

            if ($NoTextDisplay -eq $false)
            {
                $bufferText = Format-BufferText $buffer $displayEncoding $UseControlPictures
                $hexRow += "$($bufferText)"
            }

            $hexRow
        }
    }
}
    
Register-ArgumentCompleter -CommandName Format-HexDump -ParameterName Encoding -ScriptBlock $encodingAutoCompleter
