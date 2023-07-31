function ConvertTo-IPv4Netmask
{
    <#
    .SYNOPSIS
        Converts IPv4 mask bits to the corresponding netmask value.
    .DESCRIPTION
        Converts IPv4 mask bits to the corresponding netmask value.
    .PARAMETER MaskBits
        A valid IPv4 mask bits value.
    .OUTPUTS
        A System.IPAddress that contains an IPv4 netmask.
    .EXAMPLE
        ConvertTo-IPv4Netmask 24
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 32)]        
        $MaskBits
    )
    
    process
    {
        $netmask = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes([ipaddress]::NetworkToHostOrder((0xffffffff -shl (32 - $MaskBits)))))
        return $netmask
    }
}

function Test-Ipv4Netmask
{
    <#
    .SYNOPSIS
        Tests an IPv4 netmask to determine if it is valid.
    .DESCRIPTION
        Tests an IPv4 netmask to determine if it is valid.
    .PARAMETER Netmask
        An IPv4 netmask.
    .OUTPUTS
        Returns true if the specified netmask is valid; otherwise, false.
    .EXAMPLE
        Test-IPv4Netmask '255.255.255.0'
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true)]
        [ipaddress] $Netmask
    )

    process
    {
        if ($Netmask.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
        {
            $netmaskValue = [ipAddress]::HostToNetworkOrder([BitConverter]::ToInt32($Netmask.GetAddressBytes(), 0))
            $maskBits = 0
            for (; $maskBits -le 32; $maskBits++) { if ($netmaskValue -eq 0) { break; }; $netmaskValue = $netmaskValue -shl 1; }

            $Netmask -eq (ConvertTo-IPv4Netmask $maskBits)
        }
        else
        {
            $false
        }
    }
}

function ConvertTo-IPv4MaskBits
{
    <#
    .SYNOPSIS
        Converts an IPv4 netmask to the corresponding mask bits value.
    .DESCRIPTION
        Converts an IPv4 netmask to the corresponding mask bits value.
    .PARAMETER Netmask
        A valid IPv4 netmask.
    .OUTPUTS
        A int that contains an IPv4 mask bits value.
    .EXAMPLE
        ConvertTo-IPv4MaskBits '255.255.255.0'
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })]
        [ipaddress] $Netmask
    )

    process
    {
        $netmaskValue = [ipAddress]::HostToNetworkOrder([BitConverter]::ToInt32($Netmask.GetAddressBytes(), 0))
        $maskBits = 0
        for (; $maskBits -le 32; $maskBits++) { if ($netmaskValue -eq 0) { break; }; $netmaskValue = $netmaskValue -shl 1; }

        if ($Netmask -ne (ConvertTo-IPv4Netmask $maskBits))
        {
            throw (New-Object 'System.ArgumentException' @("The argument $($Netmask) is not a valid IPv4 netmask. Supply an argument that is a valid IPv4 netmask and then try the command again.", 'Netmask'))
        }

        $maskBits
    }
}

function Get-IPv4SubnetRange
{
    <#
    .SYNOPSIS
        Gets the range of addresses from the specified IPv4 address and mask bit or netmask.
    .DESCRIPTION
        Gets the range of addresses from the specified IPv4 address and mask bit or netmask.
    .PARAMETER IPAddress
        A valid IPv4 address value.
    .PARAMETER MaskBits
        A valid IPv4 mask bits value.
    .PARAMETER Netmask
        A valid IPv4 netmask.
    .OUTPUTS
        A PSCustomObject with StartAddress and EndAddress properties that are of type System.IPAddress.
    .EXAMPLE
        Get-IPv4SubnetRange '192.168.1.0' 24
    .EXAMPLE
        Get-IPv4SubnetRange '192.168.1.0' '255.255.255.0'
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=0)]
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=0)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $IPAddress,
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=1)]
        [ValidateRange(1, 32)]
        [int] $MaskBits,
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=1)]
        [ValidateScript({ if ((Test-IPv4Netmask $_) -eq $true) { $true } else { throw "The argument $($_) is not a valid IPv4 netmask. Supply an argument that is a valid IPv4 netmask and then try the command again." } })]
        [ipaddress] $Netmask
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'MaskBits')
        {
            $netmaskValue = [BitConverter]::ToInt32((ConvertTo-IPv4NetMask $MaskBits).GetAddressBytes(), 0)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Netmask')
        {
            [void] (ConvertTo-IPv4MaskBits $Netmask)
            $netmaskValue = [BitConverter]::ToInt32($Netmask.GetAddressBytes(), 0)
        }

        $lastAddressMaskValue= -bnot $netmaskValue
        $ipValue = [BitConverter]::ToInt32($ipAddress.GetAddressBytes(), 0)
        $startIPAddressValue = $ipValue -band $netmaskValue
        $endIPAddressValue = $startIPAddressValue -bor $lastAddressMaskValue
        $ipSubnetRange = [PSCustomObject] @{ 'StartAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($startIPAddressValue)); 'EndAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($endIPAddressValue)) }
        
        $ipSubnetRange
    }
}

function Get-PlainEnglish([string] $comparisonResult)
{
    switch ($comparisonResult)
    {
        '=' { 'equals' }
        '⊇' { 'is a superset of' }
        '⊆' { 'is a subset of' }
        '⋞' { 'precedes' }
        '⋟' { 'succeeds' }
        '⋞∩' { 'precedes and intersects' }
        '∩⋟' { 'intersects and succeeds' }
    }
}

function Compare-IPv4Range
{
    <#
    .SYNOPSIS
        Compares two IPv4 ranges and returns a value indicating the relationship between them.
    .DESCRIPTION
        Compares two IPv4 address ranges and returns a value indicating the relationship between them. Because IPv4 ranges can be expressed as
        ordered sets, the result of the comparison is expressed using the operator symbols from set logic The possible values are '=' (equals),
         '⊇' (is a superset of), '⊆' (is a subset of), '⋞' (precedes), '⋞∩' (precedes and intersects), '∩⋟' (intersects and succeeds).
    .PARAMETER Range1
        A PSCustomObject representing an IPv4 Address range containing StartAddress and EndAddress properties of type System.IPAddress.
    .PARAMETER Range2
        A PSCustomObject representing an IPv4 Address range containing StartAddress and EndAddress properties of type System.IPAddress.
    .PARAMETER StartAddress1
        A valid IPv4 address value representing the start of a range.
    .PARAMETER EndAddress1
        A valid IPv4 address value representing the end of a range.
    .PARAMETER StartAddress2
        A valid IPv4 address value representing the start of a range.
    .PARAMETER EndAddress2
        A valid IPv4 address value representing the end of a range.
    .PARAMETER PlainEnglish
        If PlainEnglish is present the output of the comparison will be plain english text instead of the set logic symbol.
    .OUTPUTS
        A string containing the result of the comparison.
    .EXAMPLE
        Compare-IPv4SubnetRange '192.168.1.0' 24 192.168.0.0 16
    .EXAMPLE
        Compare-IPv4SubnetRange '192.168.1.0' '255.255.255.0' '192.168.0.0' '255.255.255.0'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory=$true, ParameterSetName='RangeObject', Position=0)]
        [PSCustomObject] $Range1,
        [Parameter(Mandatory=$true, ParameterSetName='RangeObject', Position=1)]
        [PSCustomObject] $Range2,
        [Parameter(Mandatory=$true, ParameterSetName='Range', Position=0)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $StartAddress1,
        [Parameter(Mandatory=$true, ParameterSetName='Range', Position=1)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $EndAddress1,
        [Parameter(Mandatory=$true, ParameterSetName='Range', Position=2)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $StartAddress2,
        [Parameter(Mandatory=$true, ParameterSetName='Range', Position=3)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $EndAddress2,
        [Parameter(ParameterSetName='RangeObject')]
        [Parameter(ParameterSetName='Range')]
        [switch] $PlainEnglish
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Range')
        {
            $Range1 = [PSCustomObject] @{ 'StartAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($StartAddress1)); 'EndAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($EndAddress1)) }
            $Range2 = [PSCustomObject] @{ 'StartAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($StartAddress2)); 'EndAddress' = New-Object 'System.Net.IPAddress' @(,[BitConverter]::GetBytes($EndAddress2)) }
        }

        if ($Range1.StartAddress -eq $Range2.StartAddress -and $Range1.EndAddress -eq $Range2.EndAddress)
        {
            $comparisonResult = '=' # equals
        }
        elseif (([version] $Range1.StartAddress.IPAddressToString) -le ([version] $Range2.StartAddress.IPAddressToString) -and ([version] $Range1.EndAddress.IPAddressToString) -ge ([version] $Range2.EndAddress.IPAddressToString))
        {
            $comparisonResult = '⊇' # is a superset of
        }
        elseif (([version] $Range1.StartAddress.IPAddressToString) -ge ([version] $Range2.StartAddress.IPAddressToString) -and ([version] $Range1.EndAddress.IPAddressToString) -le ([version] $Range2.EndAddress.IPAddressToString))
        {
            $comparisonResult = '⊆' # is a subset of
        }
        elseif (([version] $Range1.StartAddress.IPAddressToString) -lt ([version] $Range2.StartAddress.IPAddressToString) -and ([version] $Range1.EndAddress.IPAddressToString) -lt ([version] $Range2.StartAddress.IPAddressToString))
        {
            $comparisonResult = '⋞' # precedes
        }
        elseif (([version] $Range1.StartAddress.IPAddressToString) -gt ([version] $Range2.EndAddress.IPAddressToString) -and ([version] $Range1.EndAddress.IPAddressToString) -gt ([version] $Range2.EndAddress.IPAddressToString))
        {
            $comparisonResult = '⋟' # succeeds
        }
        elseif (([version] $Range1.StartAddress.IPAddressToString) -lt ([version] $Range2.StartAddress.IPAddressToString) -and ([version] $Range1.EndAddress.IPAddressToString) -lt ([version] $Range2.EndAddress.IPAddressToString))
        {
            $comparisonResult = '⋞∩' # precedes and intersects
        }
        elseif (([version] $Range2.StartAddress.IPAddressToString) -gt ([version] $Range1.StartAddress.IPAddressToString) -and ([version] $Range2.EndAddress.IPAddressToString) -gt ([version] $Range1.EndAddress.IPAddressToString))
        {
            $comparisonResult = '∩⋟' # intersects and succeeds
        }

        if ($PlainEnglish -eq $false)
        {
            $comparisonResult
        }
        else
        {
            Get-PlainEnglish $comparisonResult
        }
    }
}

function Compare-IPv4Subnet
{
    <#
    .SYNOPSIS
        Compares two IPv4 subnets and returns a value indicating the relationship between them.
    .DESCRIPTION
        Compares two IPv4 subnets and returns a value indicating the relationship between them. Because IPv4 subnets can be expressed as ordered
        sets, the result of the comparison is expressed using the operator symbols from set logic The possible values are '=' (equals),
         '⊇' (is a superset of), '⊆' (is a subset of), '⋞' (precedes), '⋞∩' (precedes and intersects), '∩⋟' (intersects and succeeds).
    .PARAMETER IPAddress1
        A valid IPv4 address value.
    .PARAMETER MaskBits1
        A valid IPv4 mask bits value.
    .PARAMETER Netmask1
        A valid IPv4 netmask.
    .PARAMETER IPAddress2
        A valid IPv4 address value.
    .PARAMETER MaskBits2
        A valid IPv4 mask bits value.
    .PARAMETER Netmask2
        A valid IPv4 netmask.
    .PARAMETER PlainEnglish
        If PlainEnglish is present the output of the comparison will be plain english text instead of the set logic symbol.
    .OUTPUTS
        A string containing the result of the comparison.
    .EXAMPLE
        Compare-IPv4Subnet '192.168.1.0' 24 192.168.0.0 16
    .EXAMPLE
        Compare-IPv4Subnet '192.168.1.0' '255.255.255.0' '192.168.0.0' '255.255.255.0'
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=0)]
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=0)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $IPAddress1,
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=1)]
        [ValidateRange(1, 32)]
        [int] $MaskBits1,
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=1)]
        [ValidateScript({ if ((Test-IPv4Netmask $_) -eq $true) { $true } else { throw "The argument $($_) is not a valid IPv4 netmask. Supply an argument that is a valid IPv4 netmask and then try the command again." } })]
        [ipaddress] $Netmask1,
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=2)]
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=2)]
        [ValidateScript({ if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $true } else { throw "The argument $($_) is not a valid IPv4 address. Supply an argument that is a valid IPv4 address and then try the command again." } })]
        [ipaddress] $IPAddress2,
        [Parameter(Mandatory=$true, ParameterSetName='MaskBits', Position=3)]
        [ValidateRange(1, 32)]
        [int] $MaskBits2,
        [Parameter(Mandatory=$true, ParameterSetName='NetMask', Position=3)]
        [ValidateScript({ if ((Test-IPv4Netmask $_) -eq $true) { $true } else { throw "The argument $($_) is not a valid IPv4 netmask. Supply an argument that is a valid IPv4 netmask and then try the command again." } })]
        [ipaddress] $Netmask2,
        [Parameter(ParameterSetName='MaskBits')]
        [Parameter(ParameterSetName='NetMask')]
        [switch] $PlainEnglish
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'MaskBits')
        {
                $subnetRange1 = Get-IPv4SubnetRange $IPAddress1 $MaskBits1
                $subnetRange2 = Get-IPv4SubnetRange $IPAddress2 $MaskBits2
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Netmask')
        {
                $subnetRange1 = Get-IPv4SubnetRange $IPAddress1 $Netmask1
                $subnetRange2 = Get-IPv4SubnetRange $IPAddress2 $Netmask1
        }

        Compare-IPv4Range $subnetRange1 $subnetRange2 -PlainEnglish:$PlainEnglish
    }
}
