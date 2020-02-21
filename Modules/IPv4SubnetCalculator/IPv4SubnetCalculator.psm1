function ConvertTo-HexString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]] $Byte
    )

    begin
    {
        [char[]] $digits = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
        [System.Text.StringBuilder] $hexString = New-Object System.Text.StringBuilder
    }

    process
    {
        foreach ($byteValue in $Byte)
        {
            [void] $hexString.Append($digits[$byteValue -shr 4])
            [void] $hexString.Append($digits[$byteValue -band 0x0F])
        }
    }

    end
    {
        return $hexString.ToString();
    }
}

function ConvertTo-IPv4Netmask($maskBits)
{
    $netmask = [ipAddress]::new([BitConverter]::GetBytes([ipaddress]::NetworkToHostOrder(0xffffffff -shl (32 - $maskBits))))
    return $netmask
}

function ConvertTo-IPv4MaskBits([ipaddress] $netmask)
{
    $netmaskValue = [ipAddress]::HostToNetworkOrder([BitConverter]::ToInt32($netmask.GetAddressBytes(), 0))
    $maskBits = 0
    for (; $maskBits -le 32; $maskBits++) { if ($netmaskValue -eq 0) { break; }; $netmaskValue = $netmaskValue -shl 1; }
    return $maskBits
}

function Get-IPv4SubnetRange([ipaddress] $ipAddress, $maskBits)
{
    $netmaskValue = [ipaddress]::NetworkToHostOrder(0xffffffff -shl (32 - $maskBits))
    $lastAddressMaskValue = -bnot [ipaddress]::NetworkToHostOrder(0xffffffff -shl (32 - $maskBits))
    $ipValue = [BitConverter]::ToInt32($ipAddress.GetAddressBytes(), 0)
    $startIPAddressValue = $ipValue -band $netmaskValue
    $endIPAddressValue = $startIPAddressValue -bor $lastAddressMaskValue
    $ipSubnetRange = [PSCustomObject] @{ 'StartAddress' = [ipaddress]::new([BitConverter]::GetBytes($startIPAddressValue)); 'EndAddress' = [ipaddress]::new([BitConverter]::GetBytes($endIPAddressValue)) }
    return $ipSubnetRange
}

function Compare-IPv4Range($range1, $range2)
{
    if ($range1.StartAddress -eq $range2.StartAddress -and $range1.EndAddress -eq $range2.EndAddress)
    {
        '=' # equals
    }
    elseif (([version] $range1.StartAddress.IPAddressToString) -le ([version] $range2.StartAddress.IPAddressToString) -and ([version] $range1.EndAddress.IPAddressToString) -ge ([version] $range2.EndAddress.IPAddressToString))
    {
        '⊇' # is a superset of
    }
    elseif (([version] $range1.StartAddress.IPAddressToString) -ge ([version] $range2.StartAddress.IPAddressToString) -and ([version] $range1.EndAddress.IPAddressToString) -le ([version] $range2.EndAddress.IPAddressToString))
    {
        '⊆' # is a subset of
    }
    elseif (([version] $range1.StartAddress.IPAddressToString) -lt ([version] $range2.StartAddress.IPAddressToString) -and ([version] $range1.EndAddress.IPAddressToString) -lt ([version] $range2.StartAddress.IPAddressToString))
    {
        '⋞' # precedes
    }
    elseif (([version] $range1.StartAddress.IPAddressToString) -gt ([version] $range2.EndAddress.IPAddressToString) -and ([version] $range1.EndAddress.IPAddressToString) -gt ([version] $range2.EndAddress.IPAddressToString))
    {
        '⋟' # succeeds
    }
    elseif (([version] $range1.StartAddress.IPAddressToString) -lt ([version] $range2.StartAddress.IPAddressToString) -and ([version] $range1.EndAddress.IPAddressToString) -lt ([version] $range2.EndAddress.IPAddressToString))
    {
        '⋞∩' # precedes and intersects
    }
    elseif (([version] $range2.StartAddress.IPAddressToString) -gt ([version] $range1.StartAddress.IPAddressToString) -and ([version] $range2.EndAddress.IPAddressToString) -gt ([version] $range1.EndAddress.IPAddressToString))
    {
        '∩⋟' # intersects and succeeds
    }
}

function Compare-IPv4Subnet([ipaddress] $ipaddress1, $maskBits1, [ipaddress] $ipaddress2, $maskBits2)
{
    $subnetRange1 = Get-IPv4SubnetRange $ipaddress1 $maskBits1
    $subnetRange2 = Get-IPv4SubnetRange $ipaddress2 $maskBits2

    Compare-IPv4Range $subnetRange1 $subnetRange2
}

function Get-ReverseLookupName([ipaddress] $ipAddress)
{
    $reverseLookupName = $null

    if ($ipAddress.AddressFamily -eq 'InterNetwork')
    {
        $tempArray = $ipAddress.IPAddressToString.Split('.')
        [array]::Reverse($tempArray)
        $reverseLookupName = "$([string]::Join('.', $tempArray)).in-addr.arpa"
    }
    elseif ($ipAddress.AddressFamily -eq 'InterNetworkV6')
    {
        $tempArray = $ipAddress.GetAddressBytes() | %{ $_.ToString('x2').ToCharArray() }
        [array]::Reverse($tempArray)
        $reverseLookupName = "$([string]::Join('.', $tempArray)).ip6.arpa"        
    }

    return $reverseLookupName
}
