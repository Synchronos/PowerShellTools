function Test-IPAddressOrName($ipAddressOrName)
{
    $ipaddress = $null
    $isValidIPAddressOrName = [ipaddress]::TryParse($ipAddressOrName, [ref] $ipaddress)
    
    if ($isValidIPAddressOrName -eq $false)
    {
        $hasResolveDnsCommand = $null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
        if ($hasResolveDnsCommand -eq $true)
        {
            $dnsResult = Resolve-DnsName -DnsOnly -Name $ipAddressOrName -ErrorAction SilentlyContinue
            $isValidIPAddressOrName = $null -ne $dnsResult
        }
    }

    return $isValidIPAddressOrName
}

function Get-NameAndIPAddress($ipAddressOrName)
{
    $hasResolveDnsCommand = $null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)

    $ipAddress = $null
    $validIPAddress = [ipaddress]::TryParse($ipAddressOrName, [ref] $ipAddress)
    $nameAndIp = [PSCustomObject] @{ 'Name' = $null; 'IPAddress' = $null }

    if ($validIPAddress -eq $false)
    {
        if ($hasResolveDnsCommand -eq $true)
        {
            $dnsResult = Resolve-DnsName -DnsOnly $ipAddressOrName -Type A -ErrorAction SilentlyContinue

            if ($null -ne $dnsResult -and $dnsResult.QueryType -eq 'A')
            {
                $nameAndIp.Name = $dnsResult.Name
                $nameAndIp.IPAddress = $dnsResult.IPAddress
            }
            else
            {
                Write-Error "The name $($ipAddressOrName) could not be resolved."
                $nameAndIp = $null
            }
        }
        else
        {
            Write-Warning "Resolve-DnsName not present. DNS resolution check skipped."
        }
    }
    else
    {
        $nameAndIp.IPAddress = $ipAddress

        if ($hasResolveDnsCommand -eq $true)
        {
            $dnsResult = Resolve-DnsName -DnsOnly $ipAddress -Type PTR -ErrorAction SilentlyContinue

            if ($null -ne $dnsResult -and $dnsResult.QueryType -eq 'PTR')
            {
                $nameAndIp.Name = $dnsResult.NameHost
            }
        }
    }

    return $nameAndIp
}

<#
    .Synopsis
    Performs a series of pings (ICMP echo requests) with Don't Fragment specified to discover the path MTU (Maximum Transmission Unit).

    .Description
    Performs a series of pings with Don't Fragment specified to discover the path MTU (Maximum Transmission Unit). An ICMP echo request 
    is sent with a random payload with a payload length specified by the PayloadBytesMinimun. ICMP echo requests of increasing size are 
    sent until a ping response status other than Success is received. If the response status is PackeTooBig, the last successful packet 
    length is returned as a reliable MTU; otherwise, if the respone status is TimedOut, the same size packet is retried up to the number 
    of retries specified. If all of the retries have been exhausted with a response status of TimedOut, the last successful packet 
    length is returned as the assumed MTU.

    .Parameter UseDefaultGateway
    If UseDefaultGateway is specified the default gateway reported by the network interface is used as the destination host.

    .Parameter DestinationHost
    The IP Address or valid fully qualified DNS name of the destination host.

    .Parameter InitialTimeout
    The number of milliseconds to wait for an ICMP echo reply. Internally, this is doubled each time a retry occurs. The default is 
    3000 milliseconds.

    .Parameter Retries
    The number of times to try the ping in the event that no reply is recieved before the timeout. The default is 3.

    .Parameter InterPacketDelay
    The amount of time in milliseconds to wait between sending packets. This is used to prevent ICMP rate limiting on some devices 
    from rejecting packets. The default is 100 milliseconds.

    .Parameter PayloadBytesMinimum
    The minimum number of bytes in the payload to use. The minimum MTU for IPv4 is 68 bytes; however, in practice, it's extremely rare 
    to see an MTU size less than 576 bytes so the default value is 548 bytes (576 bytes total packet size minus an ICMP header of 28 
    bytes).

    .Parameter PayloadBytesMaximum
    The maximum number of bytes in the payload to use. An IPv4 MTU for jumbo frames is 9000 bytes. The default value is 8973 bytes (9001 
    bytes total packet size, which is 1 byte larger than the maximum IPv4 MTU for a jumbo frame, minus an ICMP header of 28 bytes).

    .Example
    Discover-PathMTU -UseDefaultGateway

    .Example
    Discover-PathMTU -DestinationHost '192.168.1.1'

    .Example
    Discover-PathMTU -DestinationHost 'www.google.com'
#>
function Discover-PathMtu
{
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'DefaultGateway')]
        [switch] $UseDefaultGateway,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'IPAddressOrName')]
        [ValidateScript({ Test-IPAddressOrName $_ })]
        [string] $DestinationHost,

        [Parameter(ParameterSetName = 'IPAddressOrName')]
        [Parameter(ParameterSetName = 'DefaultGateway')]
        [int] $InitialTimeout = 3000,

        [Parameter(ParameterSetName = 'IPAddressOrName')]
        [Parameter(ParameterSetName = 'DefaultGateway')]
        [int] $Retries = 3,

        [Parameter(ParameterSetName = 'IPAddressOrName')]
        [Parameter(ParameterSetName = 'DefaultGateway')]
        [int] $InterPacketDelay = 100,

        [Parameter(ParameterSetName = 'IPAddressOrName')]
        [Parameter(ParameterSetName = 'DefaultGateway')]
        [int] $PayloadBytesMinimum = 548,

        [Parameter(ParameterSetName = 'IPAddressOrName')]
        [Parameter(ParameterSetName = 'DefaultGateway')]
        [int] $PayloadBytesMaximum = 8973
    )

    begin
    {
        $ipConfiguration = Get-NetIPConfiguration -Detailed | ?{ $_.NetProfile.Ipv4Connectivity -eq 'Internet' -and $_.NetAdapter.Status -eq 'Up' } | Sort { $_.IPv4DefaultGateway.InterfaceMetric } | Select -First 1
        $gatewayIPAddress = $ipConfiguration.IPv4DefaultGateway.NextHop

        $pingOptions = New-Object System.Net.NetworkInformation.PingOptions
        $pingOptions.DontFragment = $true
        $pinger = New-Object System.Net.NetworkInformation.Ping

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    }

    process
    {
        $pingIpAddress = $null

        if ($UseDefaultGateway -eq $true)
        {
            $DestinationHost = $gatewayIPAddress
        }

        $nameAndIP = Get-NameAndIPAddress $DestinationHost

        if ($null -ne $nameAndIP)
        {
            Write-Host "Performing Path MTU discovery for $($nameAndIP.Name) $($nameAndIP.IPAddress)..."

            $pingReply = $null
            $payloadLength = $PayloadBytesMinimum
            $workingPingTimeout = $InitialTimeout

            do
            {
                $payloadLength++

                # Use a random payload to prevent compression in the path from potentially causing a false MTU report.
                [byte[]] $payloadBuffer = (,0x00 * $payloadLength)
                $rng.GetBytes($payloadBuffer)

                $pingCount = 1

                do
                {
                    $pingReply = $pinger.Send($nameAndIP.IPAddress, $workingPingTimeout, $payloadBuffer, $pingOptions)

                    if ($pingReply.Status -notin 'Success', 'PacketTooBig', 'TimedOut')
                    {
                        Write-Warning "An unexpected ping reply status, $($pingReply.Status), was received in $($pingReply.RoundtripTime) milliseconds on attempt $($pingCount)."
                    }
                    elseif ($pingReply.Status -eq 'TimedOut')
                    {
                        Write-Warning "The ping request timed out while testing a packet of size $($payloadLength + 28) using a timeout value of $($workingPingTimeout) milliseconds on attempt $($pingCount)."
                        $workingPingTimeout = $workingPingTimeout * 2
                    }
                    else
                    {
                        Write-Verbose "Testing packet of size $($payloadLength + 28). The reply was $($pingReply.Status) and was received in $($pingReply.RoundtripTime) milliseconds on attempt $($pingCount)."
                        $workingPingTimeout = $InitialTimeout
                    }

                    Sleep -Milliseconds $InterPacketDelay

                    $pingCount++
                } while ($pingReply.Status -eq 'TimedOut' -and $pingCount -le $Retries)
            } while ($payloadLength -lt $PayloadBytesMaximum -and $pingReply -ne $null -and $pingReply.Status -eq 'Success')

            if ($pingReply.Status -eq 'PacketTooBig')
            {
                Write-Host "Reported IPv4 MTU is $($ipConfiguration.NetIPv4Interface.NlMtu). The discovered IPv4 MTU is $($payloadLength + 27)."
            }
            elseif ($pingReply.Status -eq 'TimedOut')
            {
                Write-Host "Reported IPv4 MTU is $($ipConfiguration.NetIPv4Interface.NlMtu). The discovered IPv4 MTU is $($payloadLength + 27), but may not be reliable because the packet appears to have been discarded."    
            }
            else
            {
                Write-Host "Reported IPv4 MTU is $($ipConfiguration.NetIPv4Interface.NlMtu). The discovered IPv4 MTU is $($payloadLength + 27), but may not be reliable, due to an unexpected ping reply status."    
            }

            return $payloadLength + 27
        }
        else
        {
            Write-Error "The name $($DestinationHost) could not be resolved. No Path MTU discovery will be performed."
        }
    }

    end
    {
        if ($null -ne $pinger)
        {
            $pinger.Dispose()
        }

        if ($null -ne $rng)
        {
            $rng.Dispose()
        }
    }
}
