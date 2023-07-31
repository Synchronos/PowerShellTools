# If the IPv4 Subnetting Utilities are present load the IANA Address Block descriptions and add the lookup function.
if ($null -ne (Get-Module -ListAvailable 'IPv4SubnettingUtilities'))
{
    Import-Module 'IPv4SubnettingUtilities'

    $Global:IanaAddressBlocks = @'
"IPAddress"	"MaskBits"	"Description"
"0.0.0.0"	"8"	"""This network"""
"0.0.0.0"	"32"	"""This host on this network"""
"10.0.0.0"	"8"	"Private-Use"
"100.64.0.0"	"10"	"Shared Address Space"
"127.0.0.0"	"8"	"Loopback"
"169.254.0.0"	"16"	"Link Local"
"172.16.0.0"	"12"	"Private-Use"
"192.0.0.10"	"32"	"Traversal Using Relays around NAT Anycast"
"192.0.0.170"	"32"	"NAT64"	"DNS64 Discovery"
"192.0.0.171"	"32"	"NAT64"	"DNS64 Discovery"
"192.0.0.8"	"32"	"IPv4 dummy address"
"192.0.0.9"	"32"	"Port Control Protocol Anycast"
"192.0.0.0"	"29"	"IPv4 Service Continuity Prefix"
"192.0.2.0"	"24"	"Documentation (TEST-NET-1)"
"192.0.0.0"	"24"	"IETF Protocol Assignments"
"192.31.196.0"	"24"	"AS112-v4"
"192.52.193.0"	"24"	"AMT"
"192.88.99.0"	"24"	"Deprecated (6to4 Relay Anycast)"
"192.168.0.0"	"16"	"Private-Use"
"192.175.48.0"	"24"	"Direct Delegation AS112 Service"
"198.18.0.0"	"15"	"Benchmarking"
"198.51.100.0"	"24"	"Documentation (TEST-NET-2)"
"203.0.113.0"	"24"	"Documentation (TEST-NET-3)"
"240.0.0.0"	"4"	"Reserved"
"255.255.255.255"	"32"	"Limited Broadcast"
'@ | ConvertFrom-Csv -Delimiter "`t"

    function Get-IanaAddressBlockDescription([string] $ipAddressString)
    {
        $ipAddress = $null
        $isValid = [ipaddress]::TryParse($ipAddressString, [ref] $ipAddress)
    
        if ($isValid -eq $true)
        {
            $matchingSubnet = $Global:IanaAddressBlocks.Where({ (Compare-IPv4Subnet $_.IPAddress ([int]::Parse($_.MaskBits)) $ipAddress 32) -eq '⊇' }) 

            if ($null -ne $matchingSubnet -and $matchingSubnet.Count -gt 0)
            {
                $subnetDescription = $matchingSubnet.Description
            }
            else
            {
                $subnetDescription = 'Unknown'
            }
        }
        else
        {
            $subnetDescription = 'Invalid'
        }

        $subnetDescription
    }
}

# If the Active Directory module is present, pre-fetch the subnets from Active Directory Sites and Services and load the lookup function.
if ($null -ne (Get-Module -ListAvailable 'ActiveDirectory') -and $null -ne (Get-Module -ListAvailable 'IPv4SubnettingUtilities'))
{
    Import-Module 'ActiveDirectory'

    $Global:ADSubnets = Get-ADReplicationSubnet -Filter * -Properties Description | Select @{ name = 'IPAddress'; expression = { [ipaddress] $_.Name.Split('/')[0] } }, @{ name = 'MaskBits'; expression = { [int]::Parse($_.Name.Split('/')[1]) } }, Description | Select * 

    function Get-NetworkDescription([string] $ipAddressString)
    {
        $ipAddress = $null
        $isValid = [ipaddress]::TryParse($ipAddressString, [ref] $ipAddress)
    
        if ($isValid -eq $true)
        {
            $matchingSubnet = $Global:ADSubnets.Where({ (Compare-IPv4Subnet $_.IPAddress $_.MaskBits $ipAddress 32) -eq '⊇' }) 

            if ($null -ne $matchingSubnet)
            {
                $subnetDescription = $matchingSubnet.Description
            }
            else
            {
                $subnetDescription = 'Unknown'
            }
        }
        else
        {
            $subnetDescription = 'Invalid'
        }

        $subnetDescription
    }
}
elseif ($null -ne (Get-Module -ListAvailable 'IPv4SubnettingUtilities'))
{
    function Get-NetworkDescription([string] $ipAddressString)
    {
        Get-IanaAddressBlockDescription $ipAddressString
    }
}
else
{
    function Get-NetworkDescription([string] $ipAddressString)
    {
        'Unavailable'
    }    
}

$Global:DnsCache = @()

function Get-DnsCacheContent
{
	[CmdletBinding(SupportsShouldProcess = $false)]
    param()

    begin
    {
        $dnsCacheColumns = @(
            'IPAddress'
            , @{ name = 'Name'; expression = { [string]::Join(', ', $_.Name) } }
            , @{ name = 'SubnetDescription'; expression = { [string]::Join(', ', $_.SubnetDescription) } }
            , 'LookupDate'
        )
    }

    process
    {
        $Global:DnsCache | Select $dnsCacheColumns
    }
}

function Get-IPAddressName($ipAddressString)
{
    $ipAddress = $null
    $isValid = [ipaddress]::TryParse($ipAddressString, [ref] $ipAddress)
    
    if ($isValid -eq $true)
    {
        if ([ipaddress]::IsLoopback($ipAddress) -eq $true)
        {
            'localhost'
        }
        elseif ( $ipaddress -in @([ipaddress]::Any, [ipaddress]::IPv6Any))
        {
            'any'
        }
        else
        {
            $cachedDnsRecord = $Global:DnsCache | ?{ $_.IPAddress -eq $ipAddress }

            if ($null -ne $cachedDnsRecord)
            {
                $cachedDnsRecord.Name
            }
            else
            {
                $dnsRecord = Resolve-DnsName -QuickTimeout -DnsOnly $ipAddress -ErrorAction SilentlyContinue
            if ($null -ne $dnsRecord)
            {
                    $Global:DnsCache += [pscustomobject] @{ 'IPAddress' = $ipAddress; 'Name' = $dnsRecord.NameHost; 'SubnetDescription' = Get-NetworkDescription $ipAddress; 'LookupDate' = [datetimeoffset]::UtcNow }
                $dnsRecord.NameHost
            }
            else
            {
                    $Global:DnsCache += [pscustomobject] @{ 'IPAddress' = $ipAddress; 'Name' = ''; 'SubnetDescription' = Get-NetworkDescription $ipAddress; 'LookupDate' = [datetimeoffset]::UtcNow }
                ''
            }
        }
    }
    }
    else
    {
        ''
    }
}

function Get-ManagementDate($dmtfDate)
{
    if ($null -ne $dmtfDate)
    {
        $date = [System.Management.ManagementDateTimeConverter]::ToDateTime($dmtfDate)

        $dateKind = [DateTimeKind]::Utc

        if ($dmtfDate.EndsWith('+000') -eq $false -and $dmtfDate.EndsWith('+00:00') -eq $false)
        {
            $dateKind = [DateTimeKind]::Local
        }

        [System.DateTimeOffset] (New-Object 'System.DateTimeOffset' ([DateTime]::SpecifyKind($date, $dateKind)))
    }
    else
    {
        $null
    }
}

function Format-Owner($process)
{
    try
    {
        if ($null -eq $process)
        {
            'N/A'
        }
        elseif ($process -is [System.Management.ManagementObject])
        {
            $owner = $process.GetOwner()
        }
        elseif ($process -is [Microsoft.Management.Infrastructure.CimInstance])
        {
            $owner = Invoke-CimMethod -InputObject $process -MethodName 'GetOwner' -ErrorAction SilentlyContinue
        }

        if ($null -ne $owner)
        {
            if ($null -ne $owner.Domain)
            {
                "$($owner.Domain)\$($owner.User)"
            }
            else
            {
                $owner.User
            }
        }
        else
        {
            'N/A'
        }
    }
    catch [System.Management.ManagementException]
    {
        throw [Exception]::new("Could not get the process owner from $($process).", $_.Exception)
    }
}

function New-WindowsProcessConnectionDataSet()
{
    $windowsProcessConnectionDataSet = New-Object 'System.Data.DataSet' 'WindowsProcessConnection'
    $windowsProcessConnectionDataSet.SchemaSerializationMode = [System.Data.SchemaSerializationMode]::IncludeSchema

    $networkAdapterTable = $windowsProcessConnectionDataSet.Tables.Add('NetworkAdapter')
    $networkAdapterKeyColumn = $networkAdapterTable.Columns.Add('InterfaceIndex', [long])
    [void] $networkAdapterTable.Columns.Add('ServiceName', [string])
    [void] $networkAdapterTable.Columns.Add('Description', [string])
    [void] $networkAdapterTable.Columns.Add('MACAddress', [string])
    [void] $networkAdapterTable.Columns.Add('DHCPEnabled', [bool])
    [void] $networkAdapterTable.Columns.Add('DHCPLeaseObtained', [System.DateTimeOffset])
    [void] $networkAdapterTable.Columns.Add('DHCPLeaseExpires', [System.DateTimeOffset])
    [void] $networkAdapterTable.Columns.Add('DHCPServer', [string])
    [void] $networkAdapterTable.Columns.Add('IPAddress', [string[]])
    [void] $networkAdapterTable.Columns.Add('IPSubnet', [string[]])
    [void] $networkAdapterTable.Columns.Add('DefaultIPGateway', [string[]])
    [void] $networkAdapterTable.Columns.Add('FullDNSRegistrationEnabled', [bool])
    [void] $networkAdapterTable.Columns.Add('DNSHostName', [string])
    [void] $networkAdapterTable.Columns.Add('DNSDomain', [string])
    [void] $networkAdapterTable.Columns.Add('DNSServerSearchOrder', [string[]])
    $networkAdapterTable.PrimaryKey = $networkAdapterKeyColumn

    $processTable = $windowsProcessConnectionDataSet.Tables.Add('Process')
    $processKeyColumn = $processTable.Columns.Add('ProcessId', [long])
    [void] $processTable.Columns.Add('ParentProcessId', [long])
    [void] $processTable.Columns.Add('Name', [string])
    [void] $processTable.Columns.Add('ExecutablePath', [string])
    [void] $processTable.Columns.Add('CommandLine', [string])
    [void] $processTable.Columns.Add('Owner', [string])
    [void] $processTable.Columns.Add('CreationDate', [System.DateTimeOffset])
    $processTable.PrimaryKey = $processKeyColumn

    $serviceTable = $windowsProcessConnectionDataSet.Tables.Add('Service')
    $serviceKeyColumn = $serviceTable.Columns.Add('Name', [string])
    [void] $serviceTable.Columns.Add('DisplayName', [string])
    [void] $serviceTable.Columns.Add('Description', [string])
    [void] $serviceTable.Columns.Add('PathName', [string])
    [void] $serviceTable.Columns.Add('Status', [string])
    $processServiceForeignKeyColumn = $serviceTable.Columns.Add('ProcessId', [long])
    $processServiceForeignKeyColumn.AllowDBNull = $false
    $serviceTable.PrimaryKey = $serviceKeyColumn

    $serviceRelation = $windowsProcessConnectionDataSet.Relations.Add($processKeyColumn, $processServiceForeignKeyColumn)
    $serviceRelation.Nested = $true

    $tcpConnectionTable = $windowsProcessConnectionDataSet.Tables.Add('TCPConnection')
    $tcpConnectionKeyColumn = $tcpConnectionTable.Columns.Add('InstanceId', [string])
    $processTcpConnectionForeignKeyColumn = $tcpConnectionTable.Columns.Add('OwningProcess', [long])
    $processTcpConnectionForeignKeyColumn.AllowDBNull = $false
    [void] $tcpConnectionTable.Columns.Add('LocalAddressName', [string])
    [void] $tcpConnectionTable.Columns.Add('LocalAddress', [string])
    [void] $tcpConnectionTable.Columns.Add('LocalPort', [int])
    [void] $tcpConnectionTable.Columns.Add('RemoteAddressName', [string])
    [void] $tcpConnectionTable.Columns.Add('RemoteAddress', [string])
    [void] $tcpConnectionTable.Columns.Add('RemotePort', [int])
    [void] $tcpConnectionTable.Columns.Add('Status', [string])
    [void] $tcpConnectionTable.Columns.Add('CreationTime', [System.DateTimeOffset])
    $tcpConnectionTable.PrimaryKey = $tcpConnectionKeyColumn

    $tcpConnectionRelation = $windowsProcessConnectionDataSet.Relations.Add($processKeyColumn, $processTcpConnectionForeignKeyColumn)
    $tcpConnectionRelation.Nested = $true

    $udpEndpointTable = $windowsProcessConnectionDataSet.Tables.Add('UDPEndpoint')
    $udpEndpointKeyColumn = $udpEndpointTable.Columns.Add('InstanceId', [string])
    $processUdpEndpointForeignKeyColumn = $udpEndpointTable.Columns.Add('OwningProcess', [long])
    $processUdpEndpointForeignKeyColumn.AllowDBNull = $false
    [void] $udpEndpointTable.Columns.Add('LocalAddressName', [string])
    [void] $udpEndpointTable.Columns.Add('LocalAddress', [string])
    [void] $udpEndpointTable.Columns.Add('LocalPort', [int])
    [void] $udpEndpointTable.Columns.Add('CreationTime', [System.DateTimeOffset])
    $udpEndPointTable.PrimaryKey = $udpEndPointKeyColumn

    $udpEndPointRelation = $windowsProcessConnectionDataSet.Relations.Add($processKeyColumn, $processUdpEndpointForeignKeyColumn)
    $udpEndPointRelation.Nested = $true

    $orphanTcpConnectionTable = $windowsProcessConnectionDataSet.Tables.Add('OrphanTCPConnection')
    $orphanTcpConnectionKeyColumn = $orphanTcpConnectionTable.Columns.Add('InstanceId', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('OwningProcess', [long])
    [void] $orphanTcpConnectionTable.Columns.Add('LocalAddressName', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('LocalAddress', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('LocalPort', [int])
    [void] $orphanTcpConnectionTable.Columns.Add('RemoteAddressName', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('RemoteAddress', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('RemotePort', [int])
    [void] $orphanTcpConnectionTable.Columns.Add('Status', [string])
    [void] $orphanTcpConnectionTable.Columns.Add('CreationTime', [System.DateTimeOffset])
    $orphanTcpConnectionTable.PrimaryKey = $orphanTcpConnectionKeyColumn

    $orphanUdpEndpointTable = $windowsProcessConnectionDataSet.Tables.Add('OrphanUDPEndPoint')
    $orphanUdpEndpointKeyColumn = $orphanUdpEndpointTable.Columns.Add('InstanceId', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('OwningProcess', [long])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalAddressName', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalAddress', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalPort', [int])
    [void] $orphanUdpEndpointTable.Columns.Add('CreationTime', [System.DateTimeOffset])
    $orphanUdpEndPointTable.PrimaryKey = $orphanUdpEndPointKeyColumn

    $windowsProcessConnectionDataSet.AcceptChanges()

    return $windowsProcessConnectionDataSet
}

function Load-WindowsProcessConnectionDataSet([string] $computer, [System.Data.DataSet] $windowsProcessConnectionDataSet)
{
    $tcpStateNameProperty = @{ name = 'StateName'; expression = { if ($_.State -ne 100) { [System.Net.NetworkInformation.TcpState] $_.State } else { 'Bound' } } }
    $localAddressNameProperty = @{ name = 'LocalAddressName'; expression = { Get-IPAddressName $_.LocalAddress } }
    $remoteAddressNameProperty = @{ name = 'RemoteAddressName'; expression = { Get-IPAddressName $_.RemoteAddress } }

    $networkAdapterTable = $windowsProcessConnectionDataSet.Tables['NetworkAdapter']
    $processTable = $windowsProcessConnectionDataSet.Tables['Process']
    $tcpConnectionTable = $windowsProcessConnectionDataSet.Tables['TCPConnection']
    $udpEndpointTable = $windowsProcessConnectionDataSet.Tables['UdpEndpoint']
    $serviceTable = $windowsProcessConnectionDataSet.Tables['Service']
    $orphanTcpConnectionTable = $windowsProcessConnectionDataSet.Tables['OrphanTcpConnection']
    $orphanUdpEndpointTable = $windowsProcessConnectionDataSet.Tables['OrphanUdpEndpoint']

    Write-Verbose 'Getting network adapters...'
    $networkAdapterConfigs = Get-CimInstance -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = true'

    Write-Verbose 'Getting running processes...'
    $processes = Get-CimInstance -Class 'Win32_Process'

    Write-Verbose 'Getting TCP connections...'
    $netTcpConnections = Get-CimInstance -Namespace 'ROOT/StandardCimv2' -Class 'MSFT_NetTCPConnection'

    Write-Verbose 'Getting UDP endpoints...'
    $netUdpEndPoints = Get-CimInstance -Namespace 'ROOT/StandardCimv2' -Class 'MSFT_NetUDPEndpoint'

    Write-Verbose 'Getting running Windows Services...'
    $services = Get-CimInstance -Class 'Win32_Service' -Filter "State != 'Stopped'"
    
    $networkAdapterTable.BeginLoadData()
    $networkAdapterConfigs | %{ [void] $networkAdapterTable.LoadDataRow(@($_.InterfaceIndex, $_.ServiceName, $_.Description, $_.MACAddress, $_.DHCPEnabled, [Nullable[DateTimeOffset]] ($_.DHCPLeaseObtained), [Nullable[DateTimeOffset]] ($_.DHCPLeaseExpires), $_.DHCPServer, $_.IPAddress, $_.IPSubnet, $_.DefaultIPGateway, $_.FullDNSRegistrationEnabled, $_.DnsHostName, $_.DNSDomain, $_.DNSServerSearchOrder), $true) }
    $networkAdapterTable.EndLoadData()

    $processTable.BeginLoadData()
    $processes | %{ [void] $processTable.LoadDataRow(@($_.ProcessId, $_.ParentProcessId, $_.Name, $_.ExecutablePath, $_.CommandLine, (Format-Owner $_), [DateTimeOffset] ($_.CreationDate)), $true) }
    $processTable.EndLoadData()

    $tcpConnectionTable.BeginLoadData()
    $udpEndpointTable.BeginLoadData()

    Write-Verbose 'Getting DNS names for IP addresses...'
    $netTcpConnections | Select *, $localAddressNameProperty, $remoteAddressNameProperty, $tcpStateNameProperty | %{ [void] $tcpConnectionTable.LoadDataRow(@($_.InstanceId, $_.OwningProcess, $_.LocalAddressName, $_.LocalAddress, $_.LocalPort, $_.RemoteAddressName, $_.RemoteAddress, $_.RemotePort, $_.StateName, [DateTimeOffset] ($_.CreationTime)), $true) }
    $netUdpEndPoints | Select *, $localAddressNameProperty | %{ [void] $udpEndpointTable.LoadDataRow(@($_.InstanceId, $_.OwningProcess, $_.LocalAddressName, $_.LocalAddress, $_.LocalPort, [Nullable[DateTimeOffset]] ($_.CreationTime)), $true) }

    $tcpConnectionTable.EndLoadData()

    if ($tcpConnectionTable.HasErrors -eq $true)
    {
        Write-Host 'Processing orphaned TCP connections...'
        $orphanTcpConnectionTable.BeginLoadData()

        [System.Data.DataRow] $tcpConnectionTableRow = $null
        foreach ($tcpConnectionTableRow in $tcpConnectionTable.Rows)
        {
            if ($tcpConnectionTableRow.HasErrors-eq $true)
            {
                [void] $orphanTcpConnectionTable.LoadDataRow($tcpConnectionTableRow.ItemArray, $true)
                $tcpConnectionTableRow.Delete()
            }
        }

        $orphanTcpConnectionTable.EndLoadData()
        $tcpConnectionTable.EndLoadData()
    }

    $udpEndpointTable.EndLoadData()

    if ($udpEndpointTable.HasErrors -eq $true)
    {
        Write-Host 'Processing orphaned UDP endpoints...'

        $orphanUdpEndpointTable.BeginLoadData()

        [System.Data.DataRow] $udpEndpointTableRow = $null
        foreach ($udpEndpointTableRow in $udpEndpointTable.Rows)
        {
            if ($udpEndpointTableRow.HasErrors-eq $true)
            {
                [void] $orphanUdpEndpointTable.LoadDataRow($udpEndpointTableRow.ItemArray, $true)
                $udpEndpointTableRow.Delete()
            }
        }

        $orphanUdpEndpointTable.EndLoadData()
        $udpEndpointTable.EndLoadData()
    }

    $serviceTable.BeginLoadData()
    $services | %{ [void] $serviceTable.LoadDataRow(@($_.Name, $_.DisplayName, $_.Description, $_.PathName, $_.Status, $_.ProcessId), $true) }
    $serviceTable.EndLoadData()

    $windowsProcessConnectionDataSet.AcceptChanges()
}

function Get-WindowsProcessConnection
{
    <#
    .SYNOPSIS
        Gets Windows processes, network connections, and related service information.

    .DESCRIPTION
        Uses WMI to get Windows process network connection and related service information and outputs it as an XML data file. If no Computer parameter
        is provided, the local computer will be queried. Administrative rights on the target are required to query a remote computer.

    .INPUTS
        Strings containing the computers to query.

    .OUTPUTS
        Strings containg the paths to the generated XML data files.

    .EXAMPLE
        Get-WindowsProcessConnection

    .EXAMPLE
        Get-WindowsProcessConnection -Computer 'COMPUTERNAME'

    .EXAMPLE
        Get-WindowsProcessConnection -Computer 'COMPUTERNAME1', 'COMPUTERNAME2'
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        <#
        .PARAMETER Computer
            The computer to query.
        #>
        [Parameter(ValueFromPipeline=$true)]
        [string[]] $Computer
    )

    process
    {
        if ([string]::IsNullOrWhiteSpace($Computer) -eq $true)
        {
            $Computer = $env:COMPUTERNAME
        }

        foreach ($computerToQuery in $Computer)
        {
            $windowsProcessConnectionDataSet = New-WindowsProcessConnectionDataSet
            Load-WindowsProcessConnectionDataSet $computerToQuery $windowsProcessConnectionDataSet

            [pscustomobject] @{ 'Computer' = $computerToQuery; 'CaptureDateTime' = Get-Date; 'ProcessConnections' = $windowsProcessConnectionDataSet; }
        }
    }
}

function Format-WindowsProcessConnection
{
    <#
    .SYNOPSIS
        Formats the XML data file generated by Get-WindowsProcessConnection as HTML.

    .DESCRIPTION
        Formats the XML data file generated by Get-WindowsProcessConnection as HTML.

    .INPUTS
        Strings containing paths to the XML data files to process.

    .OUTPUTS
        A string that gives the path to the formatted HTML file.

    .EXAMPLE
        Format-WindowsProcessConnect $xmlFile

    .EXAMPLE
        Get-WindowsProcessConnection | Format-WindowsProcessConnection
    .EXAMPLE
        Get-WindowsProcessConnection -Computer 'COMPUTERNAME1', 'COMPUTERNAME2' | Format-WindowsProcessConnection | %{ & "$_" }
    #>
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        <#
        .PARAMETER File
            The path(s) to XML data file(s) generated by Get-WindowsProcessConnection.
        #>
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [string[]] $File
    )

    process
    {
        foreach ($xmlFile in $File)
        {
            $xmlReader = [System.Xml.XmlReader]::Create($xmlFile)

            $xmlWriterSettings = New-Object 'System.Xml.XmlWriterSettings'
            $xmlWriterSettings.Encoding = [System.Text.Encoding]::UTF8
            $xmlWriterSettings.Indent = $true
            $xmlWriterSettings.IndentChars = '  '

            $htmlTempFile = [System.IO.Path]::ChangeExtension($xmlFile, '.html')
            $xmlWriter = [System.Xml.XmlWriter]::Create($htmlTempFile, $xmlWriterSettings)

            $xslt = New-Object 'System.Xml.Xsl.XslCompiledTransform'
            $xslt.Load((Join-Path (Split-Path -Parent $PSCommandPath) 'WindowsProcessConnections.xsl'))
            $xslt.Transform($xmlReader, $xmlWriter)

            $xmlReader.Close()
            $xmlWriter.Close()

            $htmlTempFile
        }
    }
}

function Export-WindowsProcessConnection
{
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [pscustomobject] $ProcessConnections,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -PathType Container $_ })]
        [string] $FolderPath
    )

    process
    {
        $xmlFilePath = Join-Path $FolderPath "WindowsProcessConnections_$($_.Computer)_$($_.CaptureDateTime.ToString('yyyyMMddHHmmssfff')).xml"
        $ProcessConnections.ProcessConnections.WriteXml($xmlFilePath, [System.Data.XmlWriteMode]::WriteSchema)
        $xmlFilePath
    }
}
