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
            $dnsRecord = Resolve-DnsName -DnsOnly $ipAddress -ErrorAction SilentlyContinue
            if ($null -ne $dnsRecord)
            {
                $dnsRecord.NameHost
            }
            else
            {
                ''
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

        if ($dmtfDate.EndsWith('+000') -eq $false)
        {
            $dateKind = [DateTimeKind]::Local
        }

        [DateTimeOffset]::new([DateTime]::SpecifyKind($date, $dateKind))
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
        $owner = $process.GetOwner()

        if ($null -ne $owner.Domain)
        {
            "$($owner.Domain)\$($owner.User)"
        }
        else
        {
            $owner.User
        }
    }
    catch [System.Management.ManagementException]
    {
        $_.Exception.Message
    }
}

function Create-WindowsProcessConnectionDataSet()
{
    $windowsProcessConnectionDataSet = [System.Data.DataSet]::new('WindowsProcessConnection')
    $windowsProcessConnectionDataSet.SchemaSerializationMode = [System.Data.SchemaSerializationMode]::IncludeSchema

    $networkAdapterTable = $windowsProcessConnectionDataSet.Tables.Add('NetworkAdapter')
    $networkAdapterKeyColumn = $networkAdapterTable.Columns.Add('InterfaceIndex', [long])
    [void] $networkAdapterTable.Columns.Add('ServiceName', [string])
    [void] $networkAdapterTable.Columns.Add('Description', [string])
    [void] $networkAdapterTable.Columns.Add('MACAddress', [string])
    [void] $networkAdapterTable.Columns.Add('DHCPEnabled', [bool])
    [void] $networkAdapterTable.Columns.Add('DHCPLeaseObtained', [DateTimeOffset])
    [void] $networkAdapterTable.Columns.Add('DHCPLeaseExpires', [DateTimeOffset])
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
    [void] $processTable.Columns.Add('CreationDate', [DateTimeOffset])
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
    [void] $tcpConnectionTable.Columns.Add('CreationTime', [DateTimeOffset])
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
    [void] $udpEndpointTable.Columns.Add('CreationTime', [DateTimeOffset])
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
    [void] $orphanTcpConnectionTable.Columns.Add('CreationTime', [DateTimeOffset])
    $orphanTcpConnectionTable.PrimaryKey = $orphanTcpConnectionKeyColumn

    $orphanUdpEndpointTable = $windowsProcessConnectionDataSet.Tables.Add('OrphanUDPEndPoint')
    $orphanUdpEndpointKeyColumn = $orphanUdpEndpointTable.Columns.Add('InstanceId', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('OwningProcess', [long])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalAddressName', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalAddress', [string])
    [void] $orphanUdpEndpointTable.Columns.Add('LocalPort', [int])
    [void] $orphanUdpEndpointTable.Columns.Add('CreationTime', [DateTimeOffset])
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

    $networkAdapterTable.BeginLoadData()
    Get-WmiObject -ComputerName $computer -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = true' | %{ [void] $networkAdapterTable.LoadDataRow(@($_.InterfaceIndex, $_.ServiceName, $_.Description, $_.MACAddress, $_.DHCPEnabled, (Get-ManagementDate $_.DHCPLeaseObtained), (Get-ManagementDate $_.DHCPLeaseExpires), $_.DHCPServer, $_.IPAddress, $_.IPSubnet, $_.DefaultIPGateway, $_.FullDNSRegistrationEnabled, $_.DnsHostName, $_.DNSDomain, $_.DNSServerSearchOrder), $true) }
    $networkAdapterTable.EndLoadData()

    $processTable.BeginLoadData()
    Get-WmiObject -ComputerName $computer -Class 'Win32_Process' | %{ [void] $processTable.LoadDataRow(@($_.ProcessId, $_.ParentProcessId, $_.Name, $_.ExecutablePath, $_.CommandLine, (Format-Owner $_), (Get-ManagementDate $_.CreationDate)), $true) }
    $processTable.EndLoadData()

    $tcpConnectionTable.BeginLoadData()
    $udpEndpointTable.BeginLoadData()

    Get-WmiObject -ComputerName $computer -Namespace 'ROOT/StandardCimv2' -Class 'MSFT_NetTCPConnection' | Select *, $localAddressNameProperty, $remoteAddressNameProperty, $tcpStateNameProperty | %{ [void] $tcpConnectionTable.LoadDataRow(@($_.InstanceId, $_.OwningProcess, $_.LocalAddressName, $_.LocalAddress, $_.LocalPort, $_.RemoteAddressName, $_.RemoteAddress, $_.RemotePort, $_.StateName, (Get-ManagementDate $_.CreationTime)), $true) }
    Get-WmiObject -ComputerName $computer -Namespace 'ROOT/StandardCimv2' -Class 'MSFT_NetUDPEndpoint' | Select *, $localAddressNameProperty | %{ [void] $udpEndpointTable.LoadDataRow(@($_.InstanceId, $_.OwningProcess, $_.LocalAddressName, $_.LocalAddress, $_.LocalPort, (Get-ManagementDate $_.CreationTime)), $true) }

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
    Get-WmiObject -ComputerName $computer -Class 'Win32_Service' -Filter "State != 'Stopped'" | %{ [void] $serviceTable.LoadDataRow(@($_.Name, $_.DisplayName, $_.Description, $_.PathName, $_.Status, $_.ProcessId), $true) }
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
            $windowsProcessConnectionDataSet = Create-WindowsProcessConnectionDataSet
            Load-WindowsProcessConnectionDataSet $computerToQuery $windowsProcessConnectionDataSet

            $xmlTempFile = Join-Path ([System.IO.Path]::GetTempPath()) "WindowsProcessConnections_$($computerToQuery)_$(Get-Date -Format 'yyyyMMddHHmmssfff').xml"
            $windowsProcessConnectionDataSet.WriteXml($xmlTempFile, [System.Data.XmlWriteMode]::WriteSchema)

            $xmlTempFile
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

            $xmlWriterSettings = [System.Xml.XmlWriterSettings]::new()
            $xmlWriterSettings.Encoding = [System.Text.Encoding]::UTF8
            $xmlWriterSettings.Indent = $true
            $xmlWriterSettings.IndentChars = '  '

            $htmlTempFile = [System.IO.Path]::ChangeExtension($xmlFile, '.html')
            $xmlWriter = [System.Xml.XmlWriter]::Create($htmlTempFile, $xmlWriterSettings)

            $xslt = [System.Xml.Xsl.XslCompiledTransform]::new()
            $xslt.Load((Join-Path (Split-Path -Parent $PSCommandPath) 'WindowsProcessConnections.xsl'))
            $xslt.Transform($xmlReader, $xmlWriter)

            $xmlReader.Close()
            $xmlWriter.Close()

            $htmlTempFile
        }
    }
}
