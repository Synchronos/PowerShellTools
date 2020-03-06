Import-Module WebAdministration -ErrorAction Stop

function Get-CertificateTemplate
{
    <#
    .SYNOPSIS
    Gets the template name from the Certificate Template Information extension on an X.509 certificate.
    .DESCRIPTION
    Gets the template name from the Certificate Template Information extension on an X.509 certificate. Typically the result is the friendly name of the template followed by the OID in parentheses.
    .EXAMPLE
    Get-CertificateTemplate $certificate
    .EXAMPLE
    $certificate | Get-CertificateTemplate
    .PARAMETER Certificate
    The X.509 Certificate.
    .LINK
    about_CertificateManagement
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    process
    {
        [string] $certificateTemplate = $null

        if ($Certificate -ne $null)
        {
            $certificateTemplateExtension = $Certificate.Extensions | ?{ $_.Oid.FriendlyName -eq 'Certificate Template Information' }

            if ($certificateTemplateExtension -ne $null)
            {
                $certificateTemplateInfo = $certificateTemplateExtension.Format($true) | ConvertFrom-StringData
                $certificateTemplate = $certificateTemplateInfo.Template
            }
        }

        return $certificateTemplate
    }
}

function Get-SslServerCertificate
{
    <#
    .SYNOPSIS
    Gets a certifcate from the machine's Personal or WebHosting certificate stores by its thumbprint (or certificate hash).
    .DESCRIPTION Gets a certifcate from the machine's Personal or WebHosting certificate stores by its thumbprint (or certificate hash). If a wildcard (*) is given for the Thumbprint parameter all matching certificates that support SSL/TLS servers will be retrieved.
    .PARAMETER Thumbprint
    The thumbprint (or certificate hash) that uniquely identifies an X.509 certificate.
    .PARAMETER Subject
    The subject that identifies an X.509 certificate.
    .PARAMETER TemplateFriendlyName
    The thumbprint (certificate hash) that uniquely identifies an X.509 certificate.
    .PARAMETER TemplateOid
    The thumbprint (or certificate hash) that uniquely identifies an X.509 certificate.
    .PARAMETER ExpiringInDays
    If specified, the number of days before a certificate expires must be less than or equal to this number to be included.
    .PARAMETER IncludeArchived
    If this switch is present certificates with the Archived property set to true will be included in the result.
    .EXAMPLE
    Get-SslServerCertificate $thumbprint
    .EXAMPLE
    $thumbprint | Get-SslServerCertificate
    .LINK
    about_CertificateManagement
    #>
    [CmdletBinding(SupportsShouldProcess = $false, DefaultParameterSetName = 'Thumbprint')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Thumbprint')]
        [Alias('CertificateHash')]
        [SupportsWildcards()]
        [ValidatePattern('^([0-9A-Za-z*?]|(?<=.*\*.*)\[[0-9A-Za-z]+?\](?=.*\*/*))+$')]
        [string] $Thumbprint,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'SubjectWithTemplateFriendlyName')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'SubjectWithTemplateOid')]
        [string] $Subject,
        [Parameter(ParameterSetName = 'SubjectWithTemplateFriendlyName')]
        [string] $TemplateFriendlyName,
        [Parameter(ParameterSetName = 'SubjectWithTemplateOid')]
        [string] $TemplateOid,
        [Parameter()]
        [int] $ExpiringInDays,
        [Parameter()]
        [switch] $IncludeArchived
    )

    begin
    {
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $certificates = @()

        if ($PSBoundParameters.ContainsKey('Thumbprint') -eq $false)
        {
            if ($PSBoundParameters.ContainsKey('ExpiringInDays'))
            {
                [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $allCertificates = Get-ChildItem 'Cert:\LocalMachine\My' -SSLServerAuthentication -Force:$IncludeArchived -ExpiringInDays $ExpiringInDays -ErrorAction SilentlyContinue
                $allCertificates += Get-ChildItem 'Cert:\LocalMachine\My' -SSLServerAuthentication -Force:$IncludeArchived -ExpiringInDays $ExpiringInDays -ErrorAction SilentlyContinue
                $allCertificates += Get-ChildItem 'Cert:\LocalMachine\WebHosting' -SSLServerAuthentication -Force:$IncludeArchived -ExpiringInDays $ExpiringInDays -ErrorAction SilentlyContinue
            }
            else
            {
                [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $allCertificates = Get-ChildItem 'Cert:\LocalMachine\My' -SSLServerAuthentication -Force:$IncludeArchived -ErrorAction SilentlyContinue
                $allCertificates += Get-ChildItem 'Cert:\LocalMachine\My' -SSLServerAuthentication -Force:$IncludeArchived -ErrorAction SilentlyContinue
                $allCertificates += Get-ChildItem 'Cert:\LocalMachine\WebHosting' -SSLServerAuthentication -Force:$IncludeArchived -ErrorAction SilentlyContinue
            }
        }
    }

    process
    {
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $certificateResult = @()

        if ($PSBoundParameters.ContainsKey('Thumbprint'))
        {
            $certificateResult += Get-Item "Cert:\LocalMachine\My\$($Thumbprint)" -SSLServerAuthentication -Force:$IncludeArchived -ErrorAction SilentlyContinue
            $certificateResult += Get-Item "Cert:\LocalMachine\WebHosting\$($Thumbprint)" -Force:$IncludeArchived -ErrorAction SilentlyContinue
        
            # Without a wildcard in the thumbprint, ExpiringInDays is ignored by Get-Item even if it is present, so a where filter is used instead.
            if ($PSBoundParameters.ContainsKey('ExpiringInDays'))
            {
                $certificateResult = $certificateResult | ?{ $_.NotAfter.Subtract([DateTime]::Today).TotalDays -le $ExpiringInDays }
            }

        }
        elseif ($PSBoundParameters.ContainsKey('Subject'))
        {
            $certificateResult = $allCertificates | ?{ $_.Subject -eq $Subject }

            if ($PSBoundParameters.ContainsKey('TemplateOid'))
            {
                $certificateResult = $certificateResult | ?{ $_.Subject -eq $Subject -and (Get-CertificateTemplate $_) -replace '^.+?\(((?:\d+\.)+\d+)\)$', '$1' -eq $TemplateOid }
            }
            elseif ($PSBoundParameters.ContainsKey('TemplateFriendlyName'))
            {
                $certificateResult = $certificateResult | ?{ $_.Subject -eq $Subject -and (Get-CertificateTemplate $_) -replace '^(.+)?\((?:\d+\.)+\d+\)$', '$1' -eq $TemplateFriendlyName }
            }
        }

        if ($certificateResult.Count -gt 0)
        {
            $certificates += $certificateResult
        }
    }

    end
    {
        return $certificates
    }
}

function Get-WebsiteUrl
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string] $Name
    )

    process
    {
        $iisWebSite = Get-Website $Name

        [System.Collections.Generic.List[Uri]] $webSiteUrls = New-Object System.Collections.Generic.List[Uri]
        $httpBindings = $iisWebSite.bindings.Collection | ?{ $_.protocol -in 'http', 'https' }

        foreach ($httpBinding in $httpBindings)
        {
            $bindingInformation = $httpBinding.bindingInformation.Split(':')

            [UriBuilder] $webSiteUrl = New-Object UriBuilder
            $webSiteUrl.Scheme = $httpBinding.protocol
            $webSiteUrl.Path = '/'
            $webSiteUrl.Port = $bindingInformation[1]

            if ($bindingInformation.Length -eq 3 -and $bindingInformation[2] -ne '')
            {
                $webSiteUrl.Host = $bindingInformation[2]
                $webSiteUrls.Add($webSiteUrl.Uri)
            }
            elseif ($bindingInformation[0] -ne '' -and $bindingInformation[0] -ne '*')
            {
                $dnsNames = (Resolve-DnsName -ErrorAction SilentlyContinue -DnsOnly $bindingInformation[0]).NameHost

                if ($dnsNames -eq $null)
                {
                    $dnsNames = $bindingInformation[0]
                }

                if ($dnsNames -ne $null)
                {
                    $dnsNames | %{ $webSiteUrl.Host = $_; $webSiteUrls.Add($webSiteUrl.Uri) }
                }
                else
                {
                    $bindingInformation[0] | %{ $webSiteUrl.Host = $_.IPAddress; $webSiteUrls.Add($webSiteUrl.Uri) }
                }
            }
            else
            {
                $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -Type Unicast | ?{ $_.AddressState -eq 'Preferred' }

                foreach ($ipAddress in $ipAddresses)
                {
                    $dnsNames = $ipAddress | %{ (Resolve-DnsName -ErrorAction SilentlyContinue -DnsOnly $_.IPAddress).NameHost }

                    if ($dnsNames -eq $null)
                    {
                        $dnsNames = $ipAddress.IPAddress
                    }

                    if ($dnsNames -ne $null)
                    {
                        $dnsNames | %{ $webSiteUrl.Host = $_; $webSiteUrls.Add($webSiteUrl.Uri) }
                    }
                    else
                    {
                        $ipAddress | %{ $webSiteUrl.Host = $_.IPAddress; $webSiteUrls.Add($webSiteUrl.Uri) }
                    }
                }

                Get-Website | ?{ $_.ID -ne $iisWebSite.ID -and $_.State -eq 'Started' -and $bindingInformation[1] -in ($_.bindings.Collection | ?{ $_.protocol -in 'http', 'https' }).bindingInformation.Split(':')[1] } | Get-WebsiteUrl | %{ [void] $webSiteUrls.Remove($_) }
            }
        }

        return $webSiteUrls
    }
}

function Get-WebApplicationPool
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $true)]
        [string] $Name = '*',
        [Parameter(DontShow = $True, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ApplicationPool
    )

    process
    {
        if ($PSBoundParameters.ContainsKey('ApplicationPool') -eq $true)
        {
            $Name = $ApplicationPool
        }

        $applicationPoolPath = Join-Path 'IIS:\AppPools' $Name
        $matchingApplicationPool = Get-Item $applicationPoolPath
        return $matchingApplicationPool
    }
}

function Get-WebApplicationParent($webAppliation)
{
    Get-WebSite ($webApplication.GetParentElement().GetAttributeValue('Name'))
}

function Get-WebApplicationUrl($webApplication)
{
    $iisWebSite = Get-WebApplicationParent $webApplication
    $webSiteUrls = $iisWebSite | Get-WebsiteUrl

    foreach ($webSiteUrl in $webSiteUrls)
    {
        New-Object Uri($webSiteUrl, $webApplication.path)
    }
}

function Get-WebInventory()
{
    $websiteNameColumn = @{ name = 'WebsiteName'; expression = { $_.Name } }
    $websiteIDColumn = @{ name = 'WebsiteID'; expression = { $_.id } }
    $websiteVirtualPathColumn = @{ name = 'VirtualPath'; expression = { '/' } }
    $websiteUrlColumn = @{ name = 'Url'; expression = { Get-WebsiteUrl $_.Name } }
    $websiteCertficateHashColumn = @{ name = 'Thumbprint'; expression = { $_.bindings.collection.certificateHash | ?{ [string]::IsNullOrEmpty($_) -eq $false } } }
    $websiteCertificateSubjectColumn = @{ name = 'CertificateSubject'; expression = { ($_.bindings.collection | ?{ [string]::IsNullOrEmpty($_.certificateHash) -eq $false } | Get-SslServerCertificate).Subject } }
    $websiteCertificateExpirationColumn = @{ name = 'CertificateExpiration'; expression = { ($_.bindings.collection | ?{ [string]::IsNullOrEmpty($_.certificateHash) -eq $false } | Get-SslServerCertificate).NotAfter } }

    $applicationWebsiteNameColumn = @{ name = 'WebsiteName'; expression = { $_.GetParentElement().Attributes['name'].Value } }
    $applicationWebsiteIDColumn = @{ name = 'WebsiteID'; expression = { $_.GetParentElement().Attributes['id'].Value } }
    $applicationVirtualPathColumn = @{ name = 'VirtualPath'; expression = { $_.Path } }
    $applicationUrlColumn =  @{ name = 'Url'; expression = { Get-WebApplicationUrl $_ } }
    $applicationCertificateHashColumn = @{ name = 'Thumbprint'; expression = { $null } }
    $applicationCertificateSubjectColumn = @{ name = 'CertificateSubject'; expression = { $null } }
    $applicationCertificateExpirationColumn = @{ name = 'CertificateExpiration'; expression = { $null } }

    $applicationPoolAccountColumn = @{ name = 'ApplicationPoolAccount'; expression = { $applicationPool = Get-WebApplicationPool $_.applicationPool; if ($applicationPool.processModel.identityType -ne 'SpecificUser') { $applicationPool.processModel.identityType } else { $applicationPool.processModel.userName } } }

    $iisWebSites = Get-Website

    [PSCustomObject[]] $iisWebSiteUrls = $iisWebSites | Select $websiteNameColumn, $websiteIDColumn, $websiteVirtualPathColumn, applicationPool, $applicationPoolAccountColumn, physicalPath, $websiteUrlColumn, $websiteCertificateSubjectColumn, $websiteCertificateExpirationColumn, $websiteCertficateHashColumn
    $iisApplications = Get-WebApplication
    [PSCustomObject[]] $iisApplicationUrls = $iisApplications | Select $applicationWebsiteNameColumn, $applicationWebsiteIDColumn, $applicationVirtualPathColumn, applicationPool, $applicationPoolAccountColumn, physicalPath, $applicationUrlColumn, $applicationCertificateSubjectColumn, $applicationCertificateExpirationColumn, $applicationCertificateHashColumn

    $websitesAndApplications = $iisWebSiteUrls + $iisApplicationUrls | Sort Host, AbsolutePath, Scheme, Port

    return $websitesAndApplications
}
