function Get-SPQuotaTemplate
{
    <#
    .SYNOPSIS
    Gets a SharePoint quota template by either the quota ID or the name. If neither is specified all quota templates are retrieved.
    .DESCRIPTION
    Gets a SharePoint quota template by either the quota ID or the name. If neither is specified all quota templates are retrieved.
    .PARAMETER Name
    Specifies the name of the quota template to get.
    .PARAMETER QuotaID
    Specifies quota ID of the quota to get.
    .EXAMPLE
    Test-SPSiteQuotaInfo -Identity http://mywebapp/sites/mysitecollection
    #>
    [CmdletBinding(SupportsShouldProcess = $false, DefaultParameterSetName = "None")]
    param
    (
        [Parameter(ParameterSetName = "Name", Mandatory = $true, ValueFromPipeline = $true)]
        [string] $Name,
        [Parameter(ParameterSetName = "QuotaID", Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [UInt16] $QuotaID
    )

    process
    {
        [Microsoft.SharePoint.Administration.SPQuotaTemplate[]] $spQuotaTemplate = $null
        
        if ($QuotaID -ne 0)
        {
            $spQuotaTemplate = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.QuotaTemplates | ?{ $_.QuotaID -eq $QuotaID }
        }
        elseif ([string]::IsNullOrWhiteSpace($Name) -eq $false)
        {
            $spQuotaTemplate = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.QuotaTemplates | ?{ $_.Name -eq $Name }
        }
        else
        {
            $spQuotaTemplate = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.QuotaTemplates
        }

        return $spQuotaTemplate
    }
}

function Test-SPSiteQuotaNeedsUpdate
{
    <#
    .SYNOPSIS
    Tests the quota on a site collection to see if it needs to be update to match a quota template that has been changed.
    .DESCRIPTION
    Tests the quota on a site collection to see if it needs to be update to match a quota template that has been changed. This is necessary because, if a quota template has been changed after it was used on a site collection, SharePoint does not automatically update the site collection quota to match.
    .PARAMETER Identity
    Specifies the URL or GUID of the site collection to get.
    .EXAMPLE
    Test-SPSiteQuotaInfo -Identity http://mywebapp/sites/mysitecollection
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [Microsoft.SharePoint.PowerShell.SPSitePipeBind] $Identity
    )

    process
    {
        $spSite = Get-SPSite -Identity $Identity

        $quotaNeedsUpdate = $true
        [Microsoft.SharePoint.Administration.SPQuota] $spSiteQuota = $spSite.Quota

        if ($spSite.Quota.QuotaID -ne 0)
        {
            $spSiteQuotaTemplate = $spSite.Quota | Get-SPQuotaTemplate

            if ($spSiteQuotaTemplate -ne $null)
            {
                [Microsoft.SharePoint.Administration.SPQuota] $spSiteQuota = [Microsoft.SharePoint.Administration.SPQuota] $spSiteQuotaTemplate
                $quotaComparisonResult = Compare-Object $spSiteQuotaTemplate $spSite.Quota -Property QuotaID, StorageMaximumLevel, InvitedUserMaximumLevel, StorageWarningLevel, UserCodeWarningLevel, UserCodeMaximumLevel -IncludeEqual

                if($quotaComparisonResult.SideIndicator -eq "==")
                {
                    $quotaNeedsUpdate = $false
                }
            }
        }
        else
        {
            $quotaNeedsUpdate = $false
        }

        return $quotaNeedsUpdate
    }
}

function Get-SPSiteQuotaInfo
{
    <#
    .SYNOPSIS
    Gets information about the quotas for a SharePoint site collection.
    .DESCRIPTION
    Gets the quota information for a SharePoint site collection.
    .PARAMETER Identity
    Specifies the URL or GUID of the site collection to get.
    .PARAMETER Limit
    Limits the maximum number of site collections to return quota info for. The default value is 20.
    .EXAMPLE
    Get-SPSiteQuotaInfo
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [parameter(ValueFromPipeLine = $true)]
        [Microsoft.SharePoint.PowerShell.SPSitePipeBind] $Identity,
        [parameter()]
        [string] $Limit = "20"
    )
    
    begin
    {
        $rootWebIDColumn = @{name = 'RootWebID'; expression = { $_.RootWeb.ID } }
        $rootWebTitleColumn = @{name = 'RootWebTitle'; expression = { $_.RootWeb.Title } }
        $quotaIDColumn = @{name = 'QuotaID'; expression = { $_.Quota.QuotaID } }
        $quotaTemplateColumn = @{name = 'QuotaTemplate'; expression = { $quotaID = $_.Quota.QuotaID; if ($quotaID -eq 0) { "Individual Quota" } else { (($_.Quota | Get-SPQuotaTemplate).Name, "Unknown ($($quotaID))" -ne $null)[0] } } }
        $storageMaximumLevelColumn = @{ name = 'StorageMaximumLevel'; expression = { $_.Quota.StorageMaximumLevel } }
        $storageWarningLevelColumn = @{ name = 'StorageWarningLevel'; expression = { $_.Quota.StorageWarningLevel } }
        $storageUsedColumn = @{ name = 'StorageUsed'; expression = { $_.Usage.Storage } }
        $quotaNeedsUpdateColumn = @{ name = 'QuotaNeedsUpdate'; expression = { Test-SPSiteQuotaNeedsUpdate $_ } }
        $contentDatabaseNameColumn = @{ name = 'ContentDatabaseName'; expression = { $_.ContentDatabase.Name } }
    }

    process
    {
        $spQuotaInfo = $null

        # Sites must be retrieved with elevated privileges in order to ensure consistent access to the usage data.
        [Microsoft.SharePoint.SPSecurity]::RunWithElevatedPrivileges(
        {
            [Microsoft.SharePoint.SPSite[]] $spSites = $Identity | Get-SPSite -Limit $Limit
            $spQuotaInfo = $spSites | Select ID, Url, $rootWebIDColumn, $rootWebTitleColumn, $quotaIDColumn, $quotaTemplateColumn, $storageMaximumLevelColumn, $StorageWarningLevelColumn, $storageUsedColumn, $quotaNeedsUpdateColumn, $contentDatabaseNameColumn | %{ $_.PSObject.TypeNames.Insert(0, 'SharePointQuotaManagement.QuotaInfo'); $_ }

            # Passes the array of PSCustomObjects generated by the Select back out to the parent.
            Set-Variable -Scope 1 -Name spQuotaInfo -Value $spQuotaInfo
        })

        return $spQuotaInfo
    }

    end
    {
    }
}

function Update-SPSiteQuota
{
    <#
    .SYNOPSIS
    Updates the SharePoint site collection's quota limits using the values from the quota template associated with the site collection.
    .DESCRIPTION
    Updates the SharePoint site collection's quota limits using the values from the quota template associated with the site collection. This is necessary because, if a quota template has been changed after it was used on a site collection, SharePoint does not automatically update the site collection quota to match.
    .PARAMETER Identity
    Specifies the URL or GUID of the site collection to get.
    .PARAMETER Limit
    Limits the maximum number of site collections to return quota info for. The default value is 20.
    .EXAMPLE
    Update-SPSiteQuota
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [Microsoft.SharePoint.PowerShell.SPSitePipeBind] $Identity,
        [Parameter()]
        [string] $Limit = "20"
    )

    process
    {
        [Microsoft.SharePoint.SPSite[]] $spSites = $Identity | Get-SPSite -Limit $Limit

        foreach ($spSite in $spSites)
        { 
            if ((Test-SPSiteQuotaNeedsUpdate -Identity $spSite) -eq $true)
            {
                $spQuotaTemplate = Get-SPQuotaTemplate -QuotaID $spSite.Quota.QuotaID;
                Write-Host "Updating the quota for $($spSite.Url) using the $($spQuotaTemplate.Name) quota template."
                Set-SPSite -Identity $spSite -QuotaTemplate $spQuotaTemplate.Name
            }
        }
    }
}

function Get-SPSiteLockState
{
    <#
    .SYNOPSIS
    Gets the lock state of the specified site collection.
    .DESCRIPTION
    Gets the lock state of the specified site collection in a form that is compatible with the LockState argument to Set-SPSite.
    .PARAMETER Identity
    Specifies the URL or GUID of the site collection to get.
    .PARAMETER Limit
    Limits the maximum number of site collections to return quota info for. The default value is 20.
    .EXAMPLE
    Get-SPSiteLockState -Identity http://mywebapp/sites/mysitecollection
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [Microsoft.SharePoint.PowerShell.SPSitePipeBind] $Identity,
        [parameter()]
        [string] $Limit = "20"
    )

    begin
    {
        $urlColumn = @{name = "Url"; expression = { $_.Url } }
        $lockStateColumn =
            @{
                name = "LockState";
                expression = 
                {
                    $lockState = ""

                    if ($_.ReadOnly -eq $true)
                    {
                        $lockState = "ReadOnly"
                    }
                    elseif ($_.WriteLocked -eq $true)
                    {
                        if ($_.ReadLocked -eq $true)
                        {
                            $lockState = "NoAccess"
                        }
                        else
                        {
                            $lockState = "NoAdditions"
                        }
                    }
                    else
                    {
                        $lockState = "Unlock"
                    }

                    return $lockState
                }
            }
    }

    process
    {
        [Microsoft.SharePoint.SPSite[]] $spSites = $Identity | Get-SPSite -Limit $Limit
        return $spSites | Select $urlColumn, $lockStateColumn
    }
}
