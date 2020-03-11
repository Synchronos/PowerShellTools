if ( (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue) -eq $null )
{
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop
}
