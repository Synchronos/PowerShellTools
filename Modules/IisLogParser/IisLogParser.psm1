Import-Module WebAdministration

function Get-WebsiteLogDirectory($webSite)
{
    $logDirectoryPath = Join-path ([Environment]::ExpandEnvironmentVariables($webSite.logFile.directory)) "W3SVC$($webSite.id)"
    return $logDirectoryPath
}

function Get-IisLogDateLocal ($dateUtc, $timeUtc)
{
    return  [datetime]::SpecifyKind([DateTime]::Parse("$dateUtc $timeUtc"), [System.DateTimeKind]::Utc).ToLocalTime()
}

function Get-IisLogDateTimeOffset ($dateUtc, $timeUtc)
{
    return [DateTimeOffset] [datetime]::SpecifyKind([DateTime]::Parse("$dateUtc $timeUtc"), [System.DateTimeKind]::Utc)
}

function Get-IisLogFileDate($logFileName)
{
    $logFileDatePart = $logFileName -replace '.*u_ex(\d{6}).*\.log$', '$1'
    $logFileDate = [datetime]::ParseExact($logFileDatePart, "yyMMdd", [System.Globalization.DateTimeFormatInfo]::CurrentInfo, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
    $logFileDate
}

function Import-IisWebSiteLogFile
{
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $Path
    )

    begin
    {
      $localDateTimeColumn = @{ name = 'local-date-time'; expression = { (Get-IisLogDateLocal $_.date $_.time) }; }
      $dateTimeOffsetColumn = @{ name = 'date-time-offset'; expression = { (Get-IisLogDateTimeOffset $_.date $_.time) }; }
    }
    
    process
    {
        try
        {
            $logFileHeader = @()
            $logFileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $logReader = New-Object System.IO.StreamReader($logFileStream)

            while ($logReader.EndOfStream -eq $false)
            {
                $logLine = $logReader.ReadLine()

                if ($logLine.StartsWith("#Fields: ") -eq $true)
                {
                    $logFileHeader = $logLine.Remove(0,9).Split(' ')
                }

                if ($logLine.StartsWith("#") -eq $false)
                {
                    $logLine | ConvertFrom-Csv -Delimiter ' ' -Header $logFileHeader | Select $dateTimeOffsetColumn, $localDateTimeColumn, *
                }
            }
        }
        finally
        {
            if ($logReader -ne $null)
            {
                $logReader.Close()
                $logReader.Dispose()
            }

            if ($logFileStream -ne $null)
            {
                $logFileStream.Close()
                $logFileStream.Dispose()
            }
        }
    }
}

function Get-IisWebSiteLog
{
    [CmdletBinding(SupportsShouldProcess=$false)]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [Parameter()]
        [System.DateTimeOffset] $StartDate = [System.DateTimeOffset] [DateTime]::Today.AddDays(-1),
        [Parameter()]
        [System.DateTimeOffset] $EndDate = [System.DateTimeOffset]::Now
    )

    begin
    {
        $logFileDateProperty = @{ name = 'LogFileDate'; expression = { (Get-IisLogFileDate $_.Name) }; }
    }

    process
    {
        $webSite = Get-WebSite -Name $Name
        Write-Host "Getting log files for $($webSite.name)..."

        if ($webSite -ne $null)
        {
            $iisLogDirectory = Get-WebsiteLogDirectory $webSite

            $logFileStartDate = $StartDate.ToUniversalTime().Date
            $logFileEndDate = $EndDate.ToUniversalTime().Date
            $logFiles = (Get-ChildItem -Recurse "$($iisLogDirectory)\u_ex*.log" | Select *, $logFileDateProperty | Sort LogFileDate).Where({ $_.LogFileDate -ge $logFileStartDate }, 'SkipUntil').Where({ $_.LogFileDate -gt $logFileEndDate }, 'Until')

            foreach ($logFile in $logFiles)
            {
                if ($logFile.LogFileDate -eq $logFileStartDate)
                {
                    Write-Host "`tParsing log file $($logFile.FullName)..."
                    (Import-IisWebSiteLogFile $logFile.FullName).Where({ $_.'date-time-offset' -ge $StartDate }, 'SkipUntil')
                }
                elseif ($logFile.LogFileDate -lt $logFileEndDate)
                {
                    Write-Host "`tParsing log file $($logFile.FullName)..."
                    (Import-IisWebSiteLogFile $logFile.FullName)
                }
                else
                {
                    Write-Host "`tParsing log file $($logFile.FullName)..."
                    (Import-IisWebSiteLogFile $logFile.FullName).Where({ $_.'date-time-offset' -gt $EndDate }, 'Until')
                }
            }
        }
    }
}
