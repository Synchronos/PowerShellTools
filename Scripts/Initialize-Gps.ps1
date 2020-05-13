$resetConfigurationChoices =   @{
                                    "HotStart" = 1;      # Hot Start -- All data valid
                                    "WarmStart" = 2;     # Warm Start -- Ephemeris Cleared
                                    "WarmStartInit" = 3; # Warm Start (with Init) -- Ephemeris cleared, initialization data loaded
                                    "ColdStart" = 4;     # Cold Start  -- Clears all data in memory
                                    "ClearMemory" = 8;   # Clear Memory -- Clears all data in memory and resets receiver back to factory defaults
                                }
$latitude = 0.0 # decimal degrees
$longitude = 0.0 # decimal degrees
$altitude = 0 # in meters
$clockOffset = 0 # 0 uses the last saved value, default is 96000 Hz
$channelCount = 12
$resetConfiguration = $resetConfigurationChoices['WarmStart']

$ntpTimestampEpochDate = [System.DateTimeOffset]::Parse('1 January 1900, 00:00:00')
$leapSecondList = (Invoke-WebRequest 'https://www.ietf.org/timezones/data/leap-seconds.list').Content.Split("`n") | Select-String -NotMatch -Pattern '^\#' | ConvertFrom-Csv -Header "NtpTimestamp", "LeapSecondNumber", "Comment" -Delimiter "`t"
$gpsEpochDate = [System.DateTimeOffset]::Parse("1980/01/06T00:01:00Z")
$gpsEpochNtpTimestamp = ($gpsEpochDate - $ntpTimestampEpochDate).TotalSeconds
$leapSecondCount = ($leapSecondList | ?{ $_.NtpTimeStamp -ge $gpsEpochNtpTimestamp }).Count
$timeSinceGpsEpoch = [System.DateTimeOffset]::UtcNow.AddSeconds($leapSecondCount) - $gpsEpochDate
$gpsWeek = [System.Math]::Floor($timeSinceGpsEpoch.Days / 7)
$gpsSecondOfWeek = [System.Math]::Floor($timeSinceGpsEpoch.TotalSeconds - $gpsWeek * 604800)

$gpsInitializationSentence = "`$PSRF104,$($latitude),$($longitude),$($altitude),$($clockOffset),$($gpsSecondOfWeek),$($gpsWeek),$($channelCount),$($resetConfiguration)"
$gpsInitializationSentenceBytes = [System.Text.Encoding]::ASCII.GetBytes(($gpsInitializationSentence -replace '^\$(.*)\*|$', '$1'))

$gpsChecksum = $gpsInitializationSentenceBytes[0]
1..$gpsInitializationSentenceBytes.Length | %{ $gpsChecksum = $gpsChecksum -bxor $gpsInitializationSentenceBytes[$_] }

if ($gpsInitializationSentence.EndsWith('*') -eq $false)
{
    $gpsInitializationSentence  +=  '*'
}

$gpsInitializationSentence += $gpsChecksum.ToString('X2')

$gpsInitializationSentence
