# Begin hexadecimal conversion function
function ConvertFrom-Hexadecimal([string] $hexString)
{
    [byte[]] $data = @()

    if ([string]::IsNullOrEmpty($hexString) -eq $true -or $hexString.Length % 2 -ne 0)
    {
        throw New-Object FormatException("Hexadecimal string must not be empty and must contain an even number of digits to be valid.");
    }

    $hexString = $hexString.ToUpperInvariant()
    $data = New-Object byte[] -ArgumentList ($hexString.Length / 2)

    for ([int] $index = 0; $index -lt $hexString.Length; $index += 2)
    {
        [int] $highDigitValue = if ($hexString[$index] -le ([char] '9')) { $hexString[$index] - ([char] '0') } else { $hexString[$index] - ([char] 'A') + 10 }
        [int] $lowDigitValue = if ($hexString[$index + 1] -le ([char] '9')) { $hexString[$index + 1] - ([char] '0') } else { $hexString[$index + 1] - ([char] 'A') + 10 }

        if ($highDigitValue -lt 0 -or $lowDigitValue -lt 0 -or $highDigitValue -gt 15 -or $lowDigitValue -gt 15)
        {
            throw New-Object FormatException("An invalid digit was encountered. Valid hexadecimal digits are 0-9 and A-F.")
        }
        else
        {
            [byte] $value = [byte](($highDigitValue -shl 4) -bor ($lowDigitValue -band 0x0F))
            $data[$index / 2] = $value;
        }
    }

    return ,$data
}
# End hexadecimal conversion function

function Get-SqlDeadlockHistory
{
    <#
    .SYNOPSIS
    Gets the deadlock history from the system health extended events on the specified SQL Server instance.
    .DESCRIPTION
    Gets the deadlock history from the system health extended events on the specified SQL Server instance and writes them to the specified folder or to a Deadlocks directory in the current user's documents folder if no folder is specified.
    When the process completes, SQL server startup date, most recent deadlock date, total number of deadlocks, and number of deadlock graph files written will be displayed.
    .EXAMPLE
    Get-SqlDeadlockHistory "SqlServerName\Instance"
    .EXAMPLE
    Get-SqlDeadlockHistory "SqlServerName"
    .PARAMETER SqlServerInstance
    The SQL Server name and instance that Get-SqlDeadlockHistory will connect to.
    .PARAMETER UserName
    If specified a SQL autenticated account will be used to connect to the SQL Server instance.
    .PARAMETER Password
    If a UserName has been specified, uses the given password for the SQL authenticated account; otherwise, the user will be prompted for a password. If UserName has not been specified, this parameter is ignored.
    .PARAMETER OutputDirectory
    If specified the deadlock files will be written to the given directory; otherwise, deadlock files are written to Deadlocks\<SqlServerInstance> under the current user's My Documents folder.
    .PARAMETER Overwrite
    If Overwrite is present deadlock files will overwrite any pre-existing deadlock files that have the same name; otherwise, deadlocks corresponding to pre-exsiting files will be skipped.
    .PARAMETER UseEventFiles
    If UseEventFiles is present deadlock files will be retrieved from the system health event files rather than the ring buffer; otherwise, deadlocks are retrieved from the ring buffer.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        [string] $SqlServerInstance,
        [Parameter(Mandatory = $false, ValueFromPipeLine = $false)]
        [string] $UserName = $null,
        [Parameter(Mandatory = $false, ValueFromPipeLine = $false)]
        [string] $Password = $null,
        [Parameter(Mandatory = $false, ValueFromPipeLine = $false)]
        [string] $OutputDirectory = $null,
        [switch] $Overwrite,
        [switch] $UseEventFiles
    )

    process
    {
        if (([string]::IsNullOrWhiteSpace($OutputDirectory) -eq $true) -or ((Test-Path $OutputDirectory -PathType Container) -eq $false))
        {
            $OutputDirectory = Join-Path $env:USERPROFILE "Documents\Deadlocks\$($SqlServerInstance.Replace(":", "_"))"
        }

        Write-Host "Deadlock events will be retrieved from $($SqlServerInstance) and written to $($OutputDirectory)."

        [System.Data.SqlClient.SqlConnectionStringBuilder] $connectionStringBuilder = New-Object "System.Data.SqlClient.SqlConnectionStringBuilder"
        $connectionStringBuilder.PSBase.DataSource = $SqlServerInstance
        $connectionStringBuilder.PSBase.InitialCatalog = "master"

        if ($PSBoundParameters.ContainsKey("UserName") -eq $true)
        {
            $connectionStringBuilder.PSBase.UserID = $UserName

            if ($PSBoundParameters.ContainsKey("Password") -eq $true)
            {
                $connectionStringBuilder.PSBase.Password = $Password
            }
            else
            {
                $connectionStringBuilder.PSBase.Password = (Read-Host "Password: ")
            }
        }
        else
        {
                $connectionStringBuilder.PSBase.IntegratedSecurity = $true
        }

        $connectionStringBuilder.PSBase.WorkstationID = $env:COMPUTERNAME
        $connectionStringBuilder.PSBase.ApplicationName = $MyInvocation.MyCommand.Name

        if ((Test-Path $outputDirectory -PathType Container) -eq $false)
        {
            New-Item $outputDirectory -ItemType Container
        }

        [string] $startTimeQuery = "SELECT sqlserver_start_time FROM sys.dm_os_sys_info"

        if ($UseEventFiles -eq $false)
        {
        [string] $deadlockQuery = "SELECT        ringBuffer.event.value(N'./@timestamp', N'datetimeoffset') AS timestamp
            , CONVERT(xml, CASE WHEN CONVERT(varchar(3), SERVERPROPERTY(N'ProductVersion')) = '10.' THEN ringBuffer.event.value(N'(./data/value/node())[1]', N'nvarchar(MAX)') ELSE ringBuffer.event.query(N'(./data/value/node())[1]') END) AS deadlockGraph
FROM            (
                    SELECT        CONVERT(xml, sys.dm_xe_session_targets.target_data) AS target_data
                    FROM            sys.dm_xe_session_targets INNER JOIN
                                              sys.dm_xe_sessions ON sys.dm_xe_session_targets.event_session_address = sys.dm_xe_sessions.address
                    WHERE        (sys.dm_xe_sessions.name = 'system_health') AND (sys.dm_xe_session_targets.target_name = N'ring_buffer')
                ) AS sessionTarget
                CROSS APPLY sessionTarget.target_data.nodes(N'/RingBufferTarget/event[@name=`"xml_deadlock_report`"]') AS ringBuffer(event)"
        }
        else
        {
            [string] $deadlockQuery = ";WITH sessionTargetData
AS (
        SELECT sys.dm_xe_sessions.name AS session_name
                , sys.dm_xe_session_targets.target_name
                , CONVERT(XML, sys.dm_xe_session_targets.target_data) AS target_data
        FROM sys.dm_xe_sessions
        INNER JOIN sys.dm_xe_session_targets
                ON sys.dm_xe_sessions.address = sys.dm_xe_session_targets.event_session_address
        WHERE target_name = N'event_file'
        )
        , sessionTargetFiles
AS (
        SELECT session_name
                , target_name
                , target.eventFile.value(N'@name', N'nvarchar(MAX)') AS target_filename
        FROM sessionTargetData
        CROSS APPLY target_data.nodes('/EventFileTarget/File') AS target(eventFile)
        )
        , sessionDeadlockEvents
AS (
        SELECT session_name
                , file_name
                , CONVERT(XML, event_data) AS event_data
        FROM sessionTargetFiles
        CROSS APPLY sys.fn_xe_file_target_read_file(LEFT(target_filename, PATINDEX(N'%[_][0-9][_]%', target_filename)) + '*.xel' , NULL, NULL, NULL)
        WHERE (object_name = N'xml_deadlock_report')
        )
SELECT deadlock.event.value(N'./@timestamp', N'datetimeoffset') AS timestamp
        , CONVERT(XML, CASE 
                        WHEN CONVERT(VARCHAR(3), SERVERPROPERTY(N'ProductVersion')) = '10.'
                                THEN deadlock.event.value(N'(./data/value/node())[1]', N'nvarchar(MAX)')
                        ELSE deadlock.event.query(N'(./data/value/node())[1]')
                        END) AS deadlockGraph
FROM sessionDeadlockEvents
OUTER APPLY event_data.nodes(N'/event[@name=`"xml_deadlock_report`"]') AS deadlock(event)"
        }

        [string] $partitionQuery = "CREATE TABLE #allPartitions
(
    partition_id bigint NOT NULL,
    database_id int NOT NULL,
    hobt_id bigint NOT NULL,
    object_id int NOT NULL,
    index_id int NOT NULL,
    database_name sysname NOT NULL,
    object_schema_name sysname NOT NULL,
    object_name sysname NOT NULL,
    index_name sysname NULL
)
ALTER TABLE dbo.#allPartitions ADD CONSTRAINT
    PK_#allPartitions PRIMARY KEY CLUSTERED 
    (
    database_id,
    partition_id
    ) WITH( STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]

DECLARE @partitionQuery nvarchar(2000)
DECLARE @dbName sysname

SET @partitionQuery = 'USE [?];
INSERT INTO [#allPartitions]
                         (partition_id, database_id, hobt_id, object_id, index_id, database_name, object_schema_name, object_name, index_name)
SELECT        sys.partitions.partition_id, DB_ID(N''?'') AS database_id, sys.partitions.hobt_id, sys.partitions.object_id, sys.partitions.index_id, ''?'' AS database_name, 
                         OBJECT_SCHEMA_NAME(sys.partitions.object_id) AS object_schema_name, OBJECT_NAME(sys.partitions.object_id) AS object_name, sys.indexes.name AS index_name
FROM            sys.partitions LEFT OUTER JOIN
                         sys.indexes ON sys.indexes.object_id = sys.partitions.object_id AND sys.indexes.index_id = sys.partitions.index_id'

EXEC sp_MSforeachdb @partitionQuery

SELECT        partition_id, database_id, hobt_id, object_id, index_id, database_name, object_schema_name, object_name, index_name
FROM            #allPartitions

DROP TABLE #allPartitions
"

        [string] $objectQuery = "
CREATE TABLE #allObjects
(
    database_id int NOT NULL,
    object_id int NOT NULL,
    database_name sysname NOT NULL,
    object_schema_name sysname NOT NULL,
    object_name sysname NOT NULL
)
ALTER TABLE dbo.#allObjects ADD CONSTRAINT
    PK_#allObjects PRIMARY KEY CLUSTERED 
    (
    database_id,
    object_id
    ) WITH( STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]

DECLARE @objectQuery nvarchar(2000)
DECLARE @dbName sysname

SET @objectQuery = 'USE [?];
INSERT INTO [#allObjects]
                         (database_id, object_id, database_name, object_schema_name, object_name)
SELECT        DB_ID(N''?'') AS database_id, object_id, ''?'' AS database_name, SCHEMA_NAME(schema_id) AS object_schema_name,
                         name AS object_name
FROM            sys.objects'

EXEC sp_MSforeachdb @objectQuery

SELECT        database_id, object_id, database_name, object_schema_name, object_name
FROM            #allObjects

DROP TABLE #allObjects
"

        $sqlTextQuery = "
SELECT dbid
        , objectid
        , TEXT
        , SUBSTRING(TEXT, (@startOffset / 2) + 1, (
                        (
                                CASE @endOffset
                                        WHEN - 1
                                                THEN DATALENGTH(TEXT)
                                        ELSE @endOffset
                                        END - @startOffset
                                ) / 2
                        ) + 1) AS statement_text
FROM sys.dm_exec_sql_text(@sqlHandle)"

        [System.Data.SqlClient.SqlConnection] $connection = New-Object "System.Data.SqlClient.SqlConnection" -ArgumentList @($connectionStringBuilder.ConnectionString)

        [System.Data.SqlClient.SqlCommand] $startTimeQueryCommand = $connection.CreateCommand()
        $startTimeQueryCommand.CommandText = $startTimeQuery
        $startTimeQueryCommand.CommandType = [System.Data.CommandType]::Text

        [System.Data.SqlClient.SqlCommand] $deadlockQueryCommand = $connection.CreateCommand()
        $deadlockQueryCommand.CommandText = $deadlockQuery
        $deadlockQueryCommand.CommandType = [System.Data.CommandType]::Text

        [System.Data.SqlClient.SqlDataAdapter] $deadlockQueryDataAdapter = New-Object "System.Data.SqlClient.SqlDataAdapter" -ArgumentList $deadlockQueryCommand
        [System.Data.DataTable] $deadlockTable = New-Object "System.Data.DataTable"

        [System.Data.SqlClient.SqlCommand] $partitionQueryCommand = $connection.CreateCommand()
        $partitionQueryCommand.CommandText = $partitionQuery
        $partitionQueryCommand.CommandType = [System.Data.CommandType]::Text

        [System.Data.SqlClient.SqlDataAdapter] $partitionQueryDataAdapter = New-Object "System.Data.SqlClient.SqlDataAdapter" -ArgumentList $partitionQueryCommand
        [System.Data.DataTable] $partitionTable = New-Object "System.Data.DataTable"

        [System.Data.SqlClient.SqlCommand] $objectQueryCommand = $connection.CreateCommand()
        $objectQueryCommand.CommandText = $objectQuery
        $objectQueryCommand.CommandType = [System.Data.CommandType]::Text

        [System.Data.SqlClient.SqlDataAdapter] $objectQueryDataAdapter = New-Object "System.Data.SqlClient.SqlDataAdapter" -ArgumentList $objectQueryCommand
        [System.Data.DataTable] $objectTable = New-Object "System.Data.DataTable"

        [System.Data.SqlClient.SqlCommand] $sqlTextQueryCommand = $connection.CreateCommand()
        $sqlTextQueryCommand.CommandText = $sqlTextQuery
        $sqlTextQueryCommand.CommandType = [System.Data.CommandType]::Text
        $sqlTextSqlHandleParam = $sqlTextQueryCommand.Parameters.Add("@sqlHandle", [System.Data.SqlDbType]::VarBinary, 64)
        $sqlTextStartOffsetParam = $sqlTextQueryCommand.Parameters.Add("@startOffset", [System.Data.SqlDbType]::Int)
        $sqlTextEndOffsetParam = $sqlTextQueryCommand.Parameters.Add("@endOffset", [System.Data.SqlDbType]::Int, 64)

        Write-Verbose "Connecting to $($SqlServerInstance)."
        $connection.Open()

        Write-Verbose "Getting SQL Server start time."
        [DateTime] $startTime = $startTimeQueryCommand.ExecuteScalar()

        Write-Verbose "Getting SQL deadlock events from the ring buffer."
        [int] $deadlockRowsReturned = $deadlockQueryDataAdapter.Fill($deadlockTable)

        Write-Verbose "Getting partiton information."
        [int] $partitionRowsReturned = $partitionQueryDataAdapter.Fill($partitionTable)

        Write-Verbose "Getting object information."
        [int] $objectRowsReturned = $objectQueryDataAdapter.Fill($objectTable)

        $startTimeQueryCommand.Dispose()
        $deadlockQueryDataAdapter.Dispose()
        $deadlockQueryCommand.Dispose()
        $partitionQueryDataAdapter.Dispose()
        $partitionQueryCommand.Dispose()
        $objectQueryDataAdapter.Dispose()
        $objectQueryCommand.Dispose()

        $deadlocksWritten = 0
        [DateTimeOffset] $mostRecentDeadlock = [DateTimeOffset]::MinValue

        [int] $deadlockCount = $deadlockTable.Rows.Count
        [int] $deadlockItem = 0;
        Write-Verbose "Processing deadlock $($deadlockCount) graphs."

        ForEach ($deadlockRow in $deadlockTable.Rows)
        {
            Write-Progress -Id 1 -Activity "Processing Deadlock Graphs" -PercentComplete ($deadlockItem / $deadlockCount * 100)
            $deadlockItem++

            $deadlockLocalTime = $deadlockRow.timestamp.ToLocalTime()

            if ($deadlockLocalTime -gt $mostRecentDeadlock)
            {
                $mostRecentDeadlock = $deadlockLocalTime
            }

            [string] $xdlFileName = "Deadlock_$($deadlockLocalTime.ToString("yyyyMMdd_HHmmss_fff")).xdl"
            [string] $xdlFilePath = Join-Path $OutputDirectory $xdlFileName

            Write-Verbose "Using deadlock graph file $($xdlFileName)."

            if (((Test-Path $xdlFilePath) -eq $false) -or ($Overwrite -eq $true))
            {
                [XML] $deadlockGraphDocument = $deadlockRow.deadlockGraph

                $missingObjectNameNodes = $deadlockGraphDocument.deadlock.'resource-list'.SelectNodes("child::node()[@objectname='']")
                Write-Verbose "Found $($missingObjectNameNodes.Count) resource node(s) with no object names."

                ForEach ($missingObjectNameNode in $missingObjectNameNodes)
                {
                    $objectName = $null
                    $indexName = $null

                    if ($missingObjectNameNode.hobtid -ne $null)
                    {
                        Write-Verbose "Looking up Heap or B-Tree ID $($missingObjectNameNode.hobtid)."
                        $objectRow = $partitionTable.Where({ ($_.hobt_id -eq $missingObjectNameNode.hobtid) -and ($_.database_id -eq $missingObjectNameNode.dbid) })
                        $objectName = "$($objectRow.database_name).$($objectRow.object_schema_name).$($objectRow.object_name)"
                        $indexName = $objectRow.index_name
                    }
                    elseif ($missingObjectNameNode.associatedObjectId -ne $null)
                    {
                        Write-Verbose "Looking up Partition ID $($missingObjectNameNode.associatedObjectId)."
                        $objectRow = $partitionTable.Where({ ($_.partition_id -eq $missingObjectNameNode.associatedObjectId) -and ($_.database_id -eq $missingObjectNameNode.dbid) })
                        $objectName = "$($objectRow.database_name).$($objectRow.object_schema_name).$($objectRow.object_name)"
                    }

                    if ($objectName -ne $null)
                    {
                        Write-Verbose "Found object $($objectName)."
                        $missingObjectNameNode.objectname = $objectName
                    }

                    if ($indexName -ne $null)
                    {
                        Write-Verbose "Found index $($indexName)."
                        $missingObjectNameNode.indexname = $indexName
                    }
                }

                $executionStackFrames = $deadlockGraphDocument.deadlock.'process-list'.SelectNodes('//process/executionStack/frame[@procname="" or text() = "" or normalize-space(text())="unknown" or contains(text(), "*password----")]')
                Write-Verbose "Found $($executionStackFrames.Count) execution stack frame(s) with no proc name or no statement text."

                ForEach ($executionStackFrame in $executionStackFrames)
                {
                    $currentDatabaseID = $executionStackFrame.ParentNode.ParentNode.currentdb
                    $dbid = $null
                    $objectID = $null

                    if ([string]::IsNullOrWhiteSpace($executionStackFrame.sqlhandle) -eq $false)
                    {
                        Write-Verbose "Looking up sql handle $($executionStackFrame.sqlhandle)."

                        $statementStart = 0
                        if ([string]::IsNullOrWhiteSpace($executionStackFrame.stmtstart) -eq $false)
                        {
                            $statementStart = [int]::Parse($executionStackFrame.stmtstart)
                        }

                        $statementEnd = -1
                        if ([string]::IsNullOrWhiteSpace($executionStackFrame.stmtend) -eq $false)
                        {
                            $statementEnd = [int]::Parse($executionStackFrame.stmtend)
                        }

                        $sqlTextSqlHandleParam.Value = ConvertFrom-Hexadecimal $executionStackFrame.sqlhandle.Replace("0x", "")
                        $sqlTextStartOffsetParam.Value = $statementStart
                        $sqlTextEndOffsetParam.Value = $statementEnd
                        $sqlTextReader = $sqlTextQueryCommand.ExecuteReader()

                        if ($sqlTextReader.HasRows -eq $true)
                        {
                            $rowAvailable = $sqlTextReader.Read()
                            $dbid = $sqlTextReader["dbid"]
                            $objectID = $sqlTextReader["objectid"]
                            $queryText = $sqlTextReader["text"]
                            $statementText = $sqlTextReader["statement_text"]

                            $isQueryTextMissing = [string]::IsNullOrWhitespace($executionStackFrame.InnerText) -eq $true -or $executionStackFrame.InnerText.Trim() -eq "unknown" -or $executionStackFrame.InnerText -match "\*password-+\s*$"
                            $hasQueryLookupResult = $queryText -ne $null -and $queryText -ne [DBNull]::Value

                            if ($isQueryTextMissing -eq $true -and $hasQueryLookupResult -eq $true)
                            {
                                Write-Verbose "Found statement text."

                                $executionStackFrame.InnerText = $statementText
                            }
                        }

                        $sqlTextReader.Close()
                        $sqlTextReader.Dispose()

                        if ([string]::IsNullOrWhitespace($executionStackFrame.procname) -eq $true -and $objectID -ne $null -and $objectID -ne [System.DBNull]::Value)
                        {
                            if ($dbid -eq $null -or $dbid -eq [System.DBNull]::Value)
                            {
                                $dbid = $currentDatabaseID
                            }

                            Write-Verbose "Looking up procedure name for object ID $($objectID) in database id $($dbid)."
                            $procRow = $objectTable.Where({ ($_.database_id -eq $dbid) -and ($_.object_id -eq $objectID) })
                            $procName = "$($procRow.database_name).$($procRow.object_schema_name).$($procRow.object_name)"
                            Write-Verbose "Found procedure name $($procName)."

                            $executionStackFrame.procname = $procName
                        }
                    }
                }

                Write-Verbose "Writing deadlock graph to file."
                [System.Xml.XmlWriterSettings] $xdlWriterSettings = New-Object "System.Xml.XmlWriterSettings"
                $xdlWriterSettings.OmitXmlDeclaration = $false
                $xdlWriterSettings.Indent = $true
                $xdlWriterSettings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
                $xdlWriterSettings.CloseOutput = $true

                [System.Xml.XmlWriter] $xdlWriter = [System.Xml.XmlWriter]::Create($xdlFilePath, $xdlWriterSettings)
            
                $deadlockGraphDocument.Save($xdlWriter)

                $xdlWriter.Close()
                $xdlWriter.Dispose()

                $deadlocksWritten++
            }
            else
            {
                Write-Verbose "Pre-existing deadlock graph file will not be overwritten."
            }
        }
        Write-Progress -Id 1 -Activity "Processing Deadlock Graphs" -Completed

        $sqlTextQueryCommand.Dispose()
        $connection.Close()
        $connection.Dispose()
        $deadlockTable.Dispose()
        $partitionTable.Dispose()
        $objectTable.Dispose()

        Write-Host "$($SqlServerInstance) up since $($startTime)."

        if ($mostRecentDeadlock -gt [DateTimeOffset]::MinValue)
        {
            Write-Host "Most recent deadlock occurred at $($mostRecentDeadlock)."
        }

        Write-Host "$($deadlocksWritten) of $($deadlockRowsReturned) deadlock graphs written to $($outputDirectory)."
    }
}

function Analyze-DeadlockGraphs
{
    <#
    .SYNOPSIS
	Analyzes the deadlock graph files (.xdl) in the specified directory.
    .DESCRIPTION
	Analyzes the deadlock graph files (.xdl) in the specified directory and writes Deadlocks By Object.csv, Deadlocks by Date and Object.csv, and Deadlocks with Objects.csv
    .EXAMPLE
    .PARAMETER XdlFolderPath
	All deadlock files will be read from the given directory.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        [string] $XdlFolderPath
    )

    process
    {
        # Get the list of .xdl files.
        $deadlockFiles = dir (Join-Path $xdlFolderPath "*.xdl") | Sort Name

        # Load the xml content for analysis.
        $deadlocks =  $deadlockFiles| Select @{ name = "File"; expression = { $_ } }, @{ name = "DeadlockDateTime"; expression = { Get-Date ($_.Name -replace "Deadlock_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_(\d{3}).xdl", '$1-$2-$3 $4:$5:$6.$7') } }, @{ name = "Xml"; expression = { ([xml] (Get-Content $_)) } }

        $firstDeadlockDate = ($deadlocks | Select -First 1).DeadlockDateTime
        $lastDeadlockDate = ($deadlocks | Select -Last 1).DeadlockDateTime

        # Get the locked objects from the Xml and add them as a column.
        $deadlocksWithObjects = $deadlocks | Select File, DeadlockDateTime, @{ name = "LockedObjectName"; expression = { $_.Xml.deadlock.'resource-list'.ChildNodes | % { "$($_.objectname)$(if ([string]::IsNullOrEmpty($_.indexname) -eq $false) { "($($_.indexname))" })" } | Select -Unique } }, Xml

        # Get summary information.
        $deadlocksByObject = $deadlocksWithObjects | Group-Object LockedObjectName | Select @{ name = "LockedObjectName"; expression = { $_.Name } }, Count, @{ name = "LastDeadlockDateTime"; expression = { ($_.Group | Measure-Object DeadlockDateTime -Maximum).Maximum } }
        $deadlockByDateAndObject = $deadlocksWithObjects | Group-Object { $_.DeadlockDateTime.Date }, LockedObjectName | Select @{ name = "DeadlockDate"; expression = { $_.Values[0] } }, @{ name = "LockedObjectName"; expression = { $_.Values[1] } }, Count
        $deadlockByHourOfDayAndObject = $deadlocksWithObjects | Group-Object { $_.DeadlockDateTime.Date }, { $_.DeadlockDateTime.Hour }, LockedObjectName | Select @{ name = "DeadlockDate"; expression = { $_.Values[0] } }, @{ name = "DeadlockHour"; expression = { $_.Values[1] } }, @{ name = "LockedObjectName"; expression = { $_.Values[2] } }, Count

        # Display the data.
        Write-Host "`nAnalyzing deadlocks in $($xdlFolderPath) between $($firstDeadlockDate) and $($lastDeadlockDate)."

        $deadlocksByObject | ft LockedObjectName, Count, LastDeadlockDateTime -AutoSize
        $deadlockByDateAndObject | ft @{ name = "DeadlockDate"; expression = { $_.DeadlockDate.ToShortDateString() } }, LockedObjectName, Count -AutoSize
        $deadlockByHourOfDayAndObject | ft @{ name = "DeadlockDate"; expression = { $_.DeadlockDate.ToShortDateString() } }, @{ name = "DeadlockHour"; expression = { $_.DeadlockHour } }, LockedObjectName, Count -AutoSize
        $deadlocksWithObjects | ft @{name = "FileName"; expression = { $_.File.Name } }, DeadlockDateTime, LockedObjectName -AutoSize

        $deadlocksByObject | Export-Csv (Join-Path $XdlFolderPath "Deadlocks By Object.csv") -NoTypeInformation
        $deadlockByDateAndObject | Export-Csv (Join-Path $XdlFolderPath "Deadlocks by Date and Object.csv") -NoTypeInformation
        $deadlockByHourOfDayAndObject | Export-Csv (Join-Path $XdlFolderPath "Deadlocks by Hour Of Day and Object.csv") -NoTypeInformation
        $deadlocksWithObjects | Export-Csv (Join-Path $XdlFolderPath "Deadlocks with Objects.csv") -NoTypeInformation
    }
}
