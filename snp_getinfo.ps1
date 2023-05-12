##########################################################
# function
##########################################################

function snp_getInfo {

    param (
               [Parameter(Mandatory=$true)][string]$cn,
               [Parameter(Mandatory=$true)]$user
           )
    
        $globalStamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"
    
        $winrmStatus = testWinRM $cn
        if (!($winrmStatus -match 'WinRM Detected')) {
            write-output " - $cn not responding -"
            break
        }
    
        [string[]]$arrayNoir = $null
        $arrayNoir += 'cd c:\'
        [string]$string = '$optionNoPro = New-PSSessionOption -nomachineprofile'
        
        $arrayNoir += $string
        
        $string = '$noProSession = New-PSSession -ComputerName ' +  $cn + ' -name NoProSes_' + $cn + ' -SessionOption $optionNoPro'
    
        $arrayNoir += $string
    
        $arrayNoir += 'sleep 3'        
        $arrayNoir += 'if (!(pssession)){write-output "Session not established"; break}'
        
        ##########################################################
        # netConnections
        ##########################################################
        #
        #icm-begin
        $arrayNoir += '$netConData = icm -session $noProSession {'
        $arrayNoir += '$sortType = "ProcessName"'
        $arrayNoir += '$connections = Get-NetTCPConnection | select LocalPort, RemoteAddress, RemotePort, State, OwningProcess'
        $arrayNoir += '$processes = gps | select ID, ProcessName, StartTime'
        
        [string]$string = '[string[]]$svcHostServices = cmd /c tasklist /svc /fi ' + "'imagename eq svchost.exe'"
        $arrayNoir += $string
    
        $arrayNoir += '$array1 = @()'
        $arrayNoir += 'for($i=0;$i -lt $($svcHostServices.count); $i++) {'
        $string = 'if (($svcHostServices[$i] -match ' + '"^svchost.exe") -or ($svcHostServices[$i] -match ' + '"^\s")){$array1+=$svcHostServices[$i]}}'
        $arrayNoir += $string
        $arrayNoir += '$array2a = @()'
        $arrayNoir += '$array2b = @()'
        $arrayNoir += 'for ($i=0;$i -lt $($array1.count); $i++ ) {'
        
        $string = 'if ($($array1[$i]) -notmatch "^\s") {'
        $arrayNoir += $string
    
        $arrayNoir += '[string]$string = $array1[$i]'
        $arrayNoir += 'if ($($i + 1) -ne $($array1.count)) {'
        
        $string = 'Do {if ($($array1[$i + 1] -notmatch "^svchost.exe")) {'
        $arrayNoir += $string
        $arrayNoir += '[string]$string = $string + $($array1[$i + 1])'
        $arrayNoir += '$i++'
        
        $string = '}}while ($($array1[$i + 1]) -notmatch "^svchost.exe")}}'
        $arrayNoir += $string
        $arrayNoir += '$string = $string -replace "\s+", " "'
        $arrayNoir += '$string = $string -replace "^svchost.exe "'
        $arrayNoir += '[string]$string1 = [regex]::match($string,"^\d+").value'
        $arrayNoir += '[string]$string2 = [regex]::match($string,"(?<=\d+\s).+").value'
        $arrayNoir += '$array2a += $string1'
        $arrayNoir += '$array2b += $string2'
        $arrayNoir += '}'    
        
        $arrayNoir += '$bucketOConnections = @()'
    
        $arrayNoir += 'foreach ($connection_item in $connections) {'
        $arrayNoir += 'foreach ($process_item in $processes) {'
        $arrayNoir += 'if ($($process_item.ID) -ne 0) {'
        $arrayNoir += 'if ($($process_item.ID) -ne 4) {'
        $arrayNoir += 'if ($($connection_item.OwningProcess) -like $($process_item.ID)) {'
        $arrayNoir += 'for ($i=0; $i -lt $($array2a.count); $i++) {'
        $arrayNoir += 'if ($($array2a[$i] -like $($connection_item.OwningProcess))){'
        $arrayNoir += '[string]$fullProcessList = $($array2b[$i])'
        $arrayNoir += 'break'
        $arrayNoir += '}else {$fullProcessList = ""}}'
    
        $arrayNoir += '$connectionObject = New-Object psobject'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "LocalPort" -Value $($connection_item.LocalPort)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value $($connection_item.RemoteAddress)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "RemotePort" -Value $($connection_item.RemotePort)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "State" -Value $($connection_item.State)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "PID" -Value $($process_item.ID)'
        $arrayNoir += '$pidStartTime = $($process_item.StartTime)'
    
        $string = '$pidStartTime_formatted = ' + "'{0}'" + ' -f $pidStartTime'
        $arrayNoir += $string
    
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $pidStartTime_formatted'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "OwningProcess" -Value $($connection_item.OwningProcess)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "ProcessName" -Value $($process_item.ProcessName)'
        $arrayNoir += '$connectionObject | Add-Member -MemberType NoteProperty -Name "Processes" -Value $fullProcessList'
        $arrayNoir += '$bucketOConnections += $connectionObject}}}}}'    
        
        $arrayNoir += '$formattingData = @{Expression={$_.LocalPort}; Label="LocalPort"; Alignment="left"; Width=12},'
        $arrayNoir += '@{Expression={$_.RemoteAddress}; Label="RemoteAddress"; Alignment="left"; Width=18},'
        $arrayNoir += '@{Expression={$_.RemotePort}; Label="RemotePort"; Alignment="left"; Width=12},'
       $arrayNoir += '@{Expression={$_.State}; Label="State"; Alignment="left"; Width=14},'
        $arrayNoir += '@{Expression={$_.PID}; Label="PID"; Alignment="left"; Width=8},'
        $arrayNoir += '@{Expression={$_.OwningProcess}; Label="OwningProcess"; Alignment="left"; Width=16},'
        $arrayNoir += '@{Expression={$_.StartTime}; Label="StartTime"; Alignment="left"; Width=25},'
        $arrayNoir += '@{Expression={$_.ProcessName}; Label="ProcessName"; Alignment="left"; Width=16},'
        $arrayNoir += '@{Expression={$_.Processes}; Label="Processes"; Alignment="left"; Width=250}'
        $arrayNoir += '$bucketOConnections | sort $sortType | ft -Property $formattingData'
        $arrayNoir += '}'
        #icm end
        
    
        #$arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        #$arrayNoir += '$cn = (get-pssession).ComputerName'
        $string = '$netConData | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-netConnectionsReport.txt -force'
        $arrayNoir += $string
        #$arrayNoir += '$netConData | out-file c:\netConnectionsReport-$cn-$stamp.txt -Append'
        #$arrayNoir += 'start-process notepad c:\netConnectionsReport-$cn-$stamp.txt'
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-netConnectionsReport.txt'
        $arrayNoir += $string
        $arrayNoir += ''
    
        ##########################################################
        # gpsReport
        ##########################################################
        #
        #icm-begin
        $arrayNoir += '$gpsData = icm -session $noProSession {'
        $string = 'gps | select  processname, path -unique | fl'
        $arrayNoir += $string
        $arrayNoir += '}'
        #icm end
        #
        #$arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        #$arrayNoir += '$cn = (get-pssession).ComputerName'
        $string = '$gpsData | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-gpsReport.txt -force'
        $arrayNoir += $string
        #$arrayNoir += '$gpsData | out-file c:\gpsReport-$cn-$stamp.txt -Append'
        #$arrayNoir += 'start-process notepad c:\gpsReport-$cn-$stamp.txt'
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-gpsReport.txt'
        $arrayNoir += $string
        $arrayNoir += ''
    
        ##########################################################
        # gsvReport
        ##########################################################
        #
        #icm-begin
        $arrayNoir += '$gsvData = icm -session $noProSession {'
        $string = 'gsv | select  displayname, name, servicename, status, starttype | fl'
        $arrayNoir += $string
        $arrayNoir += '}'
        #icm end
        #
    
        $string = '$gsvData | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-gsvReport.txt -force'
        $arrayNoir += $string
        
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-gsvReport.txt'
        $arrayNoir += $string
        $arrayNoir += ''
    
    
        ##########################################################
        # wtsReport
        ##########################################################
        #
        #icm-begin
        $arrayNoir += '$logons = icm -session $noProSession {'
        $string = '$q = ' + "'" + '<QueryList>'
        $arrayNoir += $string
        $arrayNoir += '<Query Id="0" Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">'
        $arrayNoir += '<Select Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">*[System[(EventID=21)]]</Select>'
        $arrayNoir += '</Query>'
        $arrayNoir += "</QueryList>'"
        $arrayNoir += '$a = get-winevent -FilterXml $q'
        $arrayNoir += 'for ($i = 0 ; $i -lt $($a.count); $i++) {'
        $arrayNoir += '[string]$cn = $a[$i].MachineName'
        $arrayNoir += '$cn = $cn.split(".")[0]'
        $arrayNoir += '[string]$RecordId = $a[$i].RecordId'
        $arrayNoir += '[string]$Message = $a[$i].Message'
        $arrayNoir += '[string]$Id = $a[$i].Id'
        $arrayNoir += '[string]$TimeCreated = $a[$i].TimeCreated'
        $arrayNoir += '[string[]]$Message_string_array = $Message -split "`r`n"'
        $arrayNoir += 'foreach($item in $Message_string_array) {'
        $arrayNoir += 'if ($item -match "Services:") {'
        $arrayNoir += '$status = [regex]::match($item, "(?<=(Services:\s))[^:]+").value'
        $arrayNoir += '}'
        $arrayNoir += 'if ($item -match "User:") {'
        $arrayNoir += '$user = [regex]::match($item, "(?<=(User:\s))\S+").value'
        $arrayNoir += '}'
        $arrayNoir += 'if ($item -match "Address:") {'
        $arrayNoir += '$source = [regex]::match($item, "(?<=(Address:\s))\S+").value'
        $arrayNoir += '}'
        $arrayNoir += '}'
        $arrayNoir += '"{0,-18}{1,-7}{2,-9}{3,-4}{4,-5}{5,-22}{6,-33}{7,-32}{8,-10}{9}" -f $cn,"Index:",$RecordId,"Id:",$Id,$TimeCreated,$status,$user,"Source:",$source'
        $arrayNoir += '}'
        $arrayNoir += '}'
        #icm end
        #
        #icm begin
        $arrayNoir += '$everything = icm -session $noProSession {'
        $string = '$q = ' + "'" + '<QueryList>'
        $arrayNoir += $string
        $arrayNoir += '<Query Id="0" Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">'
        $arrayNoir += '<Select Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]</Select>'
        $arrayNoir += '</Query>'
        $arrayNoir += "</QueryList>'"
        $arrayNoir += '$a = get-winevent -FilterXml $q'
        $arrayNoir += 'for ($i = 0 ; $i -lt $($a.count); $i++) {'
        $arrayNoir += '[string]$cn = $a[$i].MachineName'
        $arrayNoir += '$cn = $cn.split(".")[0]'
        $arrayNoir += '[string]$RecordId = $a[$i].RecordId'
        $arrayNoir += '[string]$Message = $a[$i].Message'
        $arrayNoir += '[string]$Id = $a[$i].Id'
        $arrayNoir += '[string]$TimeCreated = $a[$i].TimeCreated'
        $arrayNoir += '[string[]]$Message_string_array = $Message -split "`r`n"'
        $arrayNoir += 'foreach($item in $Message_string_array) {'
        $arrayNoir += 'if ($item -match "Services:") {'
        $arrayNoir += '$status = [regex]::match($item, "(?<=(Services:\s))[^:]+").value'
        $arrayNoir += '}'
        $arrayNoir += 'if ($item -match "User:") {'
        $arrayNoir += '$user = [regex]::match($item, "(?<=(User:\s))\S+").value'
        $arrayNoir += '}'
        $arrayNoir += 'if ($item -match "Address:") {'
        $arrayNoir += '$source = [regex]::match($item, "(?<=(Address:\s))\S+").value'
        $arrayNoir += '}'
        $arrayNoir += '}'
        $arrayNoir += '"{0,-18}{1,-7}{2,-9}{3,-4}{4,-5}{5,-22}{6,-33}{7,-32}{8,-10}{9}" -f $cn,"Index:",$RecordId,"Id:",$Id,$TimeCreated,$status,$user,"Source:",$source'
        $arrayNoir += '}'
        $arrayNoir += '}'
        #icm end
        #
        
        #$arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        #$arrayNoir += '$cn = (get-pssession).ComputerName'
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -force'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file c:\wtsReport-$cn-$stamp.txt -force'
    
        $string = 'write-output "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational: Logons" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational: Logons" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "--------------------------------------------------------------------------"| out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "--------------------------------------------------------------------------"| out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        
        $string = '$logons | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += '$logons | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
       $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational: Everything" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational: Everything" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "------------------------------------------------------------------------------"| out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "------------------------------------------------------------------------------"| out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = '$everything | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += '$everything | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file c:\wtsReport-$cn-$stamp.txt -Append'
        
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-wtsReport.txt'
        $arrayNoir += $string
        #$arrayNoir += 'start-process notepad c:\wtsReport-$cn-$stamp.txt'
        $arrayNoir += ''
    
        ##########################################################
        # dnsCache
        ##########################################################
    
        #icm-begin
        $arrayNoir += '$returnedContent = icm -session $noProSession {'
        $arrayNoir += '[string[]]$a = Get-DnsClientCache | fl | out-string -stream'
        $arrayNoir += '[string[]]$stray = $null'
        $arrayNoir += '$b = $a | sls "^[a-zA-Z]"'
        $arrayNoir += '$c = $b | % {[regex]::match($_,"^\S+").value}'
        $arrayNoir += '[string[]]$stray = $null'
        $arrayNoir += '[string]$string = "Entry;RecordName;RecordType;Status;Section;TimeToLive;DataLength;Data;"'
        $arrayNoir += '$stray += $string'
        $arrayNoir += 'for ($i=0; $i -lt $($b.count); $i++){'
        $arrayNoir += 'switch ($($c[$i])) {'
        $arrayNoir += 'Entry      {$endOfRecord = $false;[string]$string = $null;[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'RecordName {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'RecordType {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'Status     {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'Section    {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'TimeToLive {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'DataLength {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s}'
        $arrayNoir += 'Data       {[string]$s = [regex]::match($($b[$i]),"(?<=:\s).+").value;$s += ";";$string += $s;$endOfRecord = $true}'
        $arrayNoir += '}'
        $arrayNoir += 'if ($endOfRecord -eq $true) {'
        $arrayNoir += '$stray += $string'
        $arrayNoir += '}'
        $arrayNoir += '}'
        $arrayNoir += '$stray'
        $arrayNoir += '}'
        #icm-end
        
        $arrayNoir += '$returnedContent'
    
        #$arrayNoir += 'pause'
        
        ##  this is useful to remember that it works, but I'm going to remark it out anyway...
        #$arrayNoir += 'if (!(test-path c:\dnsCacheTemp -PathType Container)) {'
        #$arrayNoir += '[void](md c:\dnsCacheTemp)'
        #$arrayNoir += '}'
        
        #$arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        #[string]$string = '$returnedContent | out-file c:\dnsCacheTemp\dnsCache-' + $cn + '-$stamp.txt'
        $string = '$returnedContent | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-dnsCache.txt -force'
        $arrayNoir += $string
        
        #$string = 'start-process notepad c:\dnsCacheTemp\dnsCache-' + $cn + '-$stamp.txt'
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-dnsCache.txt'
        $arrayNoir += $string
    
        $arrayNoir += ''
    
    
        ##########################################################
        # MpThreatDetection
        ##########################################################
    
        # icm begin
        $arrayNoir += '$returnedMpContent = icm -session $noProSession -scriptblock {'
        $arrayNoir += 'c:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'get-mpthreatdetection'
        $arrayNoir += '}#icm'
        # icm end
    
        $arrayNoir += 'if ($null -like $returnedMpContent){'
        $string = 'write-output "No MpThreatDetection content found . . ." | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-mpThreatDetection.txt -force}else{'
        $arrayNoir += $string
        $string = '$returnedMpContent | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-mpThreatDetection.txt -force}'
        $arrayNoir += $string
    
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-mpThreatDetection.txt'
        $arrayNoir += $string
        
        $arrayNoir += ''
    
        ##########################################################
        # MPScanResults
        ##########################################################
    
        #icm begin
        $arrayNoir += '$returnedMpScanContent = icm -session $noProSession -scriptblock {'
        $arrayNoir += 'c:'
        $arrayNoir += 'cd\'
        $arrayNoir += '[string[]]$stray = $null'
        $arrayNoir += '[string]$string = (gwmi win32_computersystem).name'
        $arrayNoir += '$stray += $string'
    
        $arrayNoir += '$string = "FullScanStartTime   : " + (get-mpcomputerstatus).FullScanStartTime'
        $arrayNoir += '$stray += $string'
    
        $arrayNoir += '$string = "FullScanEndTime     : " + (get-mpcomputerstatus).FullScanEndTime'
        $arrayNoir += '$stray += $string'
    
        $arrayNoir += '$string = "QuickScanStartTime  : " + (get-mpcomputerstatus).QuickScanStartTime'
        $arrayNoir += '$stray += $string'
    
        $arrayNoir += '$string = "QuickScanEndTime    : " + (get-mpcomputerstatus).QuickScanEndTime'
        $arrayNoir += '$stray += $string'
    
        $arrayNoir += '$stray'
        $arrayNoir += '}#icm'
        # icm end
    
        $string = '$returnedMpScanContent | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-mpComputerStatus_ScanResults.txt -force'
        $arrayNoir += $string
    
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-mpComputerStatus_ScanResults.txt'
        $arrayNoir += $string
    
        
        $arrayNoir += ''
    
    
        ##########################################################
        # Programs
        ##########################################################
    
        #icm-begin
        $arrayNoir += '$installedData = icm -session $noProSession -scriptblock {'
        
        $string = '$search = ' + "'*'"
        $arrayNoir += $string
        
        $arrayNoir += '$computername = (gwmi win32_computersystem).name'
        $arrayNoir += '$array64 = @()'
        $arrayNoir += '$array32 = @()'
        
        #64-bit search
        $string = '$UninstallKey=' + '"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"' 
        $arrayNoir += $string
    
        $string = '$reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(' + "'LocalMachine'," + '$computername)'
        $arrayNoir += $string
    
        $arrayNoir += '$regkey=$reg.OpenSubKey($UninstallKey)'
        $arrayNoir += '$subkeys=$regkey.GetSubKeyNames()'
    
        $arrayNoir += 'foreach($key in $subkeys){'
        
        $string = '$thisKey=$UninstallKey+' + '"\\"+' + '$key'
        $arrayNoir += $string
        
        $arrayNoir += '$thisSubKey=$reg.OpenSubKey($thisKey)'
        $arrayNoir += '$obj = New-Object PSObject'
        
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $computername'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $($thisSubKey.GetValue("InstallDate"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $($thisSubKey.GetValue("UninstallString"))'
        $arrayNoir += '$array64 += $obj'
        $arrayNoir += '}' 
        
        
        #32-bit search
        $arrayNoir += '$UninstallKey="SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"'
        
        $string = '$reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(' + "'LocalMachine'," + '$computername)'
        $arrayNoir += $string 
        
        $arrayNoir += '$regkey=$reg.OpenSubKey($UninstallKey)'
        $arrayNoir += '$subkeys=$regkey.GetSubKeyNames()'
        $arrayNoir += 'foreach($key in $subkeys){'
    
        $string = '$thisKey=$UninstallKey+' + '"\\"+' + '$key'
        $arrayNoir += $string
        
        $arrayNoir += '$thisSubKey=$reg.OpenSubKey($thisKey)'
        $arrayNoir += '$obj = New-Object PSObject'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $computername'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $($thisSubKey.GetValue("InstallDate"))'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $($thisSubKey.GetValue("UninstallString"))'
        $arrayNoir += '$array32 += $obj'
        $arrayNoir += '}'
    
        #combine results to single array
        $arrayNoir += '$Results = @()'
        
        $arrayNoir += 'foreach ($item in $array64) {'
        $arrayNoir += 'if ($($item.DisplayName) -like $search){'
        $arrayNoir += '$obj = New-Object -TypeName psobject'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $item.ComputerName'
        
        $string = '$obj | Add-Member -MemberType NoteProperty -Name BitVersion -Value ' + "'64-bit'"
        $arrayNoir += $string
    
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $item.DisplayName'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name DisplayVersion -Value $item.DisplayVersion'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name Publisher -Value $item.Publisher'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name InstallDate -Value $item.InstallDate'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $item.UninstallString'
        $arrayNoir += '$Results += $obj'
        $arrayNoir += '}'
        $arrayNoir += '}'
    
    
        $arrayNoir += 'foreach ($item in $array32) {'
        $arrayNoir += 'if ($($item.DisplayName) -like $search){'
        $arrayNoir += '$obj = New-Object -TypeName psobject'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $item.ComputerName'
    
        $string = '$obj | Add-Member -MemberType NoteProperty -Name BitVersion -Value ' + "'32-bit'"
        $arrayNoir += $string
    
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $item.DisplayName'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name DisplayVersion -Value $item.DisplayVersion'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name Publisher -Value $item.Publisher'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name InstallDate -Value $item.InstallDate'
        $arrayNoir += '$obj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $item.UninstallString'
        $arrayNoir += '$Results += $obj'
        $arrayNoir += '}}'
    
        
        #search results
        $arrayNoir += '$installedSearchResults = @()'
        $arrayNoir += 'if ($($Results.count) -lt 1) {'
        $arrayNoir += '[string]$installedSearchResults_string = $($item.ComputerName) + "," + "noResults" + "," + "noResults" + "," + "noResults" + "," + "noResults"'
        $arrayNoir += '$installedSearchResults += $installedSearchResults_string}else {'
        $arrayNoir += 'foreach ($item in $Results ){'
        $arrayNoir += 'if ($($item.DisplayName) -notlike "") {'
        $arrayNoir += '[string]$installedSearchResults_string = $($item.ComputerName) + "," + $($item.InstallDate) + "," + $($item.BitVersion) + "," + $($item.DisplayName) + "," + $($item.DisplayVersion)'
        $arrayNoir += '$installedSearchResults += $installedSearchResults_string'
        $arrayNoir += '}}}'
    
        $arrayNoir += '$installedSearchResults'
        
        $arrayNoir += '}'
        #icm end
        #
    
        $string = '$installedData | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-installedPrograms.txt -force'
        $arrayNoir += $string
    
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-installedPrograms.txt'
        $arrayNoir += $string
        
        $arrayNoir += ''
    
    
        ##########################################################
        # rexRun
        ##########################################################
    
        #icm-begin
        $arrayNoir += '$rexRunData = icm -session $noProSession {'
        
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += 'write-output "** Run32 **"'
        $arrayNoir += 'write-output ""'
    
        # run32 begin
       $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    
        # lss begin
        $arrayNoir += 'write-output "gi ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gi .'
        $arrayNoir += 'write-output "gp ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gp .'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Sub-Keys"'
        $arrayNoir += 'write-output "----------"'
        $arrayNoir += 'write-output ""'
    
        $arrayNoir += '$lsResults = (ls -ErrorAction SilentlyContinue).name'
    
        $arrayNoir += 'foreach ($item in $lsResults) {'
        $arrayNoir += '[string]$itemstring = $item'
        $arrayNoir += '[array]$itemstringarray = $itemstring.split("\")'
        $arrayNoir += '$itemstring = $itemstring.split("\")[$($itemstringarray.count -1)]'
        $arrayNoir += '$itemstring'
        $arrayNoir += '}'
        # lss end
        # run32 end
    
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += 'write-output "** RunOnce32 **"'
        $arrayNoir += 'write-output ""'
        #runonce32 begin
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    
        # lss begin
        $arrayNoir += 'write-output "gi ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gi .'
        $arrayNoir += 'write-output "gp ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gp .'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Sub-Keys"'
        $arrayNoir += 'write-output "----------"'
        $arrayNoir += 'write-output ""'
    
        $arrayNoir += '$lsResults = (ls -ErrorAction SilentlyContinue).name'
    
        $arrayNoir += 'foreach ($item in $lsResults) {'
        $arrayNoir += '[string]$itemstring = $item'
        $arrayNoir += '[array]$itemstringarray = $itemstring.split("\")'
        $arrayNoir += '$itemstring = $itemstring.split("\")[$($itemstringarray.count -1)]'
        $arrayNoir += '$itemstring'
        $arrayNoir += '}'
        # lss end
        # runonce32 end
    
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += 'write-output "** Run64 **"'
        $arrayNoir += 'write-output ""'
        # run64 begin
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:\software\microsoft\windows\currentversion\Run'
    
        # lss begin
        $arrayNoir += 'write-output "gi ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gi .'
        $arrayNoir += 'write-output "gp ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gp .'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Sub-Keys"'
        $arrayNoir += 'write-output "----------"'
        $arrayNoir += 'write-output ""'
    
        $arrayNoir += '$lsResults = (ls -ErrorAction SilentlyContinue).name'
    
        $arrayNoir += 'foreach ($item in $lsResults) {'
        $arrayNoir += '[string]$itemstring = $item'
        $arrayNoir += '[array]$itemstringarray = $itemstring.split("\")'
        $arrayNoir += '$itemstring = $itemstring.split("\")[$($itemstringarray.count -1)]'
        $arrayNoir += '$itemstring'
        $arrayNoir += '}'
        # lss end
        # run64 end
    
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += 'write-output "** RunOnce64 **"'
        $arrayNoir += 'write-output ""'
        # runonce64 begin
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'cd HKLM:\software\microsoft\windows\currentversion\RunOnce'
    
        # lss begin
        $arrayNoir += 'write-output "gi ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gi .'
        $arrayNoir += 'write-output "gp ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gp .'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Sub-Keys"'
        $arrayNoir += 'write-output "----------"'
        $arrayNoir += 'write-output ""'
    
        $arrayNoir += '$lsResults = (ls -ErrorAction SilentlyContinue).name'
    
        $arrayNoir += 'foreach ($item in $lsResults) {'
        $arrayNoir += '[string]$itemstring = $item'
        $arrayNoir += '[array]$itemstringarray = $itemstring.split("\")'
        $arrayNoir += '$itemstring = $itemstring.split("\")[$($itemstringarray.count -1)]'
        $arrayNoir += '$itemstring'
        $arrayNoir += '}'
        # lss end
        # runonce64 end
    
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += 'write-output "** HkuRun64 **"'
        $arrayNoir += 'write-output ""'
        # runhku64 begin
        $arrayNoir += 'new-psdrive -name hku -psprovider registry -root hkey_users'
        $arrayNoir += 'if (!(test-path hku:)) {write-output "hku: not mapped";break}'
        $arrayNoir += '$hkuserArray = @()'
        $arrayNoir += 'cd hku:'
        $arrayNoir += 'cd\'
        $arrayNoir += '$lsuserdump = ls'
        $arrayNoir += '$lsuserdump | % {'
        $arrayNoir += '[string]$hkuser = $_.name'
        $arrayNoir += '$hkuserArray += $hkuser.split("\")[1]'
        $arrayNoir += '}'
    
        #$arrayNoir += '$hkuserArray'
    
        $arrayNoir += '$hkuserArraySid = @()'
        $arrayNoir += '$hkuserArrayUser = @()'
        $arrayNoir += '$hkuserArrayPairs = @()'
    
        $arrayNoir += 'foreach ($item in $hkuserArray) {'
    
        $string = 'if (test-path $item\' + "'Volatile Environment'" + '){'
        $arrayNoir += $string
    
        $string = 'cd $item\' + "'Volatile Environment'"
        $arrayNoir += $string
    
        $arrayNoir += '$username = (gp . |select username).username'
        $arrayNoir += '$hkuserArraySid += $item'
        $arrayNoir += '$hkuserArrayUser += $username'
        $arrayNoir += '$hkuserArrayPairs += "{0,-50}{1}" -f $item, $username'
        $arrayNoir += 'cd\'
        $arrayNoir += '}'
        $arrayNoir += '}'
    
    
        #$arrayNoir += 'write-output "Pairs:"'
        #$arrayNoir += 'write-output "$hkuserArrayPairs"'
    
        # foreach user begin
        $arrayNoir += 'for ($i = 0; $i -lt $($hkuserArrayPairs.count); $i++) {'
        #$arrayNoir += 'test-path "hku:\$($hkuserArraySid[$i])\Software\Microsoft\Windows\CurrentVersion\Run"'
        $arrayNoir += 'write-output "==================================================================="'
        $arrayNoir += '$hkuserArrayUser[$i]'
        $arrayNoir += 'write-output ""'
    
        $arrayNoir += 'write-output "gi ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gi "hku:\$($hkuserArraySid[$i])\Software\Microsoft\Windows\CurrentVersion\Run"'
    
        $arrayNoir += 'write-output "gp ."'
        $arrayNoir += 'write-output "---------------------------------------------------------"'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'gp "hku:\$($hkuserArraySid[$i])\Software\Microsoft\Windows\CurrentVersion\Run"'
        
        $arrayNoir += '}'
        # foreach user end
        # runhku64 end
    
        $arrayNoir += '}'
        #icm end
    
        $string = '$rexRunData | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-rexRunReport.txt -force'
        $arrayNoir += $string
    
        $string = 'start-process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-rexRunReport.txt'
        $arrayNoir += $string
        $arrayNoir += ''
    
        ##########################################################
        # historyPull_Edge
        ##########################################################
        #
        #icm begin
        $arrayNoir += '[string]$history_stamp_returned = icm -session $noProSession {'
        [string]$string = '$' + 'user = ' + "'" + $user + "'"
        $arrayNoir += $string
        $arrayNoir += '$cn = (gwmi win32_computersystem).name'
        $arrayNoir += 'c:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'if (test-path -PathType Leaf "c:\users\$user\appdata\local\microsoft\edge\user data\default\history") {'
        $arrayNoir += '$history_info = ls "c:\users\$user\appdata\local\microsoft\edge\user data\default\history" | select *'
        $arrayNoir += '[string]$history_stamp = "history_" + $cn +"_" + $user + "_" + $(get-date -date $($history_info.CreationTime) -UFormat "%Y-%m%d-%H%M-%S00") + "_" + $(get-date -date $($history_info.LastWriteTime) -UFormat "%Y-%m%d-%H%M-%S00")'
        $arrayNoir += 'cp "c:\users\$user\appdata\local\microsoft\edge\user data\default\history" c:\ -force'
        $arrayNoir += 'rename-item c:\history $history_stamp' 
        $arrayNoir += '$history_stamp'
        $arrayNoir += '}else {write-output "-notFound-"}}#icm'
        $arrayNoir += 'if ($history_stamp_returned -eq "-notFound-") {'
        $arrayNoir += '$history_stamp_returned'
        $arrayNoir += 'write-output ""}elseif ($history_stamp_returned -match "^history") {'
        $arrayNoir += '$filepath = "c:\$history_stamp_returned"'
        $arrayNoir += 'cp -FromSession $noProSession -Path $filepath -Recurse -Verbose -Force -Destination c:\'
        $arrayNoir += 'icm -session $noProSession -ArgumentList $history_stamp_returned {'
        $arrayNoir += '$history_file = $args[0]'
        $arrayNoir += 'if (test-path -PathType leaf c:\$history_file) {'
        $arrayNoir += 'ri c:\$history_file -Verbose -Force'
        $arrayNoir += '}'
        $arrayNoir += '}'
        #icm end
        
        $arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        $arrayNoir += '[string]$history_stamp_returned_now = $history_stamp_returned + "_" + $stamp'
        $arrayNoir += 'rename-item c:\$history_stamp_returned $history_stamp_returned_now -force'
        $arrayNoir += 'ls c:\$history_stamp_returned_now'
        $arrayNoir += '}else {write-output "a kaboom occured . . ."'
        $arrayNoir += '}'
        #sqlite
        $arrayNoir += 'if (test-path -PathType Leaf c:\$history_stamp_returned_now) {'
        $arrayNoir += '$path = "c:\$history_stamp_returned_now"'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Path to HISTORY file not found . . ."'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'break'
        $arrayNoir += '}'
        $arrayNoir += '$commands = @('
        $arrayNoir += "'.output history.txt'," #double quotes
        
        [string]$string = '"SELECT datetime(last_visit_time/1000000 - 11644473600,' + "'" + 'unixepoch' + "'" + ',' + "'" + 'localtime' + "'" + '), urls.url FROM urls;"'
        $arrayNoir += $string
        $arrayNoir += "'.quit'"
        $arrayNoir += ')'                  
                                    
        $arrayNoir += 'if (test-path -PathType Leaf C:\sqlite3.exe) {' 
        $arrayNoir += '$commands | c:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf D:\sqlite3.exe) {' 
        $arrayNoir += '$commands | d:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf E:\sqlite3.exe) {'
        $arrayNoir += '$commands | e:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf F:\sqlite3.exe) {' 
        $arrayNoir += '$commands | f:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf G:\sqlite3.exe) {'
        $arrayNoir += '$commands | g:\sqlite3.exe $path'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output "sqlite3.exe not found on C: D: E: F: G: "'
        $arrayNoir += 'break'
        $arrayNoir += '}' 
    
        $arrayNoir += '$history = gc .\history.txt'
        $arrayNoir += '$historySorted = $history | sort'
        $arrayNoir += 'ri .\history.txt -force'
        
        $arrayNoir += '[string]$created = $history_stamp_returned_now.split("_")[3]' 
        #$arrayNoir += 'write-output "Created   :  $created" | out-file "c:\Edge-$history_stamp_returned_now.txt"'
        $string = 'write-output "Created   :  $created" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt -force'
        $arrayNoir += $string
    
        $arrayNoir += '[string]$lastwrite = $history_stamp_returned_now.split("_")[4]' 
        $string = 'write-output "LastWrite :  $lastwrite" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "LastWrite :  $lastwrite" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
        $arrayNoir += '[string]$copied = $history_stamp_returned_now.split("_")[5]' 
        $string = 'write-output "Copied    :  $copied" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "Copied    :  $copied" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
    
    
    
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
        
        $string = '$historySorted | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += '$historySorted | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
        $string = 'Start-Process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory.txt'
        $arrayNoir += $string
        #$arrayNoir += 'Start-Process notepad "c:\Edge-$history_stamp_returned_now.txt"'
    
    
        #$path still valid
        $string = '$commandsDL = @(' +
            "'.output historyDL.txt'," +
            '"SELECT ' +
            "datetime(start_time/1000000 - 11644473600,'unixepoch','localtime')," +
            "datetime(end_time/1000000 - 11644473600,'unixepoch','localtime')," + 
            "datetime(last_access_time/1000000 - 11644473600,'unixepoch','localtime')," +
            "downloads.target_path, downloads.referrer, downloads.tab_url FROM downloads" +
            ';",' +
            "'.quit'" +
        ")"                  
        
        
        $arrayNoir += $string
            
        $arrayNoir += 'if (test-path -PathType Leaf C:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | c:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf D:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | d:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf E:\sqlite3.exe) {'
        $arrayNoir += '$commandsDL | e:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf F:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | f:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf G:\sqlite3.exe) {'
        $arrayNoir += '$commandsDL | g:\sqlite3.exe $path'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output "sqlite3.exe not found on C: D: E: F: G: "'
        $arrayNoir += 'break'
        $arrayNoir += '}'     
        
        
        $arrayNoir += '$history = gc .\historyDL.txt'
        $arrayNoir += '[string[]]$historySorted = $history | sort'
        $arrayNoir += 'ri .\historyDL.txt -force'
        $arrayNoir += '$historySorted = $historySorted.split("|")'
        $arrayNoir += '[string[]]$historySorted2 = $null'
    
        $arrayNoir += 'for($i=0; $i -lt $($historySorted.count);$i++) {'
        
        $string = 'if (($historySorted[$i] -match  ' + "'^\d{4}-')" + ' -and ($historySorted[$i + 1] -match  ' + "'^\d{4}-')" + ' -and ($historySorted[$i + 2] -match ' + "'^\d{4}-')) {"
        $arrayNoir += $string
    
        $string = '[string]$string = ' + "'StartTime: '" + ' + $($historySorted[$i])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
    
        $string = '[string]$string = ' + "'EndTime: '" + ' + $($historySorted[$i + 1])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
    
        $string = '[string]$string = ' + "'LastAccessTime: '" + ' + $($historySorted[$i + 2])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'TargetPath: '" + ' + $($historySorted[$i + 3])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'Referrer: '" + ' + $($historySorted[$i + 4])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'TabUrl: '" + ' + $($historySorted[$i + 5])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
        $arrayNoir += '$historySorted2 += "----------------------------------------------------"'
        $arrayNoir += '$historySorted2 += ""'
        $arrayNoir += '$i = $i + 5'
        $arrayNoir += '}'
        $arrayNoir += '}'
        
        $string = '$historySorted2 | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory_download.txt'
        $arrayNoir += $string
    
        $string = 'Start-Process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-edgeHistory_download.txt'
        $arrayNoir += $string    
    
    
    
        $arrayNoir += 'if (test-path -PathType Leaf c:\$history_stamp_returned_now) {ri c:\$history_stamp_returned_now -force}'
    
        $arrayNoir += ''
    
        
    
        ##########################################################
        # historyPull_Chrome
        ##########################################################
        #
        #icm begin
        $arrayNoir += '[string]$history_stamp_returned = icm -session $noProSession {'
        [string]$string = '$' + 'user = ' + "'" + $user + "'"
        $arrayNoir += $string
        $arrayNoir += '$cn = (gwmi win32_computersystem).name'
        $arrayNoir += 'c:'
        $arrayNoir += 'cd\'
        $arrayNoir += 'if (test-path -PathType Leaf "c:\users\$user\appdata\local\google\chrome\user data\default\history") {'
        $arrayNoir += '$history_info = ls "c:\users\$user\appdata\local\google\chrome\user data\default\history" | select *'
        $arrayNoir += '[string]$history_stamp = "history_" + $cn +"_" + $user + "_" + $(get-date -date $($history_info.CreationTime) -UFormat "%Y-%m%d-%H%M-%S00") + "_" + $(get-date -date $($history_info.LastWriteTime) -UFormat "%Y-%m%d-%H%M-%S00")'
        $arrayNoir += 'cp "c:\users\$user\appdata\local\google\chrome\user data\default\history" c:\ -force'
        $arrayNoir += 'rename-item c:\history $history_stamp' 
        $arrayNoir += '$history_stamp'
        $arrayNoir += '}else {write-output "-notFound-"}}#icm'
        $arrayNoir += 'if ($history_stamp_returned -eq "-notFound-") {'
        $arrayNoir += '$history_stamp_returned'
        $arrayNoir += 'write-output ""}elseif ($history_stamp_returned -match "^history") {'
        $arrayNoir += '$filepath = "c:\$history_stamp_returned"'
        $arrayNoir += 'cp -FromSession $noProSession -Path $filepath -Recurse -Verbose -Force -Destination c:\'
        $arrayNoir += 'icm -session $noProSession -ArgumentList $history_stamp_returned {'
        $arrayNoir += '$history_file = $args[0]'
        $arrayNoir += 'if (test-path -PathType leaf c:\$history_file) {'
        $arrayNoir += 'ri c:\$history_file -Verbose -Force'
        $arrayNoir += '}'
        $arrayNoir += '}'
        #icm end
        
        $arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        $arrayNoir += '[string]$history_stamp_returned_now = $history_stamp_returned + "_" + $stamp'
        $arrayNoir += 'rename-item c:\$history_stamp_returned $history_stamp_returned_now -force'
        $arrayNoir += 'ls c:\$history_stamp_returned_now'
        $arrayNoir += '}else {write-output "a kaboom occured . . ."'
        $arrayNoir += '}'
        #sqlite
        $arrayNoir += 'if (test-path -PathType Leaf c:\$history_stamp_returned_now) {'
        $arrayNoir += '$path = "c:\$history_stamp_returned_now"'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'write-output "Path to HISTORY file not found . . ."'
        $arrayNoir += 'write-output ""'
        $arrayNoir += 'break'
        $arrayNoir += '}'
        $arrayNoir += '$commands = @('
        $arrayNoir += "'.output history.txt'," #double quotes
        
        [string]$string = '"SELECT datetime(last_visit_time/1000000 - 11644473600,' + "'" + 'unixepoch' + "'" + ',' + "'" + 'localtime' + "'" + '), urls.url FROM urls;"'
        $arrayNoir += $string
        $arrayNoir += "'.quit'"
        $arrayNoir += ')'                  
                                    
        $arrayNoir += 'if (test-path -PathType Leaf C:\sqlite3.exe) {' 
        $arrayNoir += '$commands | c:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf D:\sqlite3.exe) {' 
        $arrayNoir += '$commands | d:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf E:\sqlite3.exe) {'
        $arrayNoir += '$commands | e:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf F:\sqlite3.exe) {' 
        $arrayNoir += '$commands | f:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf G:\sqlite3.exe) {'
        $arrayNoir += '$commands | g:\sqlite3.exe $path'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output "sqlite3.exe not found on C: D: E: F: G: "'
        $arrayNoir += 'break'
        $arrayNoir += '}' 
    
        $arrayNoir += '$history = gc .\history.txt'
        $arrayNoir += '$historySorted = $history | sort'
        $arrayNoir += 'ri .\history.txt -force'
        
        $arrayNoir += '[string]$created = $history_stamp_returned_now.split("_")[3]' 
        #$arrayNoir += 'write-output "Created   :  $created" | out-file "c:\Edge-$history_stamp_returned_now.txt"'
        $string = 'write-output "Created   :  $created" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt -force'
        $arrayNoir += $string
    
        $arrayNoir += '[string]$lastwrite = $history_stamp_returned_now.split("_")[4]' 
        $string = 'write-output "LastWrite :  $lastwrite" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "LastWrite :  $lastwrite" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
        $arrayNoir += '[string]$copied = $history_stamp_returned_now.split("_")[5]' 
        $string = 'write-output "Copied    :  $copied" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "Copied    :  $copied" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
        
        $string = '$historySorted | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt -append'
        $arrayNoir += $string
        #$arrayNoir += '$historySorted | out-file "c:\Edge-$history_stamp_returned_now.txt" -append'
    
        $string = 'Start-Process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory.txt'
        $arrayNoir += $string
        #$arrayNoir += 'Start-Process notepad "c:\Edge-$history_stamp_returned_now.txt"'
    
        #$path still valid
        $string = '$commandsDL = @(' +
            "'.output historyDL.txt'," +
            '"SELECT ' +
            "datetime(start_time/1000000 - 11644473600,'unixepoch','localtime')," +
            "datetime(end_time/1000000 - 11644473600,'unixepoch','localtime')," + 
            "datetime(last_access_time/1000000 - 11644473600,'unixepoch','localtime')," +
            "downloads.target_path, downloads.referrer, downloads.tab_url FROM downloads" +
            ';",' +
            "'.quit'" +
        ")"                  
        
        
        $arrayNoir += $string
            
        $arrayNoir += 'if (test-path -PathType Leaf C:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | c:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf D:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | d:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf E:\sqlite3.exe) {'
        $arrayNoir += '$commandsDL | e:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf F:\sqlite3.exe) {' 
        $arrayNoir += '$commandsDL | f:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf G:\sqlite3.exe) {'
        $arrayNoir += '$commandsDL | g:\sqlite3.exe $path'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output "sqlite3.exe not found on C: D: E: F: G: "'
        $arrayNoir += 'break'
        $arrayNoir += '}'     
        
        
        $arrayNoir += '$history = gc .\historyDL.txt'
        $arrayNoir += '[string[]]$historySorted = $history | sort'
        $arrayNoir += 'ri .\historyDL.txt -force'
        $arrayNoir += '$historySorted = $historySorted.split("|")'
        $arrayNoir += '[string[]]$historySorted2 = $null'
    
        $arrayNoir += 'for($i=0; $i -lt $($historySorted.count);$i++) {'
        
        $string = 'if (($historySorted[$i] -match  ' + "'^\d{4}-')" + ' -and ($historySorted[$i + 1] -match  ' + "'^\d{4}-')" + ' -and ($historySorted[$i + 2] -match ' + "'^\d{4}-')) {"
        $arrayNoir += $string
    
        $string = '[string]$string = ' + "'StartTime: '" + ' + $($historySorted[$i])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
    
        $string = '[string]$string = ' + "'EndTime: '" + ' + $($historySorted[$i + 1])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
    
        $string = '[string]$string = ' + "'LastAccessTime: '" + ' + $($historySorted[$i + 2])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'TargetPath: '" + ' + $($historySorted[$i + 3])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'Referrer: '" + ' + $($historySorted[$i + 4])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
    
        $string = '[string]$string = ' + "'TabUrl: '" + ' + $($historySorted[$i + 5])'
        $arrayNoir += $string
        $arrayNoir += '$historySorted2 += $string'
        $arrayNoir += '$historySorted2 += ""'
        $arrayNoir += '$historySorted2 += "----------------------------------------------------"'
        $arrayNoir += '$historySorted2 += ""'
        $arrayNoir += '$i = $i + 5'
        $arrayNoir += '}'
        $arrayNoir += '}'
        
        $string = '$historySorted2 | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory_download.txt'
        $arrayNoir += $string
    
        $string = 'Start-Process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-chromeHistory_download.txt'
        $arrayNoir += $string   
        
    
        $arrayNoir += 'if (test-path -PathType Leaf c:\$history_stamp_returned_now) {ri c:\$history_stamp_returned_now -force}'
    
        $arrayNoir += ''
    
    
    
        ##########################################################
        # historyPull_Firefox
        ##########################################################
        #
        #icm begin
        #declare array for a return
        $arrayNoir += '[string[]]$history_stamp_returned = icm -session $noProSession {'
        [string]$string = '$' + 'user = ' + "'" + $user + "'"
        $arrayNoir += $string
        $arrayNoir += '$cn = (gwmi win32_computersystem).name'
        $arrayNoir += 'c:'
        $arrayNoir += 'cd\'
        #if
        $arrayNoir += 'if (test-path -PathType Container c:\users\$user\appdata\roaming\mozilla\firefox\profiles) {'
        $arrayNoir += 'cd c:\users\$user\appdata\roaming\mozilla\firefox\profiles'
        $arrayNoir += '$FirefoxRoamingProfileFolders = (ls .\).Name'
        $arrayNoir += '$placesSqlite_found = $false'
        $arrayNoir += '[string[]]$history_stamp_array = $null'
        $arrayNoir += 'foreach ($item in $FirefoxRoamingProfileFolders) {'
        $arrayNoir += 'if (test-path -PathType Leaf "c:\users\$user\appdata\roaming\mozilla\firefox\profiles\$item\places.sqlite") {'
        $arrayNoir += '$placesSqlite_found = $true'
        $arrayNoir += '$history_info = ls "c:\users\$user\appdata\roaming\mozilla\firefox\profiles\$item\places.sqlite" | select *'
        $arrayNoir += '[string]$history_stamp = "placesSqlite_" + $cn +"_" + $user + "_" + $(get-date -date $($history_info.CreationTime) -UFormat "%Y-%m%d-%H%M-%S00") + "_" + $(get-date -date $($history_info.LastWriteTime) -UFormat "%Y-%m%d-%H%M-%S00")'
        $arrayNoir += 'cp  c:\users\$user\appdata\roaming\mozilla\firefox\profiles\$item\places.sqlite c:\ -force'
        $arrayNoir += 'rename-item c:\places.sqlite $history_stamp -force' # debug
        $arrayNoir += '$history_stamp_array += $history_stamp}}'
        $arrayNoir += 'if ($placesSqlite_found -eq $false) {write-output "-notFound-"} else {$history_stamp_array}}else {write-output "-notFound-"}}'
        #icm end
        
        #
    
        #if begin
        $arrayNoir += 'if ($($history_stamp_returned[0]) -eq "-notFound-") {$($history_stamp_returned[0]);break}'
        $arrayNoir += 'if ($($history_stamp_returned[0]) -match "^placesSqlite") {'
        # array to pack
        $arrayNoir += '[string[]]$history_item_now_array = $null'
        # foreach loop begin
        $arrayNoir += 'foreach ($history_item in $history_stamp_returned) {'
        $arrayNoir += '[string]$filepath = "c:\$history_item"'
        #  session cp,  add 'now' timestamp
        $arrayNoir += 'cp -FromSession $noProSession -Path $filepath -Recurse -Verbose -Force -Destination c:\'
        $arrayNoir += '$stamp = get-date -uFormat "%Y-%m%d-%H%M-%S00"'
        $arrayNoir += '[string]$history_item_now = $history_item + "_" + $stamp'
        $arrayNoir += 'rename-item c:\$history_item $history_item_now -force'
        $arrayNoir += '$history_item_now_array += $history_item_now'
        $arrayNoir += '}'
        # foreach loop end
        $arrayNoir += '}'
        #if end
    
        #icm begin
        # remove remote files
        $arrayNoir += 'icm -session $noProSession -ArgumentList (,$history_stamp_returned) {'
        $arrayNoir += '[string[]]$history_file_array = $args[0]'
        $arrayNoir += 'foreach ($history_file_item in $history_file_array) {'
        $arrayNoir += 'if (test-path -PathType leaf c:\$history_file_item) {'
        $arrayNoir += 'ri c:\$history_file_item -Verbose -Force }}}'
        #icm end
    
        #sqlite syntax
        $arrayNoir += '$commands = @('
        $arrayNoir += "'.output history.txt',"
        $string = '"SELECT datetime(moz_historyvisits.visit_date/1000000,' + "'unixepoch','localtime'), moz_places.url" 
        $arrayNoir += $string
        $string = 'FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;",'
        $arrayNoir += $string
        $arrayNoir += "'.quit'"
        $arrayNoir += ')'
        #for loop begin
        $arrayNoir += 'for ($i = 0; $i -lt $($history_item_now_array.count); $i++) {'
        # if begin
        $arrayNoir += 'if (test-path -PathType Leaf c:\$($history_item_now_array[$i])) {'
        $arrayNoir += '[string]$string = $($history_item_now_array[$i])'
        $arrayNoir += '[string]$path = "c:\$string"'
        #  nested if begin
        $arrayNoir += 'if (test-path -PathType Leaf C:\sqlite3.exe) {'
        $arrayNoir += '$commands | c:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf D:\sqlite3.exe) {' 
        $arrayNoir += '$commands | d:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf E:\sqlite3.exe) {'
        $arrayNoir += '$commands | e:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf F:\sqlite3.exe) {' 
        $arrayNoir += '$commands | f:\sqlite3.exe $path'
        $arrayNoir += '}elseif (test-path -PathType Leaf G:\sqlite3.exe) {'
        $arrayNoir += '$commands | g:\sqlite3.exe $path'
        $arrayNoir += '}else {'
        $arrayNoir += 'write-output "sqlite3.exe not found on C: D: E: F: G: "'
        $arrayNoir += 'break'
        $arrayNoir += '}' 
        #  nested if end
    
        $arrayNoir += '$history = gc c:\history.txt'
        $arrayNoir += '$historySorted = $history | sort'
        $arrayNoir += 'ri c:\history.txt -force'
        #  write header
        
        # need to get creative here, as my code is too deeply nested to modifiy it to work in a 'global' way..
        # going to hack out the 'last write' timestamp from '$string', and use that as part of the global naming convention I'll use in this function
        
        $arrayNoir += '[string]$lastwrite = $($string.split("_")[4])' # this is only to id each file, seperately
    
        $arrayNoir += '[string]$created = $($string.split("_")[3])'
        
        $string = 'write-output "Created   :  $created" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt -force'
        $arrayNoir += $string
        #$arrayNoir += '[string]$created = $($string.split("_")[3])'
        #$arrayNoir += 'write-output "Created   :  $created" | out-file "c:\Firefox-$string.txt"'
        
        $arrayNoir += '[string]$lastwrite = $($string.split("_")[4])' 
        
        $string = 'write-output "LastWrite :  $lastwrite" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "LastWrite :  $lastwrite" | out-file "c:\Firefox-$string.txt" -append'
        
        $arrayNoir += '[string]$copied = $($string.split("_")[5])' 
        
        $string = 'write-output "Copied    :  $copied" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "Copied    :  $copied" | out-file "c:\Firefox-$string.txt" -append'
        
        $string = 'write-output "" | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt -append'
        $arrayNoir += $string
        #$arrayNoir += 'write-output "" | out-file "c:\Firefox-$string.txt" -append'
        
        #  write content
        $string = '$historySorted | out-file c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt -append'
        $arrayNoir += $string
        #$arrayNoir += '$historySorted | out-file "c:\Firefox-$string.txt" -append'
    
        $string = 'Start-Process notepad c:\getInfo-' + $globalStamp + '-' + $cn + '-' + $user + '-firefoxHistory-$lastwrite.txt'
        $arrayNoir += $string
        #$arrayNoir += 'Start-Process notepad "c:\Firefox-$string.txt"'
        
        $arrayNoir += '}'   
        # if end
        # !if
        $arrayNoir += 'if (!(test-path -PathType Leaf "c:\$($history_item_now_array[$i])")) {write-output "Path to HISTORY file not found . . ."}'
        $arrayNoir += '}'
        #for loop end
    
        $arrayNoir += 'foreach ($history_item in $history_stamp_returned) {[string]$filepath = "c:\$history_item*";ri $filepath -force}'
    
        $arrayNoir += ''
        
    
    
        $arrayNoir | Set-Clipboard
        write-output ""
        write-output " -set"
        write-output ""
    
    } 
    
    