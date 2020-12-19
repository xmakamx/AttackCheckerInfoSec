##########################################################################################
#
#  MittreAttackCheckerInfoSecPSSecuritySysMon.ps1
#  version 2.1
#  Written on: 02/02/2020 - Finished on 01/07/2020
#  In honor to Black Hills Information Security Attack Tactics
#  Techniques from: 'https://attack.mitre.org/'
#  Disclaimer: You will be notified if configured ok, but the thread will not be stopped!
#
# 	Test-Environment HTML Report (Local Storage C:\Logs\) DURATION:   00:00:11.4832781
# 	Test-Environment Network Share CSV Storing DURATION:   00:00:31.5361025
#
#	Network output can cause extensive 
#
# 	Run This Script As Admin!
# 
# - Mittre Attack Framework List
# - Network output folder
# - IP Detection if user is at work
# - Internal and external HTML mail reports (depending if at work or not: ip filters)
# - Local HTML Report
# - Automated install of Sysmon
# - Automated scheduled task creation
# - History on Task Scheduler enabled
# - Active user detection
# - Severity classes (possibly needs adjustments)
# - Event logs: Powershell, Security and Sysmon
# - Summary of results 
# - Console version available
# 			 
##########################################################################################

# Mittre Attack Framework List: (list is not completely processed due to implementation issues - missing approx: 3) 
# T1156,T1134,T1134,T1015,T1015,T1087,T1098,T1098,T1182,T1182,T1103,T1103,T1155,T1155,T1017,T1138,T1138,T1010,T1123,T1131,T1119,T1020,T1197,T1197,T1139,T1009,T1067,T1217,T1176,T1110,T1088,T1088,T1191,T1191,T1042,T1146,T1115,T1116,T1059,T1043,T1092,T1500,T1223,T1223,T1109,T1109,T1122,T1122,T1090,T1196,T1196,T1136,T1003,T1081,T1214,T1094,T1024,T1207,T1038,T1038,T1038,T1073,T1002,T1485,T1132,T1022,T1486,T1001,T1074,T1030,T1213,T1005,T1039,T1025,T1491,T1140,T1089,T1488,T1487,T1175,T1172,T1483,T1482,T1189,T1157,T1157,T1173,T1114,T1499,T1480,T1106,T1129,T1048,T1041,T1011,T1052,T1190,T1203,T1212,T1211,T1068,T1210,T1133,T1133,T1181,T1181,T1008,T1107,T1222,T1006,T1044,T1044,T1083,T1495,T1187,T1144,T1061,T1484,T1148,T1200,T1158,T1158,T1147,T1143,T1179,T1179,T1179,T1062,T1183,T1183,T1183,T1054,T1066,T1070,T1202,T1490,T1056,T1056,T1141,T1130,T1118,T1118,T1208,T1215,T1142,T1161,T1149,T1171,T1177,T1177,T1159,T1160,T1160,T1152,T1152,T1152,T1168,T1168,T1162,T1037,T1037,T1185,T1036,T1031,T1112,T1170,T1170,T1104,T1188,T1026,T1079,T1096,T1128,T1498,T1046,T1126,T1135,T1040,T1040,T1050,T1050,T1027,T1137,T1075,T1097,T1174,T1201,T1034,T1034,T1120,T1069,T1150,T1150,T1150,T1205,T1205,T1205,T1013,T1013,T1086,T1145,T1057,T1186,T1093,T1055,T1055,T1012,T1163,T1164,T1108,T1108,T1060,T1121,T1121,T1117,T1117,T1219,T1076,T1105,T1105,T1021,T1018,T1091,T1091,T1496,T1014,T1085,T1085,T1494,T1178,T1198,T1198,T1184,T1053,T1053,T1053,T1029,T1113,T1180,T1064,T1064,T1063,T1101,T1167,T1035,T1058,T1058,T1489,T1166,T1166,T1051,T1023,T1218,T1218,T1216,T1216,T1045,T1153,T1151,T1151,T1193,T1192,T1194,T1071,T1032,T1095,T1165,T1165,T1492,T1169,T1206,T1195,T1019,T1082,T1016,T1049,T1033,T1007,T1124,T1501,T1080,T1221,T1072,T1072,T1209,T1099,T1493,T1154,T1154,T1127,T1127,T1199,T1111,T1065,T1204,T1078,T1078,T1078,T1078,T1125,T1497,T1497,T1102,T1102,T1100,T1100,T1077,T1047,T1084,T1028,T1028,T1004,T1220,T1220


################## Variables:
################## If LogDate is adjusted, be sure to adjust the Scheduled Task Setup (keep room for duration)
################## Search for Scheduled Task Setup (Default is 1 minute), search for: Setting Up Scheduled Task
################## code to look for: # Adjust ToDo 
################## Want to contribute? Please have a look at the mentioned code (by searching for): # Review ! 
################## Thank you in advance! 

	# Event Log Retention (in combination with Scheduled Task) 
	
	$EventData = (Get-Date).AddMinutes(-2)
	
	# File Formats 
	
		$Time = (Get-Date).ToUniversalTime()
		[string]$Hostname = $ENV:COMPUTERNAME
		[string]$StartTime = $Time|Get-Date -uformat  %Y%m%d_%H%M%S
		[string]$FileNameCSV = $StartTime + '_' + $Hostname + '.csv'		

	# Export Locations 
	
		# ATTENTION! Service Account, no member of Domain Users 
		# (Create a new group and set as Default in AD) and linked to a Single Share on SQL Server only! 
	
	# Yes/?
	$UseNetWorkShare = "Yes"
	if ($UseNetWorkShare -eq "Yes") {
		
		$Server = "\\ZAKELIJK\"
		$Share = "WEB\secure\mittreattack"
		$UseShare = (Join-Path $Server $Share)
		net use $UseShare /user:makam 'MyN@SM@kam1978!'
		
		$CSVExport = "Yes"		
		$CSVReportFile = (Join-Path $UseShare $FileNameCSV)
		
		write-host "Refer to this link to import in SQL: 'https://gallery.technet.microsoft.com/scriptcenter/How-to-use-SQL-Server-0e32b08d'" -ForegroundColor yellow
		write-host "::::: - OK - ::::: Network share is setup" -ForegroundColor green
		}
	else 
		{
		write-host "::::: - ?? - ::::: Network share is not setup" -ForegroundColor yellow
		}


	# Get Active User
		function Get-TSSessions {
			param(
				$ComputerName = "localhost"
			)
		
			query user /server:$ComputerName |
			ForEach-Object {
				$_ = $_.trim() 
				$_ = $_.insert(22,",").insert(42,",").insert(47,",").insert(56,",").insert(68,",")
				$_ = $_ -replace "\s\s+",""
				$_
			} |
			ConvertFrom-Csv
		}
		foreach ($user in GET-TSSessions)
		{
			if($user.state -eq "Active")
			{
				$username = $user.USERNAME
				write-host "::::: - OK - ::::: User $username is currently active." -ForegroundColor green
			}
		}
	# End get Active User		


	# Network Detection
	
		# WorkIP ISP1 IPS2
		$WorkIP1 = "85.144.74.59"
		$WorkIP2 = "X.X.X.X"

# Mail Variables

	# Internal Mail Setup
	
	# If Client & Server does not have the same TLS Certificate and the client is not domain joined: credentials are needed:
	# Adjust Internal Mail Server at bottom of file, look for: # Adjust ToDo 
	$DomainJoinedAndCA = "No"
	$smtppass = '--' | ConvertTo-SecureString -AsPlainText -Force
	$smtpname = "administrator@home.local"
	$smtpcred = New-Object System.Management.Automation.PSCredential($smtpname,$smtppass)
	
		$InternalMailReport = "Yes"
		$DetectIfOnPremise = "Yes"

		$Subject = "Compromised System $env:computername with user $username"
		$sendFrom = "makamminga@gmail.com"
		$sendTo = "makamminga@gmail.com"

	# External Mail Setup
		$ExternalMailReport = "Yes"
		$DetectIfOnTheRoad = "Yes"
		# Outlook not supported for HTML Inline Attachement! 
		$EmailTo = "makamminga@gmail.com"
		$EmailFrom = "makamminga@gmail.com"
		$Subject = "Compromised System $env:computername with user $username" 
		$SMTPServer = "smtp.gmail.com" 
		$GmailUsername = "makamminga@gmail.com"
		$GmailAppPassword = ""

	# IP Detection 
		$HostAddress = "www.google.nl"
		$extip=Invoke-WebRequest -URI http://myip.dnsomatic.com/
		write-host "::::: - OK - ::::: External IP: $extip" -ForegroundColor green 
		
function CanPing {  
   $error.clear()  
   $tmp = test-connection $HostAddress -erroraction SilentlyContinue  

   if (!$?)   
       {write-host "::::: - ?? - ::::: Ping failed: $HostAddress."; return $false}  
   else  
   {
   write-host "::::: - OK - ::::: Ping Succesfull, checking if user is at work" -ForegroundColor green
   }

   if (("$extip" -eq "$WorkIP1") -or ("$extip" -eq "$WorkIP2")) {
		$global:AtWork = "$True"
		write-host "::::: - OK - ::::: Internal Network" -ForegroundColor green
		write-host "::::: - OK - ::::: Ping succeeded: $HostAddress" -ForegroundColor green; return $true
		}
	else 
	{
		$global:AtWork = "$False"
		write-host "::::: - OK - ::::: Detected External Network - Not at work!" -ForegroundColor yellow
	}
}
CanPing ($HostAddress)


	# Output folder HTML 
		$OutPutFolder = "C:\Logs\MittreAttackCheckerInfoSecPSSecuritySysMon"
		
			if (!(Test-Path $OutPutFolder)) {
			
					New-Item $OutPutFolder -itemtype directory 
			}
			else 
			{ 
					write-host "::::: - OK - ::::: Log Output folder has been setup" -ForegroundColor green 
			}
	
	# HTML Report True or False?
		$HTMLReport = $True
		

################## End Variables:
################## If LogDate is adjusted, be sure to adjust the Scheduled Task Setup (keep room for duration)
################## Search for Scheduled Task Setup (Default is 1 minute), search for: Setting Up Scheduled Task
################## code to look for: # Adjust ToDo 
################## Want to contribute? Please have a look at the mentioned code (by searching for): # Review ! 
################## Thank you in advance! 


 

	# Create filename for HTMLReport
	
	if ($HTMLReport) {
				[string]$Hostname = $ENV:COMPUTERNAME
				[string]$FileName = $StartTime + '_' + $Hostname + '.html'

		$HTMLReportFile = (Join-Path $OutPutFolder $FileName)

	# Delete all Files in $OutPutFolder older than 3 day(s)
		$Daysback = "-3"
		$CurrentDate = Get-Date
		$DatetoDelete = $CurrentDate.AddDays($Daysback)
		Get-ChildItem $OutPutFolder | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item

	# Header for HTML table formatting

        $HTMLReportHeader = @"
		<style>
		TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
		TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
		TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;font-family:courier;}
		H1 {color:red;}
		H2 {color:blue;}
		H3 {color:green;}
		</style>
		<style>
		.aLine {
			border-top:1px solid #6495ED};
			height:1px;
			margin:16px 0;
			}
		</style>
		<title>Threat Report</title>
"@

	# Attempt to write out HTML report header and exit if there isn't sufficient permission
        Try {
            ConvertTo-HTML -Title "Threat Report" -Head $HTMLReportHeader `
                -Body "<H1>Threat Report for $($Env:ComputerName) - $($username)</H1>`n<div class='aLine'></div>" `
                | Out-File $HTMLReportFile -ErrorAction Stop
            }
        Catch {
            "`n[-] Error writing enumeration output to disk! Check your permissions on $PWD.`n$($Error[0])`n"; Return
        }
}
	
	if($HTMLReport) {
                ConvertTo-HTML -Fragment -Pre "<H2>Threat Detection Report Overview</H2>" | Out-File -Append $HtmlReportFile
					}

	# SysMon Setup Check 

			$SysMonLog = Get-WinEvent -ListLog *Sysmon* -EA silentlycontinue
		if ($SysMonLog.LogName -eq "Microsoft-Windows-Sysmon/Operational")  { 
				write-host "::::: - OK - ::::: SysMon Enabled: continuing..." -ForegroundColor green 
		}
		else
		{
			write-host "Downloading SysMon" -foregroundcolor green
					$clientdlsysmon = new-object System.Net.WebClient
					$clientdlsysmon.DownloadFile("https://download.sysinternals.com/files/Sysmon.zip","$PWD\Sysmon.zip")
			timeout /T 3
			
	#Unzip the file
			
			Add-Type -AssemblyName System.IO.Compression.FileSystem
			function Unzip	{
					param([string]$zipfile, [string]$outpath)
					[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
				}
			Unzip "$PWD\Sysmon.zip" "$PWD"

	# Download the sysmonconfig XML File
			write-host "Downloading Config" -foregroundcolor green
					$clientdlsysmonxml = new-object System.Net.WebClient
					$clientdlsysmonxml.DownloadFile("https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml","$PWD\sysmonconfig-export.xml")
			timeout /T 3
	# Install Sysmon 
			.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
		}

	# Enable Scheduled Task History 
	
			$ScheduledTaskLogging = wevtutil get-log Microsoft-Windows-TaskScheduler/Operational
			if ($ScheduledTaskLogging -like "enabled: true") {
				write-host "::::: - OK - ::::: Scheduled Taks History Logging is enabled" -ForegroundColor green
		}
		else
		{
				write-host "::::: - OK - ::::: Setting Up Scheduled Taks History Logging" -ForegroundColor green
			wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true
		}

	# Adjust ToDo 
	# Adjust /sc minute /mo 1 = 1 minute !
	# Setting Up Scheduled Task 
	
				$taskName = "MittreAttackCheckerInfoSecPSSecuritySysMon"
				$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }	
				
		if(!($taskExists)) {
				schtasks /create /ru "SYSTEM" /sc minute /mo 1 /tn "MittreAttackCheckerInfoSecPSSecuritySysMon" /tr "Powershell -ExecutionPolicy bypass $PWD\MittreAttackCheckerInfoSecPSSecuritySysMon.ps1" /RL HIGHEST 
		} 
		else
		{
				write-host "::::: - OK - ::::: Task Scheduler is allready setup, continuing" -ForegroundColor green 
		}

	# Severity's:
	$1 = '1.High'
	$2 = '2.Medium'
	$3 = '3.Common use'
	$4 = '4.Low'


# - - - - Query Powershell Events - - - - # Set Date Minutes Effectively
$Powershell = Get-WinEvent -FilterHashtable @{Logname="Microsoft-Windows-PowerShell/Operational";StartTime=$EventData} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message
# - - - - Query Powershell Events - - - - # Set Date Minutes Effectively

foreach ($item in $Powershell) {

	switch ($item.ID) 	{

# Review ! 
	"400,500"	{		
		$query = '^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$'
		$Result = if ($item.Message -match "$query") { 
			$Technique = 'T1086'
			$Threat = "Execution - PowerShell Base64 block used"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
												'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID  
		}

	# END Switch Security IDs
	}
# End ForEach Security
}
		
# - - - - Query Security Events - - - - # Set Date Minutes Effectively
$Security = Get-WinEvent -FilterHashtable @{Logname="Security";StartTime=$EventData} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message | Where { $_.Message -notlike "*splunkd*" } 
# - - - - Query Security Events - - - - # Set Date Minutes Effectively

foreach ($item in $Security) {

	switch ($item.ID) 	{	
	
	"4688"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -notlike "*query*")) { 	
			$Technique = 'T1018'
			$Threat = "Discovery - Remote System Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID  
		}
		

	"4688"	{		
		$Result = if (((($item.Message -like "*wevtutil.exe cl*") -OR ($item.Message -like "*Clear-EventLog $_.Log*") -OR ($item.Message -like "*GlobalSession.ClearLog") -OR ($item.Message -like "*AttackCheckerInfoSec*")))) { 	
			$Technique = 'T1070'
			$Threat = "Defense_Evasion - Indicator Removal on Host - Clear Windows Event Logs"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }				
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -notlike "*query*")) { 	
			$Technique = 'T1112'
			$Threat = "Defense_Evasion - Modify Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"4688"		{
		$Result = if ((((($item.Message -like "*wevtutil.exe cl*") -OR ($item.Message -like "*Clear-EventLog $_.Log*") -OR ($item.Message -like "*GlobalSession.ClearLog") -OR ($item.Message -like "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*C:\Windows\System32\wevtutil.exe*"))))) { 	
			$Technique = 'T1070'
			$Threat = "Indicator Removal on Host - Clear Windows Event Logs"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }				
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
	
	"4688"		{
		$Result = if (((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* config*") -OR ($item.Message -like "*ipconfig.exe*") -OR ($item.Message -like "*netsh.exe*") -OR ($item.Message -like "*arp.exe*") -OR ($item.Message -like "*nbtstat.exe*")))))) { 	
			$Technique = 'T1016'
			$Threat = "System Network Configuration Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }				
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"4688"		{
		$Result = if (($item.Message -like "*tscon.exe*") -OR ($item.Message -like "*mstsc.exe*")) { 
			$Technique = 'T1076'
			$Threat = "Lateral_Movement - Remote Desktop Protocol - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }				
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*\\tscon.exe") -OR ($item.Message -like "*mstsc.exe*") -OR ($item.Message -like "*dst_port=3389*") -AND ($item.Message -like "*initiated=true*")))) { 	
			$Technique = 'T1076'
			$Threat = "Lateral Movement - Remote Desktop Protocol - Network"
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*C:\\Windows\\System32\\svchost.exe*") -OR ($item.Message -like "*wmic.exe*") -AND ($item.Message -like "*C:\\WINDOWS\\system32\\wbem\\scrcons.exe*")) { 
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process"
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}		

	"4688"	{		
		$Result = if ($item.Message -like "*net* accounts \/domain*") { 	
			$Technique = 'T1201'
			$Threat = "Discovery - Password Policy Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*Get-Process*") { 	
			$Technique = 'T1057'
			$Threat = "Execution - Process Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4624"	{		
		$Result = if (((((((($item.Message -like "*NULL SID*") -OR ($item.Message -like "*S-1-0-0*") -AND ($item.Message -like "3") -AND ($item.Message -like "*::1*") -AND ($item.Message -like "*NtLmSsp*") -AND ($item.Message -like "*NTLM V2*") -AND ($item.Message -like "*0*") -AND ($item.Message -notlike "*ANONYMOUS LOGON*")))))))) { 	
			$Technique = 'T1057'
			$Threat = "Lateral Movement - Pass the Hash NULL SID"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*.Download*") -OR ($item.Message -like "*Net.WebClient*")) { 	
			$Technique = 'T1086'
			$Threat = "Execution - Download or web connection - PowerShell Downloads - WinProcess"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*reg* query HKLM \/f password \/t REG_SZ \/s*") -OR ($item.Message -like "*reg* query HKCU \/f password \/t REG_SZ \/s*") -OR ($item.Message -like "*Get-UnattendedInstallFile*") -OR ($item.Message -like "*Get-Webconfig*") -OR ($item.Message -like "*Get-ApplicationHost*") -OR ($item.Message -like "*Get-SiteListPassword*") -OR ($item.Message -like "*Get-CachedGPPPassword*") -OR ($item.Message -like "*Get-RegistryAutoLogon*")))))))) { 	
			$Technique = 'T1214'
			$Threat = "Credential Access - Credentials in Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	# Review ! 
	"4688"	{		
		$Result = if (((((($item.Message -like "*schtasks.exe*") -OR ($item.Message -like "*taskeng.exe*") -OR ($item.Message -like "*svchost.exe*") -AND ($item.Message -notlike "*C:\Windows\System32\services.exe*") -AND ($item.Message -notlike "*0x3E7*") -AND ($item.Message -notlike "*audiodg*")))))) {	
			$Technique = 'T1053'
			$Threat = "Persistence,Privilege_Escalation,Execution - Scheduled Task - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	# Review ! 
	"4688"	{		
		$Result = if ((((((($item.Message -like "*schtasks.exe*") -OR ($item.Message -like "*taskeng.exe*") -OR ($item.Message -like "*svchost.exe*") -AND ($item.Message -notlike "*C:\\Windows\\System32\\services.exe*") -AND ($item.Message -notlike "*MittreAttackChecker*.ps1*") -AND ($item.Message -notlike "*0x3E7*") -AND ($item.Message -notlike "*audiodg*"))))))) { 	
			$Technique = 'T1053'
			$Threat = "Persistence,Privilege_Escalation,Execution Scheduled Task - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*\\rundll32.exe*") -OR ($item.Message -like "*rundll32.exe*")) { 	
			$Technique = 'T1085'
			$Threat = "Defense_Evasion,Execution - Rundll32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*\eventvwr.exe*") -OR ($item.Message -like "*\fodhelper.exe*")) { 	
			$Technique = 'T1088'
			$Threat = "Defense_Evasion,Execution - Rundll32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*InstallUtil.exe*") -OR ($item.Message -like "*\/logfile= \/LogToConsole=false \/U*")) { 	
			$Technique = 'T1118'
			$Threat = "Defense_Evasion,Execution - InstallUtil"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*regsvcs.exe*") -OR ($item.Message -like "*regasm.exe*")) { 	
			$Technique = 'T1121'
			$Threat = "Defense_Evasion,Execution - Regsvcs/Regasm"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*sdbinst.exe*") { 	
			$Technique = 'T1121'
			$Threat = "Persistence,Privilege_Escalation - Application Shimming - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*CMSTP.exe*") { 	
			$Technique = 'T1191'
			$Threat = "Defense_Evasion,Execution - CMSTP"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*cscript*script*http*") -OR ($item.Message -like "*wscript*script*http*") -OR ($item.Message -like "*certutil*script*http*") -OR ($item.Message -like "*jjs*-scripting*") -OR ($item.Message -like "*SyncAppvPublishingServe.vbs*") -OR ($item.Message -like "*manage-bde.wsf*") -OR ($item.Message -like "*pubprn.vbs*")))))))) { 	
			$Technique = 'T1216'
			$Threat = "Defense_Evasion,Execution - Signed Script Proxy Execution"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((((($item.Message -like "*msiexec.exe /q /i*") -OR ($item.Message -like "*msiexec.exe /q /i http[:]*") -OR ($item.Message -like "*msiexec.exe /y *.dll") -OR ($item.Message -like "*MavInject32.exe * /INJECTRUNNING*") -OR ($item.Message -like "*SyncAppvPublishingServe.vbs*") -OR ($item.Message -like "*manage-bde.wsf*") -OR ($item.Message -like "*odbcconf.exe /S /A *REGSVR*.dll"))))))) { 	
			$Technique = 'T1218'
			$Threat = "Defense_Evasion,Execution - Signed Binary Proxy Execution - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*cmd.exe*") { 	
			$Technique = 'T1059'
			$Threat = "Execution - Command-Line Interface"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*reg.exe*") -OR ($item.Message -like "*reg* query*")) { 	
			$Technique = 'T1012'
			$Threat = "Discovery - Query Registry - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*\mshta.exe*") -OR ($item.Message -like "*mshta.exe*")) { 	
			$Technique = 'T1170'
			$Threat = "Defense_Evasion,Execution - MSHTA - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*.Download*") -OR ($item.Message -like "*Net.WebClient*")) { 	
			$Technique = 'T1086'
			$Threat = "Download or web connection - PowerShell Downloads - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*fltmc.exe*") -OR ($item.Message -like "*fltmc*unload*")) { 	
			$Technique = 'T1054'
			$Threat = "Defense_Evasion - Indicator Blocking - Driver unloaded"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*net.exe*") -OR ($item.Message -like "*sc.exe*") -AND ($item.Message -like "*stop*")) { 	
			$Technique = 'T1089'
			$Threat = "Defense_Evasion - Disabling Security Tools - Service stopped"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -like "*save*HKLM\sam*") -OR ($item.Message -like "*save*HKLM\system*")) { 	
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping - Registry Save"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* share*$")) { 	
			$Technique = 'T1077'
			$Threat = "Lateral_Movement - Windows Admin Shares - Process - Created"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*fsutil.exe*") -AND ($item.Message -like "*usn*deletejournal*")) { 	
			$Technique = 'T1096'
			$Threat = "Defense_Evasion - NTFS File Attributes"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((($item.Message -like "*Invoke-Mimikatz -DumpCreds*") -OR ($item.Message -like "*gsecdump* -a*") -OR ($item.Message -like "*wce* -o*") -OR ($item.Message -like "*procdump* -ma lsass.exe*") -OR ($item.Message -like "*ntdsutil*ac i ntds*ifm*create full*"))))) { 	
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*whoami*") -OR ($item.Message -like "*wmic useraccount get*") -OR ($item.Message -like "*qwinsta.exe*") -OR ($item.Message -like "*query user*")))) { 	
			$Technique = 'T1033'
			$Threat = "Discovery - System Owner/User Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*netstat.exe*") -AND ($item.Message -like "*net* use*") -OR ($item.Message -like "*net* sessions*") -OR ($item.Message -like "*net* file*") -OR ($item.Message -like "*netstat*") -OR ($item.Message -like "*Get-NetTCPConnection*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*")))))))) { 	
			$Technique = 'T1049'
			$Threat = "Discovery - System Network Connections Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*powershell_ise.exe*") -OR ($item.Message -like "*psexec.exe*") -AND ($item.Message -notlike "*MittreAttackChecker*") -AND ($item.Message -notlike "*svchost.exe*") -AND ($item.Message -notlike "*conhost.exe*") -AND ($item.Message -notlike "*C:\Windows\System32\query.exe*") -AND ($item.Message -notlike "*C:\Windows\System32\wevtutil.exe*")))))))) { 	
			$Technique = 'T1086'
			$Threat = "Execution - PowerShell"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{
		$Result = if ((((((($item.Message -like "netsh.exe*") -OR ($item.Message -like "*reg.exe*") -OR ($item.Message -like "*tasklist.exe*") -AND ($item.Message -notlike "*reg* query*") -OR ($item.Message -like "*tasklist *") -OR ($item.Message -like "*netsh*") -OR ($item.Message -like "*fltmc*|*findstr*"))))))) { 	
			$Technique = 'T1063'
			$Threat = "Discovery - Security Software Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -AND ($item.Message -notlike "*net* localgroup*") -OR ($item.Message -like "*get-localgroup*") -OR ($item.Message -like "*netsh*") -OR ($item.Message -like "*get-ADPrinicipalGroupMembership*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*")))))))) { 	
			$Technique = 'T1069'
			$Threat = "Discovery - Permission Groups Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*DownloadString*") -AND ($item.Message -like "*Net.WebClient*") -AND ($item.Message -like "*New-Object*") -AND ($item.Message -notlike "*IEX*")))) { 	
			$Technique = 'T1074'
			$Threat = "Collection - Data Staged - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* use*$") -OR ($item.Message -like "*net* session*$") -OR ($item.Message -like "*net* file*$") -AND ($item.Message -like "*New-PSDrive*root*")))))) { 	
			$Technique = 'T1077'
			$Threat = "Lateral_Movement - Windows Admin Shares - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*findstr* /si pass*") -OR ($item.Message -like "*select-string -Pattern pass*") -AND ($item.Message -like "*list vdir*/text:password*"))) {	
			$Technique = 'T1081'
			$Threat = "Credential_Access - Credentials in Files"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*sysinfo.exe*") -OR ($item.Message -like "*reg.exe*") -AND ($item.Message -like "*reg*query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum*"))) {	
			$Technique = 'T1082'
			$Threat = "Discovery - System Information Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((((((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -OR ($item.Message -like "*net* localgroup*") -OR ($item.Message -like "*cmdkey* *list*") -AND ($item.Message -like "*get-localuser*") -OR ($item.Message -like "*get-localgroupmembers*") -OR ($item.Message -like "*get-aduser*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*conhost*"))))))))))) {	
			$Technique = 'T1087'
			$Threat = "Discovery - Account Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*clip.exe*") -OR ($item.Message -like "*Get-Clipboard*")) {	
			$Technique = 'T1115'
			$Threat = "Collection - Clipboard Data"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*SoundRecorder.exe*") -OR ($item.Message -like "*Get-AudioDevice*") -OR ($item.Message -like "*WindowsAudioDevice-Powershell-Cmdlet*"))) {	
			$Technique = 'T1123'
			$Threat = "Collection - Audio Capture"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*\net.exe") -OR ($item.Message -like "*net* time*") -OR ($item.Message -like "*w32tm.exe*") -OR ($item.Message -like "*Get-Date*")))) {	
			$Technique = 'T1124'
			$Threat = "Discovery - System Time Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* delete*") -OR ($item.Message -like "*Remove-SmbShare*") -OR ($item.Message -like "*Remove-FileShare*")))) {	
			$Technique = 'T1126'
			$Threat = "Defense_Evasion - Network Share Connection Removal"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*MSBuild.exe*") -OR ($item.Message -like "*msxsl.exe*")) {	
			$Technique = 'T1127'
			$Threat = "Defense_Evasion,Execution - Trusted Developer Utilities"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*netsh.exe*") -AND ($item.Message -like "*helper*")) {	
			$Technique = 'T1128'
			$Threat = "Persistence - Netsh Helper DLL - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((((((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -OR ($item.Message -like "*net* localgroup*") -OR ($item.Message -like "*cmdkey*list*") -OR ($item.Message -like "*get-localuser*") -OR ($item.Message -like "*get-localgroupmembers*") -OR ($item.Message -like "*get-aduser*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*conhost*"))))))))))) {	
			$Technique = 'T1087'
			$Threat = "Discovery - Account Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -OR ($item.Message -like "*net* localgroup*") -OR ($item.Message -like "*cmdkey*list*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*conhost*")))))))) {	
			$Technique = 'T1087'
			$Threat = "Discovery - Account Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((($item.Message -like "*remove-item*") -OR ($item.Message -like "*vssadmin*Delete Shadows /All /Q*") -OR ($item.Message -like "*wmic*shadowcopy delete*") -OR ($item.Message -like "*wbdadmin* delete catalog -q*") -OR ($item.Message -like "*bcdedit*bootstatuspolicy ignoreallfailures*") -OR ($item.Message -like "*bcdedit*recoveryenabled no*")))))) {	
			$Technique = 'T1107'
			$Threat = "Defense_Evasion - File Deletion"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* view*") -OR ($item.Message -like "*net* share*") -OR ($item.Message -like "*get-smbshare -Name*")))) {	
			$Technique = 'T1135'
			$Threat = "Discovery - Network Share Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*New-LocalUser*") -AND ($item.Message -like "*net*user*add*")) {	
			$Technique = 'T1136'
			$Threat = "Persistence - Create Account"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*AppData\Roaming\Microsoft\Windows\\PowerShell\PSReadline\ConsoleHost_history.txt*") -OR ($item.Message -like "*(Get-PSReadlineOption).HistorySavePath*")) {	
			$Technique = 'T0000'
			$Threat = "Collection - Console History"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*certutil.exe*") -AND ($item.Message -like "*decode*")) {	
			$Technique = 'T1140'
			$Threat = "Defense_Evasion - Deobfuscate/Decode Files or Information"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*certutil.exe*") -AND ($item.Message -like "*encode*")) {	
			$Technique = 'T1027'
			$Threat = "Defense_Evasion - Obfuscated Files or Information"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*rm (Get-PSReadlineOption).HistorySavePath*") -OR ($item.Message -like "*del (Get-PSReadlineOption).HistorySavePath*") -OR ($item.Message -like "*Set-PSReadlineOption *HistorySaveStyle SaveNothing*") -OR ($item.Message -like "*Remove-Item (Get-PSReadlineOption).HistorySavePath*")))) {	
			$Technique = 'T1146'
			$Threat = "Collection - Clear Command History"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*attrib.exe*") -AND ($item.Message -like "*+h*") -OR ($item.Message -like "*+s*"))) {	
			$Technique = 'T1158'
			$Threat = "Persistence,Defense_Evasion - Hidden Files and Directories"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*mavinject.exe*") -AND ($item.Message -like "*/INJECTRUNNING*")) {	
			$Technique = 'T1179'
			$Threat = "Persistence,Privilege_Escalation,Credential_Access - Hooking"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*bitsadmin.exe*") -AND ($item.Message -like "*Start-BitsTransfer*")) {	
			$Technique = 'T1197'
			$Threat = "Persistence,Defense_Evasion - BITS Jobs - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*pcalua.exe*") -OR ($item.Message -like "*bash.exe*")-OR ($item.Message -like "*forfiles.exe*"))) {	
			$Technique = 'T1202'
			$Threat = "Discovery - Indirect Command Execution"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*firefox*places.sqlite*") -OR ($item.Message -like "*bookmarks*")) {	
			$Technique = 'T1217'
			$Threat = "Discovery - Browser Bookmark Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*hh.exe*") {	
			$Technique = 'T1223'
			$Threat = "Defense_Evasion,Execution - Compiled HTML File"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((($item.Message -like "*wsmprovhost.exe*") -OR ($item.Message -like "*winrm.cmd*") -OR ($item.Message -like "*Enable-PSRemoting -Force*") -OR ($item.Message -like "*Invoke-Command -computer_name*") -OR ($item.Message -like "*wmic*node*process call create*"))))) {	
			$Technique = 'T1028'
			$Threat = "Lateral_Movement,Execution - Windows Remote Management"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "*REG*ADD*HKCU\Environment\*") {	
			$Technique = 'T1037'
			$Threat = "Lateral_Movement,Persistence - Logon Scripts"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((($item.Message -like "*tshark.exe*") -OR ($item.Message -like "*windump.exe*") -OR ($item.Message -like "*logman.exe*") -OR ($item.Message -like "*tcpdump.exe*") -OR ($item.Message -like "*wprui.exe*") -OR ($item.Message -like "*wpr.exe*")))))) {	
			$Technique = 'T1040'
			$Threat = "Credential_Access,Discovery - Network Sniffing"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*sc.exe*") -OR ($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*cmd.exe*") -AND ($item.Message -like "*sc*config*")))) {	
			$Technique = 'T1031'
			$Threat = "Persistence - Modify Existing Service"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((($item.Message -like "*sc.exe*") -OR ($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*cmd.exe*") -AND ($item.Message -like "*New-Service*BinaryPathName*") -OR ($item.Message -like "*sc*create*binpath*") -OR ($item.Message -like "*Get-WmiObject*Win32_Service*create*")))))) {	
			$Technique = 'T1050'
			$Threat = "Persistence,Privilege_Escalation,Execution - New Service - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*Invoke-DllInjection*") -OR ($item.Message -like "*c:\windows\sysnative\*")) {	
			$Technique = 'T1055'
			$Threat = "Privilege_Escalation,Defense_Evasion - Process Injection - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((((((((((((((((((((((((((((((((((((((((((((((($item.Message -like "*smss.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*csrss.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*wininit.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*winlogon.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*lsass.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*LogonUI.exe*") -AND ($item.Message -notlike "*ParentImage*winlogon.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*services.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*spoolsv.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*") -OR ($item.Message -like "*taskhost.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*") -AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*taskhostw.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*")-AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*userinit.exe*") -AND ($item.Message -notlike "*dwm.exe*") -AND ($item.Message -notlike "*ParentImage*winlogon.exe*") -OR ($item.Message -notlike "*taskhostw*") -AND ($item.Message -notlike "*backgroundTaskHost*") -AND ($item.Message -notlike "*conhost*") -AND ($item.Message -notlike "*chrome.exe*") -AND ($item.Message -notlike "*query*") -AND ($item.Message -notlike "*powershell*") -AND ($item.Message -notlike "*svchost.exe*") -OR ($item.Message -notlike "*MicrosoftOfficeHub*") -OR ($item.Message -notlike "*FlashPlayerUpdateService*") -OR ($item.Message -notlike "*conhost*") -AND ($item.Message -notlike "*powershell*")-AND ($item.Message -notlike "*A new process has been created* *chrome*") -AND ($item.Message -notlike "*backgroundTaskHost.exe*") -AND ($item.Message -notlike "*services.exe* *svchost.exe*") -AND ($item.Message -notlike "*RuntimeBroker.exe* *svchost.exe*") -AND ($item.Message -notlike "*taskhostw.exe* *svchost.exe*") -AND ($item.Message -notlike "*MicrosoftOfficeHub*") -AND ($item.Message -notlike "*audiodg.exe* *svchost.exe*") -AND ($item.Message -notlike "*svchost.exe* *services.exe*") -AND ($item.Message -notlike "*query.exe*") -AND ($item.Message -notlike "*query.exe*") -AND ($item.Message -notlike "*wbem\WmiPrvSE.exe* *svchost.exe*") -AND ($item.Message -notlike "*FlashPlayerUpdateService*") -AND ($item.Message -notlike "*C:\Windows\WinSxS\amd64*") -AND ($item.Message -notlike "*C:\Windows\servicing\TrustedInstaller.exe*") -AND ($item.Message -notlike "*GoToMeeting*")))))))))))))))))))))))))))))))))))))))))))))))))))) {	
			$Technique = 'T1093' 
			$Threat = "Defense_Evasion - Process Hollowing"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((($item.Message -like "*regsvr32.exe*") -OR ($item.Message -like "*rundll32.exe*") -OR ($item.Message -like "*certutil.exe*"))) {	
			$Technique = 'T1117'
			$Threat = "Defense_Evasion - Bypassing Application Whitelisting with Regsvr32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*-Recurse | Compress-Archive*") -OR ($item.Message -like "*rar.exe*") -OR ($item.Message -like "*rar*a**") -OR ($item.Message -like "*7z.exe*") -OR ($item.Message -like "*zip.exe*") -AND ($item.Message -notlike "*conhost*") -AND ($item.Message -notlike "*powershell*") -AND ($item.Message -notlike "*C:\Windows\servicing\TrustedInstaller.exe*")))))))) {	
			$Technique = 'T1002'
			$Threat = "Exfiltration - Data Compressed"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((((((((((((((((((((((((((((((($item.Message -like "*\a.exe*") -OR ($item.Message -like "*\b.exe*") -OR ($item.Message -like "*\c.exe*") -OR ($item.Message -like "*\d.exe*") -OR ($item.Message -like "*\e.exe*") -OR ($item.Message -like "*\f.exe*") -OR ($item.Message -like "*\g.exe*") -OR ($item.Message -like "*\h.exe*") -OR ($item.Message -like "*\i.exe*") -OR ($item.Message -like "*\j.exe*") -OR ($item.Message -like "*\k.exe*") -OR ($item.Message -like "*\l.exe*") -OR ($item.Message -like "*\m.exe*") -OR ($item.Message -like "*\n.exe*") -OR ($item.Message -like "*\o.exe*") -OR ($item.Message -like "*\p.exe*") -OR ($item.Message -like "*\q.exe*") -OR ($item.Message -like "*\r.exe*") -OR ($item.Message -like "*\s.exe*") -OR ($item.Message -like "*\t.exe*") -OR ($item.Message -like "*\u.exe*") -OR ($item.Message -like "*\w.exe*") -OR ($item.Message -like "*\v.exe*")-OR ($item.Message -like "*\x.exe*") -OR ($item.Message -like "*\y.exe*") -OR ($item.Message -like "*\z.exe*") -OR ($item.Message -like "*\1.exe*") -OR ($item.Message -like "*\2.exe*") -OR ($item.Message -like "*\3.exe*") -OR ($item.Message -like "*\4.exe*") -OR ($item.Message -like "*\5.exe*") -OR ($item.Message -like "*\6.exe*") -OR ($item.Message -like "*\7.exe*") -OR ($item.Message -like "*\8.exe*") -OR ($item.Message -like "*\9.exe*") -OR ($item.Message -like "*\10.exe*")))))))))))))))))))))))))))))))))))) {			
			$Technique = 'T0000' 
			$Threat = "Execution - Suspicious filename used"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((((((((((($item.Message -like "*.doc.*") -OR ($item.Message -like "*.docx.*") -OR ($item.Message -like "*.xls.*") -OR ($item.Message -like "*.xlsx.*") -OR ($item.Message -like "*.pdf.*") -OR ($item.Message -like "*.rtf.*") -OR ($item.Message -like "*.jpg.*") -OR ($item.Message -like "*.png.*") -OR ($item.Message -like "*.jpeg.*") -OR ($item.Message -like "*.zip.*") -OR ($item.Message -like "*.rar.*") -OR ($item.Message -like "*.ppt.*") -OR ($item.Message -like "*.pptx.*"))))))))))))) {	
			$Technique = 'T1036'
			$Threat = "Defense_Evasion - Masquerading - Extension"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "\\*\Volume*") -OR ($item.Message -like "*\\*\GLOBALROOT\Device\HarddiskVolumeShadowCopy*")) {	
			$Technique = 'T1158'
			$Threat = "Defense_Evasion,Persistence - Hidden Files and Directories - VSS"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ($item.Message -like "") {	
			$Technique = 'T1093'
			$Threat = "Defense_Evasion - Process Hollowing - commandline"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if ((((($item.Message -like "*winword.exe*") -OR ($item.Message -like "*excel.exe*") -OR ($item.Message -like "*outlook.exe*") -OR ($item.Message -like "*C:\Program Files\Microsoft Office\*-enc*") -OR ($item.Message -like "*C:\\Program Files (x86)\Microsoft Office\*-enc*"))))) {	
			$Technique = 'T1093'
			$Threat = "Defense_Evasion - Process Hollowing - office commandline"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((($item.Message -like "*netsh.exe*") -OR ($item.Message -like "*trace*start*capture=yes*") -OR ($item.Message -like "*tshark.exe*") -OR ($item.Message -like "*wireshark.exe*")))) {	
			$Technique = 'T1040'
			$Threat = "Credential_Access,Discovery - Network Sniffing - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (((((((((((((((($item.Message -like "*svchost.exe*") -AND ($item.Message -notlike "*services.exe*") -OR ($item.Message -like "*scvhost.exe*") -AND ($item.Message -notlike "*powershell*") -AND ($item.Message -notlike "*RuntimeBroker*") -AND ($item.Message -notlike "*backgroundTaskHost*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\vssvc.exe*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s gpsvc*") -AND ($item.Message -notlike "*taskhostw.exe* *svchost.exe*") -AND ($item.Message -notlike "*audiodg.exe* *svchost.exe*") -AND ($item.Message -notlike "*wbem\WmiPrvSE.exe* *svchost.exe*") -AND ($item.Message -notlike "*FlashPlayerUpdateService*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s gpsvc*") -AND ($item.Message -notlike "*C:\Windows\WinSxS\amd64*") -AND ($item.Message -notlike "*GoToMeeting*")))))))))))))))) {	
			$Technique = 'T1036' 
			$Threat = "Defense_Evasion - Masquerading - svchost"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4688"	{		
		$Result = if (($item.Message -like "*explorer.exe*") -AND ($item.Message -notlike "*userinit.exe*")) {	
			$Technique = 'T1036'
			$Threat = "Defense_Evasion - Masquerading - explorer"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"4769"	{		
		$Result = if ((($item.Message -like "*0x17*") -AND ($item.Message -notlike "*NONE_MAPPED*") -AND ($item.Message -notlike "*sa_**"))) { 	
			$Technique = 'T1208'
			$Threat = "Credential_Access - Kerberoasting"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"4768,4769,4771"	{		
		$Result = if ($item.Message -like "*0x1F*") { 	
			$Technique = 'T1097'
			$Threat = "Lateral_Movement - Pass the ticket"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"7034"	{		
		$Result = if ($item.Message -like "*Sysmon*") { 	
			$Technique = 'T1089'
			$Threat = "Defense_Evasion - Disabling Security Tools - Sysmon service was terminated"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"7036"	{		
		$Result = if ($item.Message -notlike "*Started*") { 	
			$Technique = 'T1089'
			$Threat = "Defense_Evasion - Disabling Security Tools - Sysmon service state change"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	# END Switch Security IDs
	}
# End ForEach Security
}


# - - - - Query SysMon Events - - - - # Set Date Minutes Effectively
$SysMon = Get-WinEvent -FilterHashtable @{Logname="Microsoft-Windows-Sysmon/Operational";StartTime=$EventData} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message | Where { $_.Message -notlike "*splunkd*" } 
# - - - - Query SysMon Events - - - - # Set Date Minutes Effectively

foreach ($item in $SysMon) {

	switch ($item.ID) 	{			
	"1"	{		
		$Result = if (($item.Message -like "*net view*") -OR ($item.Message -like "*ping*")) { 
			$Technique = 'T1018'
			$Threat = "Remote System Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }				
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
	
	"1"	{		
		$Result = if (((((($item.Message -like "*wevtutil.exe cl*") -OR ($item.Message -like "*Clear-EventLog $_.Log*") -OR ($item.Message -like "*GlobalSession.ClearLog") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\quser.exe* *server:localhost*") -AND ($item.Message -notlike "*wevtutil.exe")))))) { 	
			$Technique = 'T1070'
			$Threat = "Indicator Removal on Host - Clear Windows Event Logs"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -notlike "*query*")) { 	
			$Technique = 'T1112'
			$Threat = "Defense_Evasion - Modify Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile }
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -notlike "*query*")) { 	
			$Technique = 'T1018'
			$Threat = "Discovery - Remote System Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* config*") -OR ($item.Message -like "*ipconfig.exe*") -OR ($item.Message -like "*netsh.exe*") -OR ($item.Message -like "*arp.exe*") -OR ($item.Message -like "*nbtstat.exe*")))))) { 	
			$Technique = 'T1076'
			$Threat = "Discovery - System Network Configuration Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"1"	{		
		$Result = if (($item.Message -like "*tscon.exe*") -OR ($item.Message -like "*mstsc.exe*")) { 
			$Technique = 'T1076'
			$Threat = "Lateral_Movement - Remote Desktop Protocol - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"1"	{		
		$Result = if (($item.Message -like "*\wmiprvse.exe*") -OR ($item.Message -like "*wmic.exe*") -OR ($item.Message -like "*wmic*")) { 
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"1"	{		
		$Result = if (($item.Message -like "*C:\Windows\System32\svchost.exe*") -OR ($item.Message -like "*wmic.exe*") -AND ($item.Message -like "*C:\WINDOWS\system32\wbem\scrcons.exe*")) { 
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*net* accounts *domain*") { 	
			$Technique = 'T1201'
			$Threat = "Discovery - Password Policy Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*Get-Process*") { 	
			$Technique = 'T1057'
			$Threat = "Execution - Process Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((($item.Message -like "*reg* query HKLM \/f password \/t REG_SZ \/s*") -OR ($item.Message -like "*reg* query HKCU \/f password \/t REG_SZ \/s*") -OR ($item.Message -like "*Get-UnattendedInstallFile*") -OR ($item.Message -like "*Get-Webconfig*") -OR ($item.Message -like "*Get-ApplicationHost*") -OR ($item.Message -like "*Get-SiteListPassword*") -OR ($item.Message -like "*Get-CachedGPPPassword*") -OR ($item.Message -like "*Get-RegistryAutoLogon*")))))))) { 	
			$Technique = 'T1214'
			$Threat = "Credential Access - Credentials in Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	# Review ! 
	"1"	{		
		$Result = if ((((((((((((((((((($item.Message -like "*schtasks.exe*") -OR ($item.Message -like "*taskeng.exe*") -OR ($item.Message -like "*svchost.exe*") -AND ($item.Message -notlike "*C:\Windows\System32\services.exe*") -OR ($item.Message -notlike "*taskhostw*") -OR ($item.Message -notlike "*backgroundTaskHost*") -OR ($item.Message -notlike "*conhost*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*ParentCommandLine*svchost.exe -k netsvcs -p -s Schedule*") -AND ($item.Message -notlike "*MicrosoftOfficeHub*") -AND ($item.Message -notlike "*TiWorker.exe*") -AND ($item.Message -notlike "*TrustedInstaller*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s BITS*") -AND ($item.Message -notlike "*/server:localhost*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*") -AND ($item.Message -notlike "*C:\Windows\System32\usocoreworker.exe -Embedding*") -AND ($item.Message -notlike "*C:\Windows\System32\usocoreworker.exe -Embedding*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\vssvc.exe*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s gpsvc*"))))))))))))))))))) { 	
			$Technique = 'T1053'
			$Threat = "Persistence,Privilege_Escalation,Execution Scheduled Task - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((($item.Message -like "*winlogon.exe*") -AND ($item.Message -like "*sethc.exe*") -OR ($item.Message -like "*utilman.exe*") -OR ($item.Message -like "*osk.exe*") -OR ($item.Message -like "*magnify.exe*") -OR ($item.Message -like "*osk.exe*") -OR ($item.Message -like "*displayswitch.exe*") -OR ($item.Message -like "*narrator.exe*") -OR ($item.Message -like "*atbroker.exe*"))))))))) { 	
			$Technique = 'T1015'
			$Threat = "Persistence,Privilege_Escalation,Execution Scheduled Task - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*\rundll32.exe*") -OR ($item.Message -like "*rundll32.exe*")) { 	
			$Technique = 'T1085'
			$Threat = "Defense_Evasion,Execution - Rundll32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"1"	{		
		$Result = if (($item.Message -like "*eventvwr.exe*") -OR ($item.Message -like "*fodhelper.exe*")) { 	
			$Technique = 'T1088'
			$Threat = "Defense_Evasion,Execution - Rundll32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*InstallUtil.exe*") -OR ($item.Message -like "*\/logfile= \/LogToConsole=false \/U*")) { 	
			$Technique = 'T1118'
			$Threat = "Defense_Evasion,Execution - InstallUtil"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*regsvcs.exe*") -OR ($item.Message -like "*regasm.exe*")) { 	
			$Technique = 'T1121'
			$Threat = "Defense_Evasion,Execution - Regsvcs/Regasm"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*sdbinst.exe*") { 	
			$Technique = 'T1121'
			$Threat = "Persistence,Privilege_Escalation - Application Shimming - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*CMSTP.exe*") { 	
			$Technique = 'T1191'
			$Threat = "Defense_Evasion,Execution - CMSTP"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*control* \/name*") -OR ($item.Message -like "*rundll32*") -OR ($item.Message -like "*shell32.dll,Control_RunDLL*"))) { 	
			$Technique = 'T1196'
			$Threat = "Defense_Evasion,Execution - CMSTP"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((($item.Message -like "*cscript*script*http*") -OR ($item.Message -like "*wscript*script*http*") -OR ($item.Message -like "*certutil*script*http*") -OR ($item.Message -like "*jjs*-scripting*") -OR ($item.Message -like "*SyncAppvPublishingServe.vbs*") -OR ($item.Message -like "*manage-bde.wsf*") -OR ($item.Message -like "*pubprn.vbs*")))))))) { 	
			$Technique = 'T1216'
			$Threat = "Defense_Evasion,Execution - Signed Script Proxy Execution"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((($item.Message -like "*msiexec.exe /q /i*") -OR ($item.Message -like "*msiexec.exe /q /i http*") -OR ($item.Message -like "*msiexec.exe /y *.dll") -OR ($item.Message -like "*MavInject32.exe * /INJECTRUNNING*") -OR ($item.Message -like "*SyncAppvPublishingServe.vbs*") -OR ($item.Message -like "*manage-bde.wsf*") -OR ($item.Message -like "*odbcconf.exe /S /A *REGSVR*.dll"))))))) { 	
			$Technique = 'T1218'
			$Threat = "Defense_Evasion,Execution - Signed Binary Proxy Execution - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*qwinsta.exe*") { 	
			$Technique = 'T0000'
			$Threat = "Discovery - Remotely Query Login Sessions - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*cmd.exe*") { 	
			$Technique = 'T1059'
			$Threat = "Execution - Command-Line Interface"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*reg.exe*") -OR ($item.Message -like "*reg query*")) { 	
			$Technique = 'T1012'
			$Threat = "Discovery - Query Registry - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*\mshta.exe*") -OR ($item.Message -like "*mshta.exe*")) { 	
			$Technique = 'T1170'
			$Threat = "Defense_Evasion,Execution - MSHTA - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*.Download*") -OR ($item.Message -like "*Net.WebClient*")) { 	
			$Technique = 'T1086'
			$Threat = "Download or web connection - PowerShell Downloads - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*fltmc.exe*") -OR ($item.Message -like "*fltmc*unload*")) { 	
			$Technique = 'T1054'
			$Threat = "Defense_Evasion - Indicator Blocking - Driver unloaded"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*net.exe*") -OR ($item.Message -like "*sc.exe*") -AND ($item.Message -like "*stop*") -AND ($item.Message -notlike "*Windows Defender*")))) { 	
			$Technique = 'T1089'
			$Threat = "Defense_Evasion - Disabling Security Tools - Service stopped"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*reg.exe*") -AND ($item.Message -like "*save*HKLM\sam*") -OR ($item.Message -like "*save*HKLM\system*")) { 	
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping - Registry Save"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* share*$")) { 	
			$Technique = 'T1077'
			$Threat = "Lateral_Movement - Windows Admin Shares - Process - Created"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*fsutil.exe*") -AND ($item.Message -like "*usn*deletejournal*")) { 	
			$Technique = 'T1096'
			$Threat = "Defense_Evasion - NTFS File Attributes"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((($item.Message -like "*Invoke-Mimikatz -DumpCreds*") -OR ($item.Message -like "*gsecdump* -a*") -OR ($item.Message -like "*wce* -o*") -OR ($item.Message -like "*procdump* -ma lsass.exe*") -OR ($item.Message -like "*ntdsutil*ac i ntds*ifm*create full*"))))) { 	
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*tasklist.exe*") -OR ($item.Message -like "*sc.exe*") -OR ($item.Message -like "*wmic.exe*") -AND ($item.Message -like "*net* start*") -OR ($item.Message -like "*tasklist *svc*") -OR ($item.Message -like "*sc* query*") -OR ($item.Message -like "*wmic* service where*") -OR ($item.Message -like "*/server:localhost*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*/server:localhost*") -AND ($item.Message -notlike "*/server:localhost*"))))))))))) { 	
			$Technique = 'T1007' 
			$Threat = "Discovery - System Service Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((($item.Message -like "*whoami*") -OR ($item.Message -like "*wmic useraccount get*") -OR ($item.Message -like "*qwinsta.exe*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\quser.exe* /server:localhost*"))))) { 	
			$Technique = 'T1033' 
			$Threat = "Discovery - System Owner/User Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*netstat.exe*") -AND ($item.Message -like "*net* use*") -OR ($item.Message -like "*net* sessions*") -OR ($item.Message -like "*net* file*") -OR ($item.Message -like "*netstat*") -OR ($item.Message -like "*Get-NetTCPConnection*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*"))))))))) { 	
			$Technique = 'T1049'
			$Threat = "Discovery - System Network Connections Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*powershell_ise.exe*") -OR ($item.Message -like "*psexec.exe*") -AND ($item.Message -notlike "*server:localhost*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*wevtutil.exe*")))))) { 	
			$Technique = 'T1086'
			$Threat = "Execution - PowerShell"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((($item.Message -like "netsh.exe*") -OR ($item.Message -like "*reg.exe*") -OR ($item.Message -like "*tasklist.exe*") -AND ($item.Message -notlike "*reg query*") -OR ($item.Message -like "*tasklist *") -OR ($item.Message -like "*netsh*") -OR ($item.Message -like "*fltmc*|*findstr*"))))))) { 	
			$Technique = 'T1063'
			$Threat = "Discovery - Security Software Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -AND ($item.Message -notlike "*net* localgroup*") -OR ($item.Message -like "*get-localgroup*") -OR ($item.Message -like "*netsh*") -OR ($item.Message -like "*get-ADPrinicipalGroupMembership*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*")))))))) { 	
			$Technique = 'T1069'
			$Threat = "Discovery - Permission Groups Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*DownloadString*") -AND ($item.Message -like "*Net.WebClient*") -AND ($item.Message -like "*New-Object*") -AND ($item.Message -notlike "*IEX*")))) { 	
			$Technique = 'T1074'
			$Threat = "Collection - Data Staged - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* use*$") -OR ($item.Message -like "*net* session*$") -OR ($item.Message -like "*net* file*$") -AND ($item.Message -like "*New-PSDrive*root*")))))) {	
			$Technique = 'T1077'
			$Threat = "Lateral_Movement - Windows Admin Shares - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*findstr* /si pass*") -OR ($item.Message -like "*select-string -Pattern pass*") -AND ($item.Message -like "*list vdir*/text:password*"))) {	
			$Technique = 'T1081'
			$Threat = "Credential_Access - Credentials in Files"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*sysinfo.exe*") -OR ($item.Message -like "*reg.exe*") -AND ($item.Message -like "*reg*query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum*"))) {	
			$Technique = 'T1082'
			$Threat = "Discovery - System Information Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((($item.Message -like "*net.exe*") -OR ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -OR ($item.Message -like "*net* localgroup*") -OR ($item.Message -like "*cmdkey* *list*") -AND ($item.Message -like "*get-localuser*") -OR ($item.Message -like "*get-localgroupmembers*") -OR ($item.Message -like "*get-aduser*") -OR ($item.Message -like "*query*user*") -AND ($item.Message -notlike "*/server:localhost*"))))))))))) {	
			$Technique = 'T1087'
			$Threat = "Discovery - Account Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*clip.exe*") -OR ($item.Message -like "*Get-Clipboard*")) {	
			$Technique = 'T1115'
			$Threat = "Collection - Clipboard Data"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*SoundRecorder.exe*") -OR ($item.Message -like "*Get-AudioDevice*") -OR ($item.Message -like "*WindowsAudioDevice-Powershell-Cmdlet*"))) {	
			$Technique = 'T1123'
			$Threat = "Collection - Audio Capture"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*\net.exe") -OR ($item.Message -like "*net* time*") -OR ($item.Message -like "*w32tm.exe*") -OR ($item.Message -like "*Get-Date*")))) {	
			$Technique = 'T1124'
			$Threat = "Discovery - System Time Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* delete*") -OR ($item.Message -like "*Remove-SmbShare*") -OR ($item.Message -like "*Remove-FileShare*")))) {	
			$Technique = 'T1126'
			$Threat = "Defense_Evasion - Network Share Connection Removal"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*MSBuild.exe*") -OR ($item.Message -like "*msxsl.exe*")) {	
			$Technique = 'T1127'
			$Threat = "Defense_Evasion,Execution - Trusted Developer Utilities"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*netsh.exe*") -AND ($item.Message -like "*helper*")) {	
			$Technique = 'T1128'
			$Threat = "Persistence - Netsh Helper DLL - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((($item.Message -like "*net.exe*") -AND ($item.Message -like "*powershell.exe*") -AND ($item.Message -like "*net* user*") -OR ($item.Message -like "*net* group*") -OR ($item.Message -like "*net* localgroup*") -OR ($item.Message -like "*cmdkey*list*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*/server:localhost")))))))) {	
			$Technique = 'T1087'
			$Threat = "Discovery - Account Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((($item.Message -like "*remove-item*") -AND ($item.Message -like "*vssadmin*Delete Shadows /All /Q*") -AND ($item.Message -like "*wmic*shadowcopy delete*") -OR ($item.Message -like "*wbdadmin* delete catalog -q*") -OR ($item.Message -like "*bcdedit*bootstatuspolicy ignoreallfailures*") -OR ($item.Message -like "*bcdedit*recoveryenabled no*") -OR ($item.Message -like "*get-localuser*") -OR ($item.Message -like "*get-localgroupmembers*") -OR ($item.Message -like "*get-aduser*") -OR ($item.Message -like "*query user*") -AND ($item.Message -notlike "*/server:localhost*"))))))))))) {	
			$Technique = 'T1107'
			$Threat = "Defense_Evasion - File Deletion"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net* view*") -OR ($item.Message -like "*net* share*") -OR ($item.Message -like "*get-smbshare -Name*")))) {	
			$Technique = 'T1135'
			$Threat = "Discovery - Network Share Discovery - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*New-LocalUser*") -AND ($item.Message -like "*net*user*add*")) {	
			$Technique = 'T1136'
			$Threat = "Persistence - Create Account"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*AppData\Roaming\Microsoft\Windows\\PowerShell\PSReadline\ConsoleHost_history.txt*") -OR ($item.Message -like "*(Get-PSReadlineOption).HistorySavePath*")) {	
			$Technique = 'T0000'
			$Threat = "Collection - Console History"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*certutil.exe*") -AND ($item.Message -like "*decode*")) {	
			$Technique = 'T1140'
			$Threat = "Defense_Evasion - Deobfuscate/Decode Files or Information"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*certutil.exe*") -AND ($item.Message -like "*encode*")) {	
			$Technique = 'T1027'
			$Threat = "Defense_Evasion - Obfuscated Files or Information"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*rm (Get-PSReadlineOption).HistorySavePath*") -OR ($item.Message -like "*del (Get-PSReadlineOption).HistorySavePath*") -OR ($item.Message -like "*Set-PSReadlineOption *HistorySaveStyle SaveNothing*") -OR ($item.Message -like "*Remove-Item (Get-PSReadlineOption).HistorySavePath*")))) {	
			$Technique = 'T1146'
			$Threat = "Collection - Clear Command History"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*attrib.exe*") -AND ($item.Message -like "*+h*") -OR ($item.Message -like "*+s*"))) {	
			$Technique = 'T1158'
			$Threat = "Persistence,Defense_Evasion - Hidden Files and Directories"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*mavinject.exe*") -AND ($item.Message -like "*/INJECTRUNNING*")) {	
			$Technique = 'T1179'
			$Threat = "Persistence,Privilege_Escalation,Credential_Access - Hooking"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*bitsadmin.exe*") -AND ($item.Message -like "*Start-BitsTransfer*")) {	
			$Technique = 'T1197'
			$Threat = "Persistence,Defense_Evasion - BITS Jobs - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*pcalua.exe*") -OR ($item.Message -like "*bash.exe*")-OR ($item.Message -like "*forfiles.exe*"))) {	
			$Technique = 'T1202'
			$Threat = "Discovery - Indirect Command Execution"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*firefox*places.sqlite*") -OR ($item.Message -like "*bookmarks*")) {	
			$Technique = 'T1217'
			$Threat = "Discovery - Browser Bookmark Discovery"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*hh.exe*") {	
			$Technique = 'T1223'
			$Threat = "Defense_Evasion,Execution - Compiled HTML File"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((($item.Message -like "*wsmprovhost.exe*") -OR ($item.Message -like "*winrm.cmd*") -OR ($item.Message -like "*Enable-PSRemoting -Force*") -OR ($item.Message -like "*Invoke-Command -computer_name*") -OR ($item.Message -like "*wmic*node*process call create*"))))) {	
			$Technique = 'T1028'
			$Threat = "Lateral_Movement,Execution - Windows Remote Management"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ($item.Message -like "*REG*ADD*HKCU\Environment\*") {	
			$Technique = 'T1037'
			$Threat = "Lateral_Movement,Persistence - Logon Scripts"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*tshark.exe*") -OR ($item.Message -like "*windump.exe*") -OR ($item.Message -like "*logman.exe*") -OR ($item.Message -like "*tcpdump.exe*") -OR ($item.Message -like "*wprui.exe*") -OR ($item.Message -like "*wpr.exe*")))))) {	
			$Technique = 'T1040'
			$Threat = "Credential_Access,Discovery - Network Sniffing"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*sc.exe*") -OR ($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*cmd.exe*") -AND ($item.Message -like "*sc*config*")))) {	
			$Technique = 'T1031'
			$Threat = "Persistence - Modify Existing Service"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*sc.exe*") -OR ($item.Message -like "*powershell.exe*") -OR ($item.Message -like "*cmd.exe*") -AND ($item.Message -like "*New-Service*BinaryPathName*") -OR ($item.Message -like "*sc*create*binpath*") -OR ($item.Message -like "*Get-WmiObject*Win32_Service*create*")))))) {	
			$Technique = 'T1050'
			$Threat = "Persistence,Privilege_Escalation,Execution - New Service - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*Invoke-DllInjection*") -OR ($item.Message -like "*c:\windows\sysnative\*")) {	
			$Technique = 'T1055'
			$Threat = "Privilege_Escalation,Defense_Evasion - Process Injection - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((((((((((((((((((((((((((((((((((((((((($item.Message -like "*smss.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*csrss.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*wininit.exe*") -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*winlogon.exe*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*")  -AND ($item.Message -notlike "*ParentImage*smss.exe*") -OR ($item.Message -like "*lsass.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*LogonUI.exe*") -AND ($item.Message -notlike "*ParentImage*winlogon.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*services.exe*") -AND ($item.Message -notlike "*ParentImage*wininit.exe*") -OR ($item.Message -like "*spoolsv.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*") -OR ($item.Message -like "*taskhost.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*") -AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*taskhostw.exe*") -AND ($item.Message -notlike "*ParentImage*services.exe*")-AND ($item.Message -notlike "*ParentImage*svchost.exe*") -OR ($item.Message -like "*userinit.exe*") -AND ($item.Message -notlike "*dwm.exe*") -AND ($item.Message -notlike "*ParentImage*winlogon.exe*") -OR ($item.Message -notlike "*taskhostw*") -OR ($item.Message -notlike "*backgroundTaskHost*") -OR ($item.Message -notlike "*conhost*") -OR ($item.Message -notlike "*MittreAttackChecker*.ps1*") -AND ($item.Message -notlike "*ParentCommandLine*svchost.exe -k netsvcs -p -s Schedule*") -AND ($item.Message -notlike "*MicrosoftOfficeHub*") -AND ($item.Message -notlike "*TiWorker.exe*") -AND ($item.Message -notlike "*TrustedInstaller*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s BITS*") -AND ($item.Message -notlike "*/server:localhost*")-AND ($item.Message -notlike "*C:\Windows\System32\usocoreworker.exe -Embedding*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\vssvc.exe*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s gpsvc*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*quser.exe*") -AND ($item.Message -notlike "*query.exe*")-AND ($item.Message -notlike "*GoToMeeting*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*")))))))))))))))))))))))))))))))))))))))))))))) {		
			$Technique = 'T1093' 
			$Threat = "Defense_Evasion - Process Hollowing"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((($item.Message -like "*regsvr32.exe*") -OR ($item.Message -like "*rundll32.exe*") -OR ($item.Message -like "*certutil.exe*"))) {	
			$Technique = 'T1117'
			$Threat = "Defense_Evasion - Bypassing Application Whitelisting with Regsvr32"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((((((((((((((($item.Message -like "*powershell.exe*") -AND ($item.Message -notlike "*MittreAttackChecker*") -AND ($item.Message -notlike "*__PSScriptPolicyTest*") -OR ($item.Message -like "*-Recurse | Compress-Archive*") -OR ($item.Message -like "*rar.exe*") -OR ($item.Message -like "*rar*a**") -OR ($item.Message -like "*7z.exe*") -OR ($item.Message -like "*zip.exe*") -OR ($item.Message -notlike "*MittreAttackChecker*") -OR ($item.Message -notlike "*TiWorker*") -OR ($item.Message -notlike "*TrustedInstaller*") -OR ($item.Message -notlike "*taskhostw*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s Schedule*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s BITS*") -AND ($item.Message -notlike "*/server:localhost*") -AND ($item.Message -notlike "*MicrosoftOfficeHub*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*") -AND ($item.Message -notlike "*C:\Windows\System32\usocoreworker.exe -Embedding*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\vssvc.exe*")-AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s gpsvc*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*TiWorker.exe*") -AND ($item.Message -notlike "*C:\WINDOWS\servicing\TrustedInstaller.exe*"))))))))))))))))))))))) {	
			$Technique = 'T1002'
			$Threat = "Exfiltration - Data Compressed"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((((((((((((((((((((((((((((((((($item.Message -like "*\a.exe*") -OR ($item.Message -like "*\b.exe*") -OR ($item.Message -like "*\c.exe*") -OR ($item.Message -like "*\d.exe*") -OR ($item.Message -like "*\e.exe*") -OR ($item.Message -like "*\f.exe*") -OR ($item.Message -like "*\g.exe*") -OR ($item.Message -like "*\h.exe*") -OR ($item.Message -like "*\i.exe*") -OR ($item.Message -like "*\j.exe*") -OR ($item.Message -like "*\k.exe*") -OR ($item.Message -like "*\l.exe*") -OR ($item.Message -like "*\m.exe*") -OR ($item.Message -like "*\n.exe*") -OR ($item.Message -like "*\o.exe*") -OR ($item.Message -like "*\p.exe*") -OR ($item.Message -like "*\q.exe*") -OR ($item.Message -like "*\r.exe*") -OR ($item.Message -like "*\s.exe*") -OR ($item.Message -like "*\t.exe*") -OR ($item.Message -like "*\u.exe*") -OR ($item.Message -like "*\w.exe*") -OR ($item.Message -like "*\v.exe*")-OR ($item.Message -like "*\x.exe*") -OR ($item.Message -like "*\y.exe*") -OR ($item.Message -like "*\z.exe*") -OR ($item.Message -like "*\1.exe*") -OR ($item.Message -like "*\2.exe*") -OR ($item.Message -like "*\3.exe*") -OR ($item.Message -like "*\4.exe*") -OR ($item.Message -like "*\5.exe*") -OR ($item.Message -like "*\6.exe*") -OR ($item.Message -like "*\7.exe*") -OR ($item.Message -like "*\8.exe*") -OR ($item.Message -like "*\9.exe*") -OR ($item.Message -like "*\10.exe*")))))))))))))))))))))))))))))))))))) {		
			$Technique = 'T0000' 
			$Threat = "Execution - Suspicious filename used"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((((($item.Message -like "*.doc.*") -OR ($item.Message -like "*.docx.*") -OR ($item.Message -like "*.xls.*") -OR ($item.Message -like "*.xlsx.*") -OR ($item.Message -like "*.pdf.*") -OR ($item.Message -like "*.rtf.*") -OR ($item.Message -like "*.jpg.*") -OR ($item.Message -like "*.png.*") -OR ($item.Message -like "*.jpeg.*") -OR ($item.Message -like "*.zip.*") -OR ($item.Message -like "*.rar.*") -OR ($item.Message -like "*.ppt.*") -OR ($item.Message -like "*.pptx.*"))))))))))))) {	
			$Technique = 'T1036' 
			$Threat = "Defense_Evasion - Masquerading - Extension"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "\\*\Volume*") -OR ($item.Message -like "*\\*\GLOBALROOT\Device\HarddiskVolumeShadowCopy*")) {	
			$Technique = 'T1158'
			$Threat = "Defense_Evasion,Persistence - Hidden Files and Directories - VSS"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
# Review ! How to add process path ?

	"1"	{		
		$Result = if ($item.Message -like "") {	
			$Technique = 'T1093'
			$Threat = "Defense_Evasion - Process Hollowing - commandline"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((((($item.Message -like "*winword.exe*") -OR ($item.Message -like "*excel.exe*") -OR ($item.Message -like "*outlook.exe*") -OR ($item.Message -like "*C:\\Program Files\Microsoft Office\*-enc*") -OR ($item.Message -like "*C:\\Program Files (x86)\Microsoft Office\*-enc*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*")))))) {	
			$Technique = 'T1093'
			$Threat = "Defense_Evasion - Process Hollowing - office commandline"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (((($item.Message -like "*netsh.exe*") -OR ($item.Message -like "*trace*start*capture=yes*") -OR ($item.Message -like "*tshark.exe*") -OR ($item.Message -like "*wireshark.exe*")))) {	
			$Technique = 'T1040'
			$Threat = "Credential_Access,Discovery - Network Sniffing - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if ((((((((((((((($item.Message -like "*svchost.exe*") -AND ($item.Message -notlike "*services.exe*") -OR ($item.Message -like "*scvhost.exe*") -AND ($item.Message -notlike "*MittreAttackChecker*") -AND ($item.Message -notlike "*__PSScriptPolicyTest*") -OR ($item.Message -notlike "*taskhostw*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s Schedule*") -AND ($item.Message -notlike "*TiWorker*") -AND ($item.Message -notlike "*/server:localhost*") -AND ($item.Message -notlike "*MicrosoftOfficeHub*") -AND ($item.Message -notlike "*AttackCheckerInfoSec*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s BITS* *services.exe*") -AND ($item.Message -notlike "*GoToMeeting*") -AND ($item.Message -notlike "*svchost.exe -k netsvcs -p -s wuauserv*") -AND ($item.Message -notlike "*C:\WINDOWS\servicing\TrustedInstaller.exe*"))))))))))))))) {	
			$Technique = 'T1036'
			$Threat = "Defense_Evasion - Masquerading - svchost"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{		
		$Result = if (($item.Message -like "*explorer.exe*") -AND ($item.Message -notlike "*userinit.exe*")) {	
			$Technique = 'T1036'
			$Threat = "Defense_Evasion - Masquerading - explorer"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"1"	{
		$OriginalFileName = $item.Message -like "*OriginalFileName:*"
		$Image = $item.Message -like "*Image:*"
		$Result = if ("$OriginalFileName" -notlike "$Image") {	
			$Technique = 'T1036'
			$Threat = "Defense_Evasion - Masquerading - renamedbin"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"3"	{		
		$Result = if ($item.Message -like "*qwinsta.exe*") { 	
			$Technique = 'T0000'
			$Threat = "Discovery - Remotely Query Login Sessions - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"3"	{		
		$Result = if (($item.Message -like "*net.exe*") -OR ($item.Message -like "*net1.exe*")) { 	
			$Technique = 'T1069'
			$Threat = "Discovery - Permission Groups Discovery - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -like "*net* view*") -OR ($item.Message -like "*net* share*")) { 	
			$Technique = 'T1135'
			$Threat = "Discovery - Network Share Discovery - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -like "*net.exe*") -OR ($item.Message -like "*ping.exe*")) { 	
			$Technique = 'T1018'
			$Threat = "Discovery - Remote System Discovery - Network"
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (((($item.Message -like "*tscon.exe*") -OR ($item.Message -like "*mstsc.exe*") -OR ($item.Message -like "*dst_port=3389*") -AND ($item.Message -like "*initiated=true*")))) { 	
			$Technique = 'T1076'
			$Threat = "Lateral Movement - Remote Desktop Protocol - Network"
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (((($item.Message -like "*net.exe*") -AND ($item.Message -like "*net use*") -OR ($item.Message -like "*net session*") -OR ($item.Message -like "*net file*")))) { 	
			$Technique = 'T1077'
			$Threat = "Lateral Movement - Windows Admin Shares - Network"
			$Threat = "Execution - Windows Management Instrumentation - Process"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -like "*wmic.exe*") -OR ($item.Message -like "*wmic*")) { 	
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -like "*wmic.exe*") -OR ($item.Message -like "*wmic*")) { 	
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ($item.Message -like "*\regsvr32.exe*") { 	
			$Technique = 'T1047'
			$Threat = "Defense_Evasion,Execution - Regsvr32 - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{	
		$Result = if ((((((((($item.Message -like "*msiexec.exe /q /i*") -OR ($item.Message -like "*msiexec.exe /q /i http*") -OR ($item.Message -like "*msiexec.exe /y *.dll") -OR ($item.Message -like "*MavInject32.exe * /INJECTRUNNING*") -OR ($item.Message -like "*SyncAppvPublishingServe.vbs*") -OR ($item.Message -like "*manage-bde.wsf*") -OR ($item.Message -like "*odbcconf.exe /S /A {REGSVR*.dll") -OR ($item.Message -like "*certutil.exe*") -OR ($item.Message -like "*certutil*script*http*") -OR ($item.Message -like "*\replace.exe*"))))))))) {		
			$Technique = 'T1218'
			$Threat = "Defense_Evasion,Execution - Signed Binary Proxy Execution - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ($item.Message -like "*bitsadmin.exe*") { 	
			$Technique = 'T1197'
			$Threat = "Persistence,Defense_Evasion - BITS Jobs - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -notlike "*Started*") -AND ($item.Message -like "*Sysmon*")) { 	
			$Technique = 'T1089'
			$Threat = "Defense_Evasion - Disabling Security Tools - Sysmon service state change"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ((($item.Message -like "*C:\\Users\*") -OR ($item.Message -like "*C:\Windows\Temp\*") -OR ($item.Message -like "*C:\Temp\**"))) { 	
			$Technique = 'T0000'
			$Threat = "Lateral_Movement,Execution - Connections from Uncommon Locations"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ((((((((((($item.Message -like "*DestinationPort: 22*") -OR ($item.Message -like "*DestinationPort: 23*") -OR ($item.Message -like "*DestinationPort: 25*") -OR ($item.Message -like "*DestinationPort: 135*") -OR ($item.Message -like "*DestinationPort: 3389*") -OR ($item.Message -like "*DestinationPort: 5800*") -OR ($item.Message -like "*DestinationPort: 5900*") -OR ($item.Message -like "*DestinationPort: 8080*") -OR ($item.Message -like "*DestinationPort: 5985*") -OR ($item.Message -like "*DestinationPort: 5986*")-AND ($item.Message -like "*Inititated: true*"))))))))))) { 	
			$Technique = 'T1043'
			$Threat = "Command_and_Control - Commonly Used Port"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if (($item.Message -like "*reg.exe*") -OR ($item.Message -like "*reg query*")) { 	
			$Technique = 'T1012'
			$Threat = "Discovery - Query Registry - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ($item.Message -like "*\mshta.exe*") { 	
			$Technique = 'T1170'
			$Threat = "Defense_Evasion,Execution - MSHTA - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"3"	{		
		$Result = if ((((($item.Message -like "*DestinationPort: 389*") -OR ($item.Message -like "*DestinationPort: 636*") -OR ($item.Message -like "*DestinationPort: 445*") -OR ($item.Message -like "*DestinationPort: 8080*") -AND ($item.Message -notlike "*C:\Program Files\HP*"))))) {
			$Technique = 'T1033'
			$Threat = "Discovery - System Owner/User Discovery - Network"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"6"	{		
		$Result = if (($item.Message -like "*ImageLoaded*\Temp\*") -OR ($item.Message -like "*ImageLoaded*C:\Users\*") -OR ($item.Message -notlike "*SignatureStatus*Valid*")) { 	
			$Technique = 'T1044'
			$Threat = "Persistence,Privilege_Escalation - File System Permissions Weakness"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
	"7"	{		
		$Result = if (((((((($item.Message -like "*C:\Windows\System32\samlib.dll*") -OR ($item.Message -like "*C:\Windows\System32\WinSCard.dll*") -OR ($item.Message -like "C:\Windows\System32\cryptdll.dll*") -OR ($item.Message -like "*C:\Windows\System32\hid.dll*") -OR ($item.Message -like "*C:\Windows\System32\vaultcli.dll") -OR ($item.Message -notlike "*\Sysmon.exe*") -OR ($item.Message -notlike "*\svchost.exe*") -OR ($item.Message -notlike "*\logonui.exe*")))))))) { 	
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping ImageLoad"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"7"	{		
		$Result = if ($item.Message -like "*0x*0B80*") { 	
			$Technique = 'T1073'
			$Threat = "Privilege_Escalation,Defense_Evasion - Process Injection - CobaltStrike"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"7"	{		
		$Result = if ((((($item.Message -like "*\System.Management.Automation.ni.dll*") -OR ($item.Message -like "*\System.Management.Automation.dll*") -OR ($item.Message -like "*\PowerShdll.dll*") -AND ($item.Message -notlike "*powershell.exe*") -OR ($item.Message -like "*powershell_ise.exe*"))))) { 	
			$Technique = 'T1073'
			$Threat = "Defense_Evasion - DLL Side-Loading - PowerShell"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"7"	{		
		$Result = if (($item.Message -like "*wmiutils.dll*") -OR ($item.Message -like "*C:\Windows\*")) { 	
			$Technique = 'T1073'
			$Threat = "Defense_Evasion - DLL Side-Loading - WMI"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"10"	{		
		$Result = if (((((((($item.Message -like "*C:\Windows\system32\lsass.exe*") -AND ($item.Message -like "*0x1010*") -OR ($item.Message -like "*0x1410*") -OR ($item.Message -like "*0x147a*") -OR ($item.Message -like "*0x143a") -OR ($item.Message -like "*C:\Windows\SYSTEM32\ntdll.dll\*") -OR ($item.Message -like "*C:\\Windows\\system32\\KERNELBASE.dll*") -OR ($item.Message -like "*UNKNOWN(*)*")))))))) { 	
			$Technique = 'T1003'
			$Threat = "Potentially Mimikatz - Credential Dumping - Process Access"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
	
	# Review ! 
	"11"	{		
		$Result = if ((((((($item.Message -notlike "*C:\WINDOWS\system32\svchost.exe*") -OR ($item.Message -like "*C:\Windows\System32\Tasks\*") -OR ($item.Message -like "*C:\Windows\Tasks\*") -AND ($item.Message -notlike "*C:\WINDOWS\System32\WindowsPowerShell\v1.0\Powershell.EXE -ExecutionPolicy bypass *MittreAttackChecker*.ps1*") -AND ($item.Message -notlike "*_PSScriptPolicyTest*.ps*") -AND ($item.Message -notlike "*notepad++.exe*") -AND ($item.Message -notlike "*C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator*"))))))) { 	
			$Technique = 'T1053'
			$Threat = "Persistence,Privilege_Escalation,Execution - Scheduled Task - FileAccess"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$3"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if ($item.Message -like "*C:\WINDOWS\system32\wbem\scrcons.exe*") { 	
			$Technique = 'T1047'
			$Threat = "Execution - Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"11"	{		
		$Result = if (($item.Message -like "*.lnk") -OR ($item.Message -like "*.scf")) { 	
			$Technique = 'T1187'
			$Threat = "Credential_Access - Forced Authentication"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if ($item.Message -like "*C:\Windows\AppPatch\Custom\*") { 	
			$Technique = 'T1138'
			$Threat = "Persistence,Privilege_Escalation - Application Shimming - FileAccess"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if (((((((((((((((($item.Message -like "*TargetFilename*SysWOW64*") -OR ($item.Message -like "*TargetFilename*System32*") -OR ($item.Message -like "*TargetFilename*AppData*") -OR ($item.Message -like "*TargetFilename*.exe*") -OR ($item.Message -like "*TargetFilename**.dll*") -OR ($item.Message -like "*TargetFilename*.bat*") -OR ($item.Message -like "*TargetFilename*.com*") -OR ($item.Message -like "*TargetFilename*.ps1*") -OR ($item.Message -like "*TargetFilename*.py*") -OR ($item.Message -like "*TargetFilename*.js*") -OR ($item.Message -like "*TargetFilename*.vbs*") -OR ($item.Message -like "*TargetFilename*.hta*") -AND ($item.Message -notlike "*MittreAttackChecker*") -AND ($item.Message -notlike "*__PSScriptPolicyTest*") -AND ($item.Message -notlike "*C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator*")))))))))))))))) { 	
			$Technique = 'T1036' 
			$Threat = "Defense_Evasion - Masquerading - Location"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if ((((((((((((((((((((((($item.Message -like "*TargetFilename*.docm*") -OR ($item.Message -like "*TargetFilename*.xlsm*") -OR ($item.Message -like "*TargetFilename*.pptm*") -OR ($item.Message -like "*TargetFilename*.ps1*") -AND ($item.Message -notlike "*MittreAttackChecker*") -AND ($item.Message -notlike "*__PSScriptPolicyTest*") -OR ($item.Message -like "*TargetFilename**.py*") -OR ($item.Message -like "*TargetFilename*.js*") -OR ($item.Message -like "*TargetFilename*.vbs*") -OR ($item.Message -like "*TargetFilename*.hta*") -OR ($item.Message -like "*TargetFilename*.bat*") -OR ($item.Message -like "*TargetFilename*.slk*") -OR ($item.Message -like "*TargetFilename*.jspx*") -OR ($item.Message -like "*TargetFilename*.cmd*") -OR ($item.Message -like "*TargetFilename**.php*") -OR ($item.Message -like "*TargetFilename*.pyw*") -OR ($item.Message -like "*TargetFilename*.xla*") -OR ($item.Message -like "*TargetFilename*.application*") -OR ($item.Message -like "*TargetFilename*.potm*") -OR ($item.Message -like "*TargetFilename*.csproj*") -OR ($item.Message -like "*TargetFilename*.aspx*") -OR ($item.Message -like "*TargetFilename**.exe*") )))))))))))))))))))))) { 	
			$Technique = 'T1193'
			$Threat = "Initial_Access - Spearphishing Attachment"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if ($item.Message -like "*\AppData\Local\Microsoft\CLR_v2.0*\UsageLogs\*") { 	
			$Technique = 'T1127'
			$Threat = "Defense_Evasion,Execution - Trusted Developer Utilities - net2"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"11"	{		
		$Result = if (((((((((($item.Message -like "*.zip*") -OR ($item.Message -like "*.rar*") -OR ($item.Message -like "*.arj*") -OR ($item.Message -like "*.gz*") -OR ($item.Message -like "*.tar*") -OR ($item.Message -like "*.tgz*") -OR ($item.Message -like "*.7z*") -OR ($item.Message -like "*.zip*") -OR ($item.Message -like "*.tar.gz*") -OR ($item.Message -like "*.bin*")))))))))) { 	
			$Technique = 'T1002'
			$Threat = "Exfiltration - Data Compressed - Files"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"11,15"	{		
		$Result = if ($item.Message -like "*.hta*") { 	
			$Technique = 'T1170'
			$Threat = "Defense_Evasion,Execution - MSHTA - FileAccess"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"12,13,14"	{		
		$Result = if (($item.Message -like "*\SYSTEM\\CurrentControlSet\Control\Lsa\Security Packages*") -or ("*\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages*")) { 
			$Technique = 'T1101'
			$Threat = "Persistence - Security Support Provider - LSA Attack"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (($item.Message -like "*C:\Windows\system32\LogonUI.exe*") -or ("*\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\*")) { 
			$Technique = 'T1076'
			$Threat = "Lateral_Movement - Remote Desktop Protocol - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\System\CurrentControlSet\Services\W32Time\TimeProviders\*") { 
			$Technique = 'T1209'
			$Threat = "Discovery - Time Providers"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\SYSTEM\CurrentControlSet\Control\Print\Monitors\*") { 
			$Technique = 'T1013'
			$Threat = "Persistence,Privilege_Escalation - Local Port Monitor"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (($item.Message -like "*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\*") -OR ($item.Message -like "*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\*")) { 
			$Technique = 'T1103'
			$Threat = "Persistence,Privilege_Escalation - AppInit DLLs"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\Software\Classes\\CLSID\*") { 
			$Technique = 'T1122'
			$Threat = "Persistence,Defense_Evasion - Component Object Model Hijacking"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*") { 
			$Technique = 'T1138'
			$Threat = "Persistence,Privilege_Escalation - Application Shimming - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\System\CurrentControlSet\Control\Session Manager\AppCertDlls\*") { 
			$Technique = 'T1182'
			$Threat = "Persistence,Privilege_Escalation - AppCert DLLs"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -like "*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace*") -OR ($item.Message -like "*\Software\Microsoft\Windows\CurrentVersion\Controls Folder\*\Shellex\PropertySheetHandlers\*") -OR ($item.Message -like "*\Software\Microsoft\Windows\CurrentVersion\Control Panel\*"))) { 
			$Technique = 'T1196'
			$Threat = "Defense_Evasion,Execution - Control Panel Items - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -like "*\SYSTEM\CurrentControlSet\\Control\Lsa\*") -AND ($item.Message -notlike "*C:\WINDOWS\system32\lsass.exe*") -OR ($item.Message -notlike "*C:\\Windows\\system32\\svchost.exe*") -OR ($item.Message -notlike "*C:\Windows\system32\services.exe*"))) { 
			$Technique = 'T1131'
			$Threat = "Persistence - Authentication Package"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -like "*\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider\*") -AND ($item.Message -like "*\SYSTEM\CurrentControlSet\Control\Lsa\*") -OR ($item.Message -like "*\SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders\*") -OR ($item.Message -like "*\Control\SecurityProviders\WDigest\*") -OR ($item.Message -notlike "*\Lsa\RestrictRemoteSamEventThrottlingWindow*"))) { 
			$Technique = 'T1003'
			$Threat = "Credential_Access - Credential Dumping - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "*\SOFTWARE\Microsoft\Netsh\*") { 
			$Technique = 'T1128'
			$Threat = "Persistence - Netsh Helper DLL - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -like "*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\user_nameinit\*") -OR ($item.Message -like "*\SOFTWARE\\Microsoft\Windows NT\currentVersion\Winlogon\Shell\*") -OR ($item.Message -like "*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*"))) { 
			$Technique = 'T1004'
			$Threat = "Persistence - Winlogon Helper DLL"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -like "HKLM\System\CurrentControlSet\Services\SysmonDrv\*") -OR ($item.Message -like "HKLM\System\CurrentControlSet\Services\Sysmon\*") -OR ($item.Message -like "HKLM\System\CurrentControlSet\Services\Sysmon64\*"))) { 
			$Technique = 'T1054'
			$Threat = "Defense_Evasion - Indicator Blocking - Sysmon registry edited from other source"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ($item.Message -like "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*") { 
			$Technique = 'T1015'
			$Threat = "Persistence,Privilege_Escalation - Accessibility Features - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (($item.Message -like "*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*") -OR ($item.Message -like "*\Software\\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders*")) { 
			$Technique = 'T1060'
			$Threat = "Persistence - Registry Run Keys or Start Folder"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if ((($item.Message -notlike "*svchost.exe*") -AND ($item.Message -like "*\SOFTWARE\\Microsoft\EnterpriseCertificates\Root\Certificates\*") -OR ($item.Message -like "*\Microsoft\SystemCertificates\Root\Certificates\*"))) { 
			$Technique = 'T1130'
			$Threat = "Defense_Evasion - Install Root Certificate"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (($item.Message -like "*\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*") -OR ($item.Message -like "*\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*")) { 
			$Technique = 'T1183'
			$Threat = "Persistence,Privilege_Escalation - Image File Execution Options Injection"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (($item.Message -like "*\SOFTWARE\Classes\*\*") -OR ($item.Message -like "*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\GlobalAssocChangedCounter*")) { 
			$Technique = 'T1042'
			$Threat = "Persistence - Change Default File Association"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (((($item.Message -like "*\Control Panel\Desktop\SCRNSAVE.EXE*") -AND ($item.Message -notlike "*explorer.exe*") -OR ($item.Message -notlike "*rundll32.exe*") -OR ($item.Message -notlike "*shell32.dll,Control_RunDLL desk.cpl,ScreenSaver,*")))) { 
			$Technique = 'T1180'
			$Threat = "Persistence - Screensaver"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$2"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"12,13,14"	{		
		$Result = if (((((($item.Message -like "*\mscfile\shell\open\command\*") -OR ($item.Message -like "*\ms-settings\shell\open\command\*") -OR ($item.Message -like "*rundll32.exe*") -AND ($item.Message -notlike "*S-1-5-18*") -OR ($item.Message -notlike "*S-1-5-19*") -OR ($item.Message -notlike "*S-1-5-20*")))))) { 
			$Technique = 'T1088'
			$Threat = "Privilege_Escalation,Defense_Evasion - Bypass User Account Control - Registry"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"13"	{		
		$Result = if (($item.Message -like "HKU\*\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup") -AND ($item.Message -like "*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*") ) { 
			$Technique = 'T1060'
			$Threat = "Persistence - Registry Run Keys or Start Folder - Folder Changed"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"13"	{		
		$Result = if (($item.Message -like "*trustrecords*") -AND ($item.Message -like "*TargetObject=*Software\Microsoft\VBA\7.1\Common*") ) { 
			$Technique = 'T1193'
			$Threat = "Initial_Access - Spearphishing Attachment - Opened"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"16"	{		
		$Result = if ((($item.Message -like "*sysmon *c *.xml*") -OR ($item.Message -like "*sysmon *c *") -OR ($item.Message -like "*sysmon *s*"))) { 
			$Technique = 'T1054'
			$Threat = "Defense_Evasion - Indicator Blocking - Unknown Sysmon Config loaded"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"17"	{		
		$Result = if ($item.Message -like "*msagent_*") { 
			$Technique = 'T0000'
			$Threat = "Lateral_Movement - Named Pipes - CobaltStrike"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}

	"17"	{		
		$Result = if (((((((((((((((($item.Message -like "*isapi_http*") -OR ($item.Message -like "*isapi_dg*") -OR ($item.Message -like "*isapi_dg2*") -OR ($item.Message -like "*isapi_http*") -OR ($item.Message -like "*sdlrpc*") -OR ($item.Message -like "*aheec*") -OR ($item.Message -like "*winsession*") -OR ($item.Message -like "*lsassw*") -OR ($item.Message -like "*rpchlp_3*") -OR ($item.Message -like "*NamePipe_MoreWindows*") -OR ($item.Message -like "*pcheap_reuse*") -OR ($item.Message -like "*PSEXESVC*") -OR ($item.Message -like "*PowerShellISEPipeName_*") -OR ($item.Message -like "*csexec*") -OR ($item.Message -like "*paexec*") -OR ($item.Message -like "*remcom*")))))))))))))))) { 
			$Technique = 'T0000'
			$Threat = "Lateral_Movement - Named Pipes"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
		
	"20"	{		
		$Result = if ($item.Message -like "*Command Line*") { 
			$Technique = 'T1047'
			$Threat = "Lateral_Movement - WMI command execution"
			$URL = "https://attack.mitre.org/techniques/$Technique/" 
			$Severity = "$1"
					$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $username
												'ID3' = $item.ID
												'ID4' = $item.TimeCreated
												'ID5' = $item.Message
												'ID6' = $Threat
												'ID7' = $URL 
		 										'ID8' = $Severity
													}
					$PSObjectQuery
				# End Result 
				}
				$Result | fl *
		if ($Result -ne $Null) { $Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Out-File -Append $HTMLReportFile } 
		if ($CSVExport -eq "Yes") { $Result | Select-Object ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8 | Export-CSV -Path $CSVReportFile -NoTypeInformation -Append }
		# End ID
		}
	
	# End Switch
	}
# End ForEach	
}

#### Internal Mail Function ###




Function InternalMailReport() {

	# If Client & Server does not have the same TLS Certificate and the client is not domain joined: credentials are needed:
		
		# Adjust ToDo
		$SMTPServer = "srv1ad.home.local"
		$SMTPPort = "587"
		
	$Content = Get-Content "$HTMLReportFile" | Out-String
	
	if ($DomainJoinedAndCA -eq "Yes") {
		write-host "If SMTP Server is confiured for TLS Certificate, Sending mail on Port 587" -ForegroundColor yellow

Send-MailMessage -BodyAsHTML -From $sendFrom -to $sendTo -Subject $Subject -Body $Content -priority high -SmtpServer $SMTPServer -port $SMTPPort -UseSsl
	}
	else 
	{
	write-host "Your are not domain joined or do not have a TLS Certificate on Server and client + Credentials Needed" -ForegroundColor yellow 
Send-MailMessage -BodyAsHTML -From $sendFrom -to $sendTo -Subject $Subject -Body $Content -priority high -SmtpServer $SMTPServer -port $SMTPPort -Credential $smtpcred -UseSsl
	}
	write-host "You've send a Security Report to your IT-Admins" -ForegroundColor green
}

if (($InternalMailReport -eq "Yes") -and ($AtWork -eq "$True")) {

	# Summary
	$size = ((Get-Item $HTMLReportFile).length)
	Write-Host "Report Size is: $size" -foregroundcolor green
	If ($size -ge "2000") 	{
								InternalMailReport
									Write-Host "Internal Mail report enabled and user at work: sending..." -ForegroundColor green
							}
							else
							{
									Write-Host "Internal Mail report not enabled or user is not at work" -ForegroundColor yellow
									Write-Host "Mail Report should not be sent because it's under the threshold of 2000" -Foregroundcolor green
									Write-Host "Deleting obsolete report" -Foregroundcolor yellow
								
								Remove-Item $HTMLReportFile
							}
						}

#### Exterrnal Mail Function ###

Function ExternalMailReport() {

		# Save the report out to a file in the current path

$Attachment = New-Object Net.Mail.Attachment("$HTMLReportFile")
$Attachment.ContentDisposition.Inline = $True
$Attachment.ContentDisposition.DispositionType = "Inline"
$Attachment.ContentType.MediaType = "text/html"

$MailMessage = New-Object System.Net.Mail.SmtpClient($SmtpServer, 587)
$MailMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$Body)
$MailMessage.IsBodyHtml = $True
$MailMessage.Attachments.Add($Attachment)

$MailMessage.Body = "
  <html>
    <head></head>
    <body>
      <iframe='CID:$($Attachment.ContentId)' />
    </body>
  </html>"

$SmtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, 587)
$SmtpClient.EnableSsl = $true
$SmtpClient.Credentials = New-Object System.Net.NetworkCredential( $GmailUsername , $GmailAppPassword )
$SmtpClient.Send($MailMessage)
}

if (($ExternalMailReport -eq "Yes") -and ($AtWork -eq "$False")) {

	# Summary
	$size = ((Get-Item $HTMLReportFile).length)
	write-host "Report Size is: $size" -foregroundcolor green
	If ($size -ge "2000") 	{
								ExternalMailReport
									write-host "External Mail report enabled and user not at work." -ForegroundColor green
									write-host "You've send a Security Report to your IT-Admins" -ForegroundColor green
							}
							else
							{
									write-host "External Mail report not enabled or user is at work." -ForegroundColor yellow
							}
						}


							

##############################################################################
# Complete the report and output
##############################################################################

	# Determine the execution duration
$Duration = New-Timespan -start $Time -end ((Get-Date).ToUniversalTime())

# Print report location and finish execution

If (Test-Path $HTMLReport) {
						"[+] FILE:`t$HTMLReportFile"
						"[+] FILESIZE:`t$((Get-Item $HTMLReportFile).length) Bytes"
						
						"[+] FILE:`t$exportlocation"
						"[+] FILESIZE:`t$((Get-Item $exportlocation).length) Bytes"
						} else 	{
					"[+] Report Deleted because of no Result"	
					"[+] DURATION:`t$Duration"
					"[+] MittreAttackCheckerInfoSecPSSecuritySysMon.ps1 complete!"
								}
##############################################################################
# The END
##############################################################################