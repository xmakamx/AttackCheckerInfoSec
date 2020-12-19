##########################################################################################
# AttackCheckerInfoSec.ps1								 #
# version 1.2										 #
# Changes to initial: SysMon Functionality + Rewrite code for multiple checks		 #
# Written on: 07/11/2019 - Finished on 07/16/2019					 #
# In honor to Black Hills InfoSec Attack Tactics					 #
# The extra files can be filled with event IDs and KeyWords for scanning events		 #
# The Goal is to pull / assemble it of/from Mitre: https://attack.mitre.org/		 #
# Disclaimer: You will be notified if configured ok, but the thread will not be stopped! #
# Test-Environment DURATION:   00:00:09.7632987						 #
##########################################################################################

# Run First: New-Item -ItemType "file" -Path "$PWD\Sysmon-Setup.txt" -Value "User is requesting the installation of SysMon"

# Interval on Queries



$Server = 'ZAKELIJK'
$Share = 'LogFiles'
$Date = (Get-Date).ToString('yyyyMMdd-HHmmss')
$PC = $env:computername
$User = $env:username
$exportlocation = "\\$Server\$Share\$Date-$PC-$User.csv"


net use /user:user \\zakelijk\logfiles "password"

# Mail Variables
#$smtpServer = "MAILSERVER.LOCAL"
#$subject = "Threat Detected on PC: $PC"
#$sendfrom = "user@domain.com"
#$sendTo = "user@domain.com"

# Set Powershell Priority to low:
$processid = Get-Process -name powershell
foreach ($process in $processid) {
$process.PriorityClass = 'BelowNormal' 
}

# End Prioritization

Function PromptForChoice {

		$message  = 'Do you wish to install Sysmon?'
		$question = 'Are you sure you want to proceed?'
		
		$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
		$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
		
		$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
		
		if ($decision -eq 0) {
			Write-Host 'Confirmed'
				$SysMonAgreed = New-Item -ItemType "file" -Path "$PWD\Agreed-Sysmon.txt" -Value "User has accepted the installation of SysMon"
				$SysMonAgreed
				
			if (Test-Path "$PWD\Agreed-Sysmon.txt") {
				write-host "SysMon64 will be downloaded and installed" -foregroundcolor green

			#Download SysMon Executable
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
			
			write-host 'Adjust the following lines in sysmonconfig-export.xml to be used with Splunk Monitoring' -ForegroundColor red
			write-host '<TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\</TargetObject> <!--Microsoft:Windows: Feature disabled by default [ write-host "https://attack.mitre.org/wiki/Technique/T1103 ] -->' -ForegroundColor yellow
			write-host '<TargetObject condition="begin with">HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls\</TargetObject> <!--Microsoft:Windows:  Feature disabled by default [ https://attack.mitre.org/wiki/Technique/T1103 ] -->' -ForegroundColor yellow
			write-host 'Remove the \ at the END of the Dlls -foregroundcolor green
			write-host ''<TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls</TargetObject> <!--Microsoft:Windows: Feature disabled by default [ write-host "https://attack.mitre.org/wiki/Technique/T1103 ] -->' -ForegroundColor green
			write-host '<TargetObject condition="begin with">HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls</TargetObject> <!--Microsoft:Windows:  Feature disabled by default [ https://attack.mitre.org/wiki/Technique/T1103 ] -->' -ForegroundColor green
			notepad "$PWD\sysmonconfig-export.xml"
			Write-Host "Click a key to continue importing the config file after you've saved the file" -ForegroundColor yellow
			pause
					.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
													}
	else	{
			timeout /T 3
			if (Test-Path "$PWD\Declined-Sysmon.txt") {
				write-host "Failed to get Sysmon Log, Switching to Windows Event Logging" -foregroundcolor yellow 
														}
			}
	} else  {
			Write-Host 'Cancelled'
				$DoNotAskAgain = New-Item -ItemType "file" -Path "$PWD\Declined-Sysmon.txt" -Value "User has declined the installation of SysMon"
				$DoNotAskAgain
			}
						}

# SysMon Setup
	if (Test-Path "$PWD\Sysmon-Setup.txt") {
				PromptForChoice
			timeout /T 3
				write-host "Removing Setup Check File" -foregroundcolor green
					Remove-Item -Path "$PWD\Sysmon-Setup.txt"
										} 
	else {
				write-host 'Initial Setup: Run this command first: New-Item -ItemType "file" -Path "$PWD\Sysmon-Setup.txt" -Value "User is requesting the installation of SysMon"'
		 }
			
# SysMon Installed?
					$SysMonLog = Get-WinEvent -ListLog *Sysmon* -EA silentlycontinue
	if ($SysMonLog.LogName -eq "Microsoft-Windows-Sysmon/Operational")  { 
				write-host "SysMon Enabled: continuing..." -ForegroundColor green 
		$SysMon = "True"
																		} 
# Enable Scheduled Task History 
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true


if ($TaskScheduler.enabled -eq "true") {
write-host "Succesfully enable Scheduled Task History" -ForegroundColor green
}

																		
### Begin Main Execution ###

# Create filename for HTMLReport
    
		$Time = (Get-Date).ToUniversalTime()
		[string]$StartTime = $Time|Get-Date -uformat  %Y%m%d_%H%M%S
		# Addition Start
		$username = $env:username
		#End Addition    
		#Addition Start
		$HTMLReport = $True
		#End Addition

	if ($HTMLReport) {
				[string]$Hostname = $ENV:COMPUTERNAME
				[string]$FileName = $StartTime + '_' + $Hostname + '.html'
        
		$HTMLReportFile = (Join-Path $PWD $FileName)
        
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
                -Body "<H1>Threat Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" `
                | Out-File $HTMLReportFile -ErrorAction Stop
            }
        Catch {
            "`n[-] Error writing enumeration output to disk! Check your permissions on $PWD.`n$($Error[0])`n"; Return
        }
    }

	if($HTMLReport) {
                ConvertTo-HTML -Fragment -Pre "<H2>Threat Detection Report Overview</H2>" | Out-File -Append $HtmlReportFile
					}


# Utilization of Computer 

Function Checkup {
					$Result | ConvertTo-HTML -PreContent "<H3>Computer Performance Properties</H3>" | Out-File -Append $HTMLReportFile	
					
 
					$Processor = Get-WmiObject -computername $PC win32_processor | Measure-Object -property LoadPercentage -Average | Select Average
					$DiskUtilization += % { (Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -eq "_Total"}).IOWriteOperationsPersec }
					$IdleTime = Get-WMIObject -Class "Win32_PerfFormattedData_PerfDisk_PhysicalDisk" -Filter 'Name = "_Total"'
			
			# Memory utilization
					$ComputerMemory =  Get-WmiObject -Class WIN32_OperatingSystem -ComputerName $PC
					$Memory = ((($ComputerMemory.TotalVisibleMemorySize - $ComputerMemory.FreePhysicalMemory)*100)/ $ComputerMemory.TotalVisibleMemorySize)
            
            # Top process
					$TopMem = Get-WmiObject WIN32_PROCESS -ComputerName $PC | Sort-Object -Property ws -Descending | Select-Object -first 1 processname, @{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}},@{Name="UserID";Expression={$_.getowner().user}}
 
            If($TopMem -and $ComputerMemory)
				{
                $ProcessName = $TopMem.ProcessName
                $ProcessMem  = $TopMem.'Mem Usage(MB)'
                $ProcessUser = $TopMem.UserID
                $RoundMemory = [math]::Round($Memory, 2)
				}
		
				$Result = [PSCustomObject]@{
									"ID1"	= "$($Processor.Average)%"
									"ID2"   = "$RoundMemory"
									"ID3"	= "$($IdleTime.PercentIdleTime)%"
									"ID4"   = "$ProcessName"
									"ID5"  	= "$ProcessMem"
				}
				$Result
		
			Foreach($Entry in $Result) 
			{ 
			if(($Entry.CpuLoad) -or ($Entry.memload) -ge "80" -or ($DiskIdle.PercentIdleTime) -ge "10") 
				{ 
				write-host "Either one of these checks has failed" -foregroundcolor yellow 
				write-host "CPU Load is above threshold: 80% > $Entry.CpuLoad"
				write-host "RAM Load is above threshold: 80% > $Entry.memload"
				write-host "Disk Idle stat is above threshold: 10% > $DiskIdle.PercentIdleTime"
			
				# VERBOSE EVENT DATA: $Result | fl *
				$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	
				#
				if (!(Test-Path $exportlocation)) {
													New-Item -Path $exportlocation -ItemType "file" -Force
					} 
				else 
					{
													write-host "Log file location already exists, continuing" -ForegroundColor green
					}
				if (Test-Path $exportlocation) {
													$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
					} 
				else
					{
					write-host "No Critical issues" -ForegroundColor green
					}
				}
			}
}
	
# Security Events
	
Function Security {

		$Result | ConvertTo-HTML -PreContent "<H3>Security Report</H3>" | Out-File -Append $HTMLReportFile	

			#adjust here and at $QueryEvents
			$Part = "Security"
			$LogName = "Security"
			# Excluded events, because of noice: 
			# 4673	#	A privileged service was called (NOISY)
			# 4688	#	A new process has been created (NOISY)	
			$EventId = 1102,4624,4625,4648,4672,4720,4724,4725,4726,4731,4732,4733,4734,4735,4738,4740,4769,4781,4964,4634,4662,5140,5152,5154,5156,5157,4698,4702
			for ($i = 0; $i -lt $EventId.count; $i=$i+21) { 
			[array]$QueryEvents += Get-WinEvent -FilterHashtable @{Logname="$LogName";ID = $EventId[$i..($i+21)];StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message
			}
			
			$Result = foreach ($DataValues in $QueryEvents)
            {
			write-host "$DataValues | fl auto " -ForegroundColor green
				if ($DataValues -ne "") {
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
											}
			}
  # VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
		}
	
# Application Events

Function Application {

		$Result | ConvertTo-HTML -PreContent "<H3>Application Report</H3>" | Out-File -Append $HTMLReportFile	
		
			#adjust here and at $QueryEvents
			$Part = "Application"
			$LogName = "Application"
			$EventId = 7,4098,7040
			$WordIDs = "$Part-words.txt"
			$WordItems = Get-Content -Path (Join-Path $PWD $WordIDs)

			$QueryEvents = Get-WinEvent -FilterHashtable @{Logname="$LogName";ID=$EventId;StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message

			$Result = foreach ($DataValues in $QueryEvents)
            {
					foreach ($WordPart in $WordItems) {
					
								write-host "Checking on:"
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host "$EventId" -foregroundcolor yellow
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host ""
								write-host "::::::::::::: Applciation Threats :::::::::::::::"
								write-host "$WordPart" -foregroundcolor green
								write-host "::::::::::::: Applciation Threats :::::::::::::::"
								write-host ""
								
						if ($DataValues.message -like "*$WordPart*")
						{
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
						}
													  }
			}
  # VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
					}
					


# System Events

Function System {

		$Result | ConvertTo-HTML -PreContent "<H3>System Report</H3>" | Out-File -Append $HTMLReportFile	
			#adjust here and at $QueryEvents
			$Part = "System"
			$LogName = "System"
			$EventId = 7045
			$WordIDs = "$Part-words.txt"
			$WordItems = Get-Content -Path (Join-Path $PWD $WordIDs)

			$QueryEvents = Get-WinEvent -FilterHashtable @{Logname="$LogName";ID=$EventId;StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message

			$Result = foreach ($DataValues in $QueryEvents)
            {
					foreach ($WordPart in $WordItems) {
					
								write-host "Checking on:"
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host "$EventId" -foregroundcolor yellow
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host ""
								write-host "::::::::::::::: System Threats ::::::::::::::::::"
								write-host "$WordPart" -foregroundcolor green
								write-host "::::::::::::::: System Threats ::::::::::::::::::"
								write-host ""
								
						if ($DataValues.message -like "*$WordPart*")
						{
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
						}
													  }
			}
  # VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
				}


# Power_shell Events
	
Function Power_shell {

		$Result | ConvertTo-HTML -PreContent "<H3>Power_shell Report</H3>" | Out-File -Append $HTMLReportFile	
			#adjust here and at $QueryEvents
			$Part = "Powershell"
			$LogName = "Microsoft-Windows-PowerShell/Operational"
			$EventId = 4100,4104,500,501
			$WordIDs = "$Part-words.txt"
			$WordItems = Get-Content -Path (Join-Path $PWD $WordIDs)

			$QueryEvents = Get-WinEvent -FilterHashtable @{Logname="$LogName";ID=$EventId;StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message
			$Result = foreach ($DataValues in $QueryEvents)
            {
					foreach ($WordPart in $WordItems) {
					
								write-host "Checking on:"
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host "$EventId" -foregroundcolor yellow
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host ""
								write-host "::::::::::::: Powershel Threats :::::::::::::::::"
								write-host "$WordPart" -foregroundcolor green
								write-host "::::::::::::: Powershel Threats :::::::::::::::::"
								write-host ""
								
						if ($DataValues.message -like "*$WordPart*")
						{
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
						}
													  }
			}
		# VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
					}
# ScheduledTask Events

Function ScheduledTask {
		$Result | ConvertTo-HTML -PreContent "<H3>ScheduledTask Report</H3>" | Out-File -Append $HTMLReportFile	
			#adjust here and at $QueryEvents
			$Part = "ScheduledTask"
			$LogName = "Microsoft-Windows-TaskScheduler/Operational"
			$EventId = 
			$WordIDs = "$Part-words.txt"
			$WordItems = Get-Content -Path (Join-Path $PWD $WordIDs)

			$QueryEvents = Get-WinEvent -FilterHashtable @{Logname="$LogName";ID=$EventId;StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message

			$Result = foreach ($DataValues in $QueryEvents)
            {
					foreach ($WordPart in $WordItems) {
					
								write-host "Checking on:"
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host "$EventId" -foregroundcolor yellow
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host ""
								write-host ":::::::::::::: Scheduled Tasks ::::::::::::::::::"
								write-host "$WordPart" -foregroundcolor green
								write-host ":::::::::::::: Scheduled Tasks ::::::::::::::::::" 
								write-host ""
								
						if ($DataValues.message -like "*$WordPart*")
						{
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
						}
													  }
			}
  # VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
						}

# CALL FUNCTIONS
# Checkup Events
	"`n[+] Checkup Events`n"
$CheckupExecution = Checkup
$CheckupExecution
# Security Events
	"`n[+] Security Events`n"
$SecurityExecution = Security
$SecurityExecution
# Application Events
	"`n[+] Application Events`n"
$ApplicationExecution = Application
$ApplicationExecution
# System Events
	"`n[+] System Events`n"
$SystemExecution = System
$SystemExecution
# Power_shell Events
# 	"`n[+] Power_shell Events`n"
# $Power_shellExecution = Power_shell
# $Power_shellExecution
# ScheduledTask Events
	"`n[+] ScheduledTask Events`n"
$ScheduledTaskExecution = ScheduledTask
$ScheduledTaskExecution


if ($SysMon -eq "True") {

# SysMon Events

Function SysMon {

		$Result | ConvertTo-HTML -PreContent "<H3>SysMon Report</H3>" | Out-File -Append $HTMLReportFile
		
			#adjust here and at $QueryEvents
			$Part = "SysMon"
			$LogName = "Microsoft-Windows-Sysmon/Operational"
			$EventId = 1,4,516
			$WordIDs = "$Part-words.txt"
			$WordItems = Get-Content -Path (Join-Path $PWD $WordIDs)

			$QueryEvents = Get-WinEvent -FilterHashtable @{Logname="$LogName";ID=$EventId;StartTime=(Get-Date).AddMinutes(-6)} -erroraction silentlycontinue | Select-Object ID, TimeCreated, Message

			$Result = foreach ($DataValues in $QueryEvents)
            {
					foreach ($WordPart in $WordItems) {
					
								write-host "Checking on:"
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host "$EventId" -foregroundcolor yellow
								write-host "::::::::::::::::::: EventID :::::::::::::::::::::"
								write-host ""
								write-host "::::::::::::::: Sysmon Threats ::::::::::::::::::"
								write-host "$WordPart" -foregroundcolor green
								write-host "::::::::::::::: Sysmon Threats ::::::::::::::::::" 
								write-host ""
								
						if ($DataValues.message -like "*$WordPart*")
						{
						$global:MailTrue = "True"
						$DataRequest = $DataValues.properties | ForEach-Object {$DataValues.Value}
						$PSObjectQuery = [PSCustomObject]@{
												'ID1' = $env:computername
												'ID2' = $env:username
												'ID3' = $DataValues.ID
												'ID4' = $DataValues.TimeCreated
												'ID5' = $DataValues.Message
														  }
						$PSObjectQuery
						}
													  }
			}
  # VERBOSE EVENT DATA: $Result | fl *
		$Result | ConvertTo-HTML -Fragment -Property ID1, ID2, ID3, ID4, ID5 | Out-File -Append $HTMLReportFile	

		if (!(Test-Path $exportlocation)) {
		New-Item -Path $exportlocation -ItemType "file" -Force
		} else {
		write-host "Log file location already exists, continuing" -ForegroundColor green
		}
		if (Test-Path $exportlocation) {
		$Result | Export-CSV -Append -Path $exportlocation  -Encoding UTF8
		}
				}
	
$SysMonExecution = SysMon
$SysMonExecution
}




#### Mail Function ###
#
# Function MailReport () {
# 						$StartEmailLayout = @"
# 						<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
# 						<html><head><title>Threat Review Report</title>
# 						</head>
# 						<body>
# 						
# 						"@
# 						$bodyinfo = @"
# 							<hr noshade size=3 width="100%">
# 						"@
# 							$Information += $bodyinfo
# 						$EndEmailLayout = @"
# 						</body>
# 						</html>
# "@	 
#  
# $DateStr = Get-Date -format "yyyy-MM-dd-hh-mm"
# $Content = $StartEmailLayout + $Information + $EndEmailLayout
# $Content = Get-Content "$HTMLReportFile" -Raw
# 
# 	send-mailmessage -from $sendfrom -to $sendTo -subject $subject -BodyAsHTML -body $Content -priority high -smtpServer $smtpServer -Port 587 -UseSsl
# 			
# 	write-host "You've send a Security Report to your IT-Admins" -ForegroundColor green
# 						}
#
#### End Mail Function ### 
#
#	If ($MailTrue -eq "True") 	{
#							MailReport
#							}
#
##############################################################################    
# Complete the report and output
##############################################################################    

	# Determine the execution duration
    $Duration = New-Timespan -start $Time -end ((Get-Date).ToUniversalTime())
    
    # Print report location and finish execution
    
    "`n"
    If ($HTMLReport) 	{
						"[+] FILE:`t$HTMLReportFile"
						"[+] FILESIZE:`t$((Get-Item $HTMLReportFile).length) Bytes"
						
						"[+] FILE:`t$exportlocation"
						"[+] FILESIZE:`t$((Get-Item $exportlocation).length) Bytes"
						}
					"[+] DURATION:`t$Duration"
					"[+] AttackCheckerInfoSec.ps1 complete!"

##############################################################################    
# The END
##############################################################################  
