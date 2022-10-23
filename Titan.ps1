#  *** THIS SCRIPT IS DESIGNED FOR ADMINS ONLY, USE AT YOUR OWN RISK ***
<#

.DESCRIPTION
	Use WMI to remotely gather hardware and software (HW/SW) information from domain clients.
    This script will ping a list of computer names and run the inventory on activePCs.txt.
    Once the HW/SW information is collected, the data will be exported to a CSV file. 

.NOTES
	File Name: Titan.ps1
	Author: Chauncey Johnson, MSITM, MCSA
    Title: Data Operations Architect
	Contact Info:
        Company: 3rd SFG (A), FBNC 
		Email: chauncey.l.johnson@outlook.com
        O365: chauncey.l.johnson10.mil
        Github: https://cjohnsonX.github.io/System-Admin/
	Requires: PowerShell Remoting Enabled (Enable-PSRemoting) 
	Tested: PowerShell V5, Windows 10, Windows Server 2019

.PARAMETER 
    ComputerName(s), see the examples below.
		 
.EXAMPLE
     .\Titan.ps1 -ComputerName ARULBRXXXXXXX
     .\Titan.ps1 -ComputerName ARULBRXXXXXX1, ARULBRXXXXXX2
     .\Titan.ps1 -ComputerName (Get-Content -Path "C:\sie\activePCs.txt")

.REFERENCES
    https://technet.microsoft.com/en-us/library/hh847806.aspx
     
#>

Function Get-Inventory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$Computers
        )


$exportLocation = "$env:HOMEDRIVE\sie\"

# Test connection to each computer before getting the inventory info
foreach ($computer in $Computers) {
  if (Test-Connection -ComputerName $computer -Quiet -count 2){
    # The path to the activePCs.txt file, change to meet your needs
    Add-Content -value $computer -path "$exportLocation\activePCs.txt"
  }else{
    # The path to the deadPCs.txt file, change to meet your needs
    Add-Content -value $computer -path "$exportLocation\deadPCs.txt"
  }
}


# We now know which PCs are on the network
# Proceed with the HW/SW inventory

$computers = Get-Content -Path "$exportLocation\activePCs.txt"

foreach ($computer in $computers) {
    $Bios = Get-WmiObject -Class win32_bios -ComputerName $Computer
    $Hardware = Get-WmiObject -Class Win32_computerSystem -ComputerName $Computer
    $Sysbuild = Get-WmiObject -Class Win32_WmiSetting -ComputerName $Computer
    $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
    $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Computer | Where-Object {$_.IPEnabled}
    $driveSpace = Get-WmiObject -Class win32_volume -ComputerName $Computer -Filter 'drivetype = 3' | 
    Select-Object -Property PScomputerName, driveletter, label, @{LABEL='GBfreespace';EXPRESSION={'{0:N2}' -f($_.freespace/1GB)} } |
    Where-Object { $_.driveletter -match 'C:' }
    $cpu = Get-WmiObject -Class Win32_Processor  -ComputerName $computer
    $username = Get-ChildItem "\\$computer\c$\Users" | Sort-Object -Property LastWriteTime -Descending | Select-Object -Property Name, LastWriteTime -First 1
    $totalMemory = [math]::round($Hardware.TotalPhysicalMemory/1024/1024/1024, 2)
    $lastBoot = $OS.ConvertToDateTime($OS.LastBootUpTime) 

    $IPAddress  = $Networks.IpAddress[0]
    $MACAddress  = $Networks.MACAddress
    $systemBios = $Bios.serialnumber

    $OutputObj  = New-Object -TypeName PSObject
    $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()
    $OutputObj | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $Hardware.Manufacturer
    $OutputObj | Add-Member -MemberType NoteProperty -Name Model -Value $Hardware.Model
    $OutputObj | Add-Member -MemberType NoteProperty -Name Processor_Type -Value $cpu.Name
    $OutputObj | Add-Member -MemberType NoteProperty -Name System_Type -Value $Hardware.SystemType
    $OutputObj | Add-Member -MemberType NoteProperty -Name Operating_System -Value $OS.Caption
    $OutputObj | Add-Member -MemberType NoteProperty -Name Operating_System_Version -Value $OS.version
    $OutputObj | Add-Member -MemberType NoteProperty -Name Operating_System_BuildVersion -Value $SysBuild.BuildVersion
    $OutputObj | Add-Member -MemberType NoteProperty -Name Serial_Number -Value $systemBios
    $OutputObj | Add-Member -MemberType NoteProperty -Name IP_Address -Value $IPAddress
    $OutputObj | Add-Member -MemberType NoteProperty -Name MAC_Address -Value $MACAddress
    $OutputObj | Add-Member -MemberType NoteProperty -Name Last_User -Value $username.Name
    $OutputObj | Add-Member -MemberType NoteProperty -Name User_Last_Login -Value $username.LastWriteTime
    $OutputObj | Add-Member -MemberType NoteProperty -Name C:_FreeSpace_GB -Value $driveSpace.GBfreespace
    $OutputObj | Add-Member -MemberType NoteProperty -Name Total_Memory_GB -Value $totalMemory
    $OutputObj | Add-Member -MemberType NoteProperty -Name Last_ReBoot -Value $lastboot
    $OutputObj | Export-Csv -Path "$exportLocation\Titan_PC-Inventory.csv" -Append -NoTypeInformation
  }
}  
write-host -foregroundcolor cyan "Chief Johnson is a bad motherfucker; the proof is here: $exportLocation"  