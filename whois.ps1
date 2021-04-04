#requires -version 5
<#
.SYNOPSIS
This script enumerates a machine's tcp network connections, checks if any local or remote ports are using unsecure protocols, gets the has of each owning process executable.
It also has a function to check against virus total (providing an authroized api-key)

.DESCRIPTION
  Whois and Virustotal network connection checks

.PARAMETER API Key (required)
  A Virustotal API-KEY used to check artifacts against virustotal database

.INPUTS
  Takes in a virustotal api-key for use in checking against their database of malicous hash.

.OUTPUTS
  Sends information to screen

.NOTES
  Version:        1.0
  Author:         Yrume Fernandez
  Creation Date:  18-MAR-2021
  Purpose/Change: Initial script development

.EXAMPLE
  Run the Powershell script from ps, passing API-KEY
  
  PS whois.p1 abcdefgshjklmnopqrstuvwxyz
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

Param (
  [string]
  [Parameter(Mandatory = $true)]
  $apikey
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import Modules & Snap-ins

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Any Global Declarations go here
$headers = @{"x-Apikey"="$($apikey)"}

# get tcp connections into remotenets variable.
$remotenets=Get-NetTCPConnection

# create an array of publicly known unsecure or leveraged ports
$unsecuredPorts=20,21,23,80,139,1080,1433,1434,3306,4444,31337,50050

#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Get-NetPortsUnsecure {
  Param ()
  Begin {

  }
  Process {
    Try {
        # notify users on unsecure locally hosted protocol checks
        Write-Host -ForegroundColor Black -BackgroundColor Green "Checking for unsecure protocols locally in use"

        # check unique local ports against list of unsecure ports
        $LocalUnsec = $remotenets.localport | sort-object -Unique | Where-Object {$unsecuredPorts -contains $_} | ForEach-Object {Write-output "The following local ports are unsecure: $($_)"}

        # notify users on unsecure remote protocol checks
        Write-Host -ForegroundColor Black -BackgroundColor Green "Checking for remote connections to non-secure protocols"

        # check unique remote ports against list of unsecure ports
        $remoteUnsec = $remotenets.Remoteport | sort-object -Unique | Where-Object {$unsecuredPorts -contains $_} | ForEach-Object {Write-output "The following remote ports are unsecure: $($_)"}

    } catch {
            $_
    }
  }
  End {
  Write-Output $LocalUnsec, $remoteUnsec
  }
  }


Function whois-connect {
  Param ()
  Begin {
# notify user of program start
Write-Host -ForegroundColor black -BackgroundColor Green "WhoIs Powershell starting to get NetTCPConnections"
  }
  Process {
    Try {

        # notify users on next process to check routable remote addresses against ARIN WhoIs
        Write-Host -ForegroundColor black -BackgroundColor Green "Whois Powershell finding routable Remote Addresses"

        #get ARIN IP address whois information for each unique remote address found connected.
        $whois=$remotenets.remoteaddress | Where-Object {$_ -notmatch "0.0.0.0|::|127.0.0.*|10.*.*.*|172.{16-31}.*.*|192.168.*.*"} | Sort-Object -Unique | ForEach-Object {Write-Host "Checking IP $($_) for ARIN record";(Invoke-RestMethod https://whois.arin.net/rest/ip/$($_))}

        #get ARIN POC information for each Address Organizational Owner.
        $connectedorgs=$whois.net.orgref.handle | sort-object -unique | ForEach-Object {Write-output "Retreiving POCS for $($_)";(Invoke-RestMethod https://whois.arin.net/rest/org/$($_))}

    } catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
      }
  }
  end {
      Write-Output $connectedorgs.org
  }
}

Function whois-VT {
  Param ()
  Begin {

  }
  Process {
    Try {

        # identify current running process.
        $foundProcess=$(get-process).path | sort -Unique

        #hash each found application with network connection.
        try{
        $filehash=$foundProcess| ForEach-Object {Get-FileHash -Path $_}
        } catch {$_}

        # notify user of program start
        Write-Host -ForegroundColor black -BackgroundColor Green "WhoIs Powershell starting to check hashes against virus total"
  
        try {
        $virustotalrsp=$(foreach ($i in $($filehash | Select-Object -ExpandProperty hash)) {wait-event -Timeout 60;Write-host "Checking Virus total for $($i)";(Invoke-RestMethod -Headers $headers https://www.virustotal.com/api/v3/files/$($i))})
        } catch [System.Net.WebException] {
        Write-Warning $_
        }

        write-warning $virustotalrsp.names.count
        $vt=$virustotalrsp | Where-Object {$_.data.attributes.last_analysis_results -EQ "malicious"} | ForEach-Object { 
        Write-Host "Mcafee cetegorized file hash $($_.data.attributes.names) as $($_.data.attributes.last_analysis_results.Mcafee.category)" |
        Write-output $_ }
 }
    Catch {
      Write-Host -BackgroundColor Red "Error: $($_.Exception)"
    }
  }
  End {
    If ($?) {
      Write-Host 'VirusTotal Checks Completed Successfully.'
      Write-Host ' '
      Write-Output $virustotalrsp
    }
  }
}
#-----------------------------------------------------------[Execution]------------------------------------------------------------
Get-NetPortsUnsecure | Out-File whois_output.txt
whois-connect | Out-File -Append whois_output.txt
whois-VT | Out-File -Append whois_output.txt
