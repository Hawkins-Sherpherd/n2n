# install path for edge
$binaryPath = "$env:ProgramFiles\n2n"

# arguments for edge to be saved in the registry
$arguments = "-a static:192.168.1.1 -A  fdfd:cafe:babe::1/64 -c x -l localhost:4385 -k x -b"

if (Get-Service -Name "edge") {
    Stop-Service -Name "edge" | Out-Null
    # cmdlet only available for PWSH 6+
    & "$env:SystemRoot\System32\sc.exe" delete "edge" | Out-Null
}

# create a new program folder
if (!(Test-Path -Path "$binaryPath" -Type Container)) {
    New-Item -Type Directory -Path "$binaryPath" | Out-Null
}

# copy the edge executable
Copy-Item "edge.exe" "$binaryPath\edge.exe"



# create a new service with manual startup type
New-Service -Name "edge" -BinaryPathName "$binaryPath\edge.exe" -StartupType Manual -DisplayName "Edge" | Out-Null

if (!(Test-Path -Path "HKLM:\SOFTWARE\n2n" -PathType Container)) {
    New-Item -Type Directory -Path "HKLM:\SOFTWARE\n2n" | Out-Null
}

if (!(Test-Path -Path "HKLM:\SOFTWARE\n2n\edge" -PathType Container)) {
    New-Item -Type Directory -Path "HKLM:\SOFTWARE\n2n\edge" | Out-Null
}

New-ItemProperty -Path "HKLM:\SOFTWARE\n2n\edge" -Name "Arguments" -PropertyType String -Value "$arguments" -Force | Out-Null
