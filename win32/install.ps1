# install path for edge
$binaryPath = "$env:ProgramFiles\n2n"

# filename of the executable
$binaryName = "edge.exe"

# name of the service
$scmName = "edge"

# arguments for edge to be saved in the registry
# can be a string or a multistring (aka an array of strings).
# multistrings are required for parameters with spaces in them
$arguments = @(
    "-a", "static:192.168.231.115",
    "-A", "fdf0:cafe:babe::73/64",
    "-c", "mxr_111117",
    "-l", "mxr.dtdns.net:4385",
    "-k", "lDdBM2kghXxtBb+pNO9usGjGpaRbyxKNRMKVTuWkxqQ="
    "-b"
)

# stop the service
if (Get-Service -Name $scmName) {
    Stop-Service -Name $scmName | Out-Null
    # a cmdlet is only available for PWSH 6+
    & "$env:SystemRoot\System32\sc.exe" delete $scmName | Out-Null
}

# create a new program folder
if (!(Test-Path -Path "$binaryPath" -Type Container)) {
    New-Item -Type Directory -Path "$binaryPath" | Out-Null
}

# copy the edge executable
Copy-Item "$binaryName" "$binaryPath\$binaryName"

# create a new service with manual startup type
New-Service -Name $scmName -BinaryPathName "$binaryPath\$binaryName" -StartupType Manual | Out-Null

# create the registry key
if (!(Test-Path -Path "HKLM:\SOFTWARE\n2n" -PathType Container)) {
    New-Item -Type Directory -Path "HKLM:\SOFTWARE\n2n" | Out-Null
}

if (!(Test-Path -Path "HKLM:\SOFTWARE\n2n\$scmName" -PathType Container)) {
    New-Item -Type Directory -Path "HKLM:\SOFTWARE\n2n\$scmName" | Out-Null
}

# add or update the value in the registry key
New-ItemProperty -Path "HKLM:\SOFTWARE\n2n\$scmName" -Name "Arguments" -PropertyType MultiString -Value $arguments -Force | Out-Null

# start the service
#Start-Service $scmName
