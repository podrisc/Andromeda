New-Item -Path E:\ -ItemType Directory -Name 'ÿ'

Get-Item -LiteralPath E:\$([char]0xA0)\ -Force 

New-Item -Path C:\users\engineer\Desktop -ItemType Directory -Name $([char]0xA0) -Force 


gci E:\ -force

$s = [String]::Join([char]0x00a0, (''))
New-Item -ItemType Directory "$([char]0xa0)test"


Get-Item -LiteralPath E:\$([char]0xA0)test\ -Force | Rename-Item -NewName ' ' -Force
