function Get-Driveletters {
 clear

    Write-Host @"
                                .     .-/,\-.     ,
                                \ .-'//,M,\\`-. /
                                .-' .'/,MMM,\`. `-.
                        _.-"^\  / /       \ \  /^"-._
                        /,MMMM".' /  .-|-.  \ '."MMMM,\
            ________,,,/_,MMMM"/  /.-"  |  "-.\  \"MMMM,_\,,,_________
    -=========================='===^==^==^=====^==='=============================-
            ``^^^"""""""||\""""""""""""||\""""""""""""/||""""""""^^^``
                        ||             ||_)            ||
                        ||,            (|             ,||
                        db|            d8b            |db
                        YP             Y8P             YP


                                AUTHOR: Peter O'Driscoll
                                VERSION:FEBRUARY 2021
"@`n

    Write-host "---------------------------"
    write-host " FINDING DRIVE INFORMATION "
    write-host "---------------------------"`n

    Start-Sleep -Seconds 3

    $driveLetter = Get-WmiObject -class win32_logicaldisk -ErrorAction SilentlyContinue |?{($_.DeviceID -notmatch 'c:' -and $_.DeviceID -notmatch 'd:' -and $_DeviceID -ne ' ')}| Select-Object DeviceID, VolumeName 

    foreach ($drive in $driveLetter){
        #Write-Host ($drive).DeviceID
        #Get-ChildItem -LiteralPath ($drive).DeviceID 
        write-host "[+] FOUND DRIVE:" ($drive).DeviceID -ForegroundColor Yellow
   }

#look through the attached drives to find malicious LNK file that is used by Andromeda to execute the malicous DLL

    Start-Sleep -Seconds 3

    $andromedaLnk = get-childitem -LiteralPath ($driveLetter).DeviceID -filter '*.lnk' -force -ErrorAction SilentlyContinue
    $output = $andromedaLnk
        
    if ($andromedaLnk -eq $null) {
        write-host "No malicious LNK file found"
    } else {
        $Global:maliciousdrive =     
        write-host " "
        Write-host "---------------------------"
        write-host "    LNK ARTIFACT FOUND     "
        Write-host "---------------------------"
        write-host " "
        Write-host [+] ($andromedaLnk).FullName -ForegroundColor Yellow

    }
 
 #look for the hidden non-breaking space folder.  
  write-host " "
  Write-host "------------------------------------------"
  write-host "    LOOKING FOR HIDDEN FOLDER CONTENTS    "
  Write-host "------------------------------------------"
  write-host " "

  Start-Sleep 3

  if ($andromedaLnk){
      $driveLetterPath = ($andromedaLnk).DirectoryName
      $childitem = Get-ChildItem -LiteralPath $driveLetterPath"$([char]0xA0)\" -Force
          foreach ($item in $childitem){
              write-host [+] $item.FullName -ForegroundColor Yellow
          }
  } else {write-host [+] "no non-breaking space folder" -ForegroundColor Red}

  write-host " "
  Write-host "------------------------------------------"
  write-host "    RENAMING USB HIDDEN FOLDER            "
  Write-host "------------------------------------------"
  write-host " "

  Start-Sleep 3

  try {
    $Global:driveLetterPath = ($andromedaLnk).DirectoryName
    Get-Item -LiteralPath $Global:driveLetterPath"$([char]0xA0)\" -Force | Rename-Item -NewName 'FOR_REVIEW_RenamedFolder' -Force
    write-host [+] "Successfully modified directory: FOR_REVIEW_RenamedFolder" -ForegroundColor Green
  } catch [exception] {
    write-host [+] "ERROR - Can not modify drive" -ForegroundColor Red
  }

  write-host " "
  Write-host "-------------------------------"
  write-host "    REMOVING MALICIOUS LNK     "
  Write-host "-------------------------------"
  write-host " "

  Start-Sleep 3

  try { 
      write-host [+] Removing ($andromedaLnk).FullName -ForegroundColor Yellow
      Remove-Item ($andromedaLnk).FullName -force
          if (test-path($andromedaLnk).FullName){
              write-host [+] "LNK File does not exist" -ForegroundColor Red
          } else {
              write-host [+] "Successfully removed LNK" -ForegroundColor Green
          }
  } catch [exception] {
      write-host "error removing LNK" -ForegroundColor Red
  }

  write-host " "
  Write-host "-------------------------------"
  write-host "    REMOVING MALICIOUS DLL     "
  Write-host "-------------------------------"
  write-host " "

  Start-Sleep 3

  if (test-path $(join-path ($andromedaLnk).DirectoryName"FOR_REVIEW_RenamedFolder")){
     gci $(join-path ($andromedaLnk).DirectoryName"FOR_REVIEW_RenamedFolder") -Recurse -force | ?{$_.FullName.Length -gt 70} | remove-item -force
     write-host [+] "Successfully removed Andromeda DLL" -ForegroundColor Green
    #Remove-Item -Path $(join-path ($andromedaLnk).DirectoryName"FOR_REVIEW_RenamedFolder") -recurse -force | ?{$_.length -gt 7000000}
  } else {write-host "Not a good day"}


  write-host " "
  Write-host "-------------------------------"
  write-host "    REMOVING MALICIOUS FILES   "
  Write-host "-------------------------------"
  write-host " "

  Start-Sleep 3

  try { 
      if (test-path $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\desktop.ini){
      write-host [+] Removing $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\desktop.ini -ForegroundColor Green
      Remove-Item $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\desktop.ini -force -ea 0
      } else {write-host "failed to delete"}
  } catch [exception] {
      write-host "error removing LNK" -ForegroundColor Red
  }
  try { 
      if (test-path $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\IndexerVolumeGuid){
      write-host [+] Removing $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\IndexerVolumeGuid -ForegroundColor Green
      Remove-Item $Global:driveLetterPath"FOR_REVIEW_RenamedFolder"\IndexerVolumeGuid -force -ea 0
      } else {write-host "failed to delete"}
  } catch [exception] {
      write-host "error removing LNK" -ForegroundColor Red
  }


#THIS IS THE BOTTOM LINE
}

#Lets prompt the user if they wish to remediate the andromeda malware. 
$startAnromedaClearup = Read-Host "Are you ready to start ANDROMEDA clearnup (y/n)" 

#if user says yes then continue, else exit.    
    while("y","n" -notcontains $startAnromedaClearup )
    {
     $startAnromedaClearup = Read-Host "Please enter your response (y/n)"
    }
    #user selects yes lets find artificats to remediate.
    if ($startAnromedaClearup -eq "y"){
        Get-Driveletters
    #user says no, we will exit.        
    } elseif ($startAnromedaClearup -eq "n"){
        write-host "ok we will exit"
    }






