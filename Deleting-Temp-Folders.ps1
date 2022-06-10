# Deleting Temp Folders 
## Variables ####   
   
    $objShell = New-Object -ComObject Shell.Application   
    $objFolder = $objShell.Namespace(0xA)   
      
    $temp = get-ChildItem "env:\TEMP"   
    $temp2 = $temp.Value   
      
    $WinTemp = "c:\Windows\Temp\*"   
      
 
  
# Remove temp files located in "C:\Users\USERNAME\AppData\Local\Temp"   
    write-Host "Removing Junk files in $temp2." -ForegroundColor Magenta    
    Remove-Item -Recurse  "$temp2\*" -Force
      

      
# Remove Windows Temp Directory    
    write-Host "Removing Junk files in $WinTemp." -ForegroundColor Green   
    Remove-Item -Recurse $WinTemp -Force    
      

    
    write-Host "Deleted Temp FIles!!!"