# Compilation Info

| Binary | Compilation |
|-------|-------------|
| `dummy-i386.exe`| `nim cpp -d:release --cpu:i386 --opt:size --out=dummy-i386.exe dummy.nim`|  
| `dummy-x64.exe`| `nim cpp -d:release --opt:size --out=dummy-x64.exe dummy.nim`| 
| `dummy-elf-x64`| `nim cpp -d:release --opt:size --out=dummy-elf-x64 dummy.nim`|