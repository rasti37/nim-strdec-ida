nim cpp --gcc.exe:musl-gcc -d:release -d:mingw --cpu:i386 --opt:size --verbosity:0 --out=bin/dummy-i386.exe dummy.nim
nim cpp --gcc.exe:musl-gcc -d:release -d:mingw --opt:size --verbosity:0 --out=bin/dummy-x64.exe dummy.nim
nim cpp -d:release --opt:size --verbosity:0 --out=bin/dummy-elf-x64 dummy.nim
sha256sum bin/dummy* > bin/sha256.checksums
