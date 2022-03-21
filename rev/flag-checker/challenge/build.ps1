function chk_rm {
    param (
        $fp
    )
    if (Test-Path -Path $fp) {
        Write-Output "Removing ${fp}"
        Remove-Item -Path $fp
    }
}
Write-Output "Killing zombie notepads..."
Get-Process | ? { $_.Name -eq "Notepad" } | % { $_.Kill($true) }
chk_rm "server.exe"
chk_rm "anime.exe"
Remove-Item pid.*.log
chk_rm "server.pdb"
chk_rm "anime.pdb"
chk_rm "server.ilk"
chk_rm "anime.ilk"
chk_rm "anime.log"
chk_rm "server.log"
chk_rm "task.log"
chk_rm "${env:Temp}\anime.exe"
chk_rm "${env:Temp}\server.exe"
Write-Output "Building server.cc ..."
$env:BIT_SIZE = 8
clang -DNUM_BITS=8 -DRELEASE -o "anime.exe" -DSPNG_USE_MINIZ server.cc miniz.c spng.c -w
llvm-strip -s anime.exe
# clang -DNUM_BITS=3 -g -o "server.exe" -DSPNG_USE_MINIZ server.cc miniz.c spng.c -w
clang -o cmd_open.exe cmd_open.c -w
Set-Location anime_list
chk_rm "animelist.exe"
Write-Output "Building go bin...."
go build -ldflags -H=windowsgui .
rm *.exe
go build -o animelist.exe -ldflags -H=windowsgui .
go build -o main.exe -ldflags -H=windowsgui .
Set-Location ..
Set-Location mkimg
Write-Output "Building image ..."
go build -o mkimg.exe .
& ".\mkimg.exe"
Set-Location ..
Write-Output "Building scripts..."
Get-ChildItem *.au3 | ForEach-Object {
    $t = $_.Name
    $name = $_.Name.Substring(0, $_.Name.Length - 4) + ".exe";
    Write-Output "Compiling $t ..."
    Aut2exe_x64.exe /in $_.Name /out $name /x64
}
Write-Output "Building final.cc ..."
clang -o final.exe final.cc -static -w
Write-Output "Patching task.exe ..."
& ".\final.exe"