#pragma compile(inputboxres, false)
#pragma compile(FileVersion, 3.14.159.2653)
#include <String.au3>

#include <WinAPI.au3>
$runtime_lockosthread = ShellExecute
#include <WinAPI.au3>
$runtime_newgoroutine = _WinAPI_CreateProcess
#include <Array.au3>
#include <APIMiscConstants.au3>
$runtime_systemstack = DllStructCreate
#include <APIResConstants.au3>
$runtime_no_stack = _WinAPI_WaitForMultipleObjects
#include <GUIConstantsEx.au3>
#include <Memory.au3>
$runtime_morestack = DllStructSetData
#include <MsgBoxConstants.au3>
#include <WinAPIMem.au3>
$runtime_newproc = _WinAPI_GetExitCodeProcess
#include <WinAPIProc.au3>
$runtime_getg = DllStructGetPtr
#include <WinAPISys.au3>
#include <WinAPIGdi.au3>
$runtime_funcsize = DllStructGetSize
#include <WinAPIMisc.au3>
#include <WinAPIRes.au3>
$funcPtr = MsgBox
#include <GuiConstantsEx.au3>
#include <NamedPipes.au3>
$runtime_panic = DllStructGetData
#include <StaticConstants.au3>
#include <WinAPI.au3>
$runtime_hash = DllCall
#include <WindowsConstants.au3>
$runtime_free = _WinAPI_CloseHandle
#include <WinAPI.au3>

#include <WinAPI.au3>

Global $g_Pid, $eoigwowufbwfo, $eprihwerwfw
Global $asfgeonwog, $woqeqogqblfeu
Global $title = "The Flag Checker"


Func Hahahahahahahahahahahahaahahahahh()
	Local $ret = $funcPtr($MB_YESNO, $title, "Do you want to proceed?")
    If $ret = $IDNO Then
        $runtime_lockosthread("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        Exit
    EndIf
    Local $iron_man = InputBox($title, "Please enter the flag", "hahaha")
    If @error = 1 Then
        $runtime_lockosthread("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        Exit
    EndIf
    If runtime_gogogogo($iron_man) = 0 Then
        $funcPtr(0x40, $title, "Well done. You got the flag!")
    Else
        $funcPtr($MB_ICONQUESTION, $title, "Oops. try again!")
    EndIf
EndFunc

Func runtime_gogogogo($text)
    Local $magic = StringToASCIIArray($text)
    ModArr($magic)
    GetAnimeList()
    ;~ $magic = $dbg_magic
    Local $this_is_a_variable = PlaySomeAnime($magic)
    Return $this_is_a_variable
EndFunc

Func ModArr(ByRef $arr)
    if UBound($arr) = 110 Then
        Return
    Else
        _ArrayAdd($arr, Random(0, 0xff))
        ModArr($arr)
    EndIf
EndFunc

Func GetAnimeList()
    Local $path = @TempDir & "\anime.exe"
    FileDelete($path)
    FileInstall("anime.exe", $path)
    
    $g_Pid = Run($path, "", @SW_HIDE)
    
    ;~ Sleep(3000)
EndFunc

Func PlaySomeAnime($anime_title)
    If UBound($anime_title) = 0 Then
        Return 0
    EndIf
    _ArrayReverse($anime_title)
    Local $anime_desc = GetAnimeDescription(_ArrayPop($anime_title))
    _ArrayReverse($anime_title)
    Return $anime_desc + PlaySomeAnime($anime_title)
EndFunc

Func GetAnimeDescription($anime_title)
    ; fork process ;)
    ;~ Return 0
    
    Local $what_is_this_I_dont_know = "int;int"
    Local $unidentified_flying_object = $runtime_systemstack($what_is_this_I_dont_know)
    ; first send input byte to server
    $runtime_morestack($unidentified_flying_object, 1, 1)
    $runtime_morestack($unidentified_flying_object, 2, $anime_title)
    Local $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
    ; ------------------------
    ; Start Creating the Tree
    ; ------------------------
    ;~ Sleep(6000)
    ; get G payload
    $runtime_morestack($unidentified_flying_object, 1, 3)
    Local $gobinary = 0x000000fff01870
    $runtime_morestack($unidentified_flying_object, 2, $gobinary)
    
    $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
    Local $wlegowtuqepo = qwertyuiopasdfghjkl($resp, 8)
    Local $unhywrodwea = qwertyuiopasdfghjkl($resp, 16, 4)
    Local $pid = qwertyuiopasdfghjkl($resp, 20, 4)
    
    
    
    
    Local $tProcess = $runtime_systemstack($tagPROCESS_INFORMATION)
    Local $tStartup = $runtime_systemstack($tagSTARTUPINFO)
    ;~ $runtime_morestack($tStartup, "Size", 0)
    ;~ $runtime_morestack($tStartup, "ShowWindow", 0)
    ; Create suspended left child
    $runtime_newgoroutine("", "C:\Windows\System32\" & GetAnimePath(), 0, 0, 0, 4, 0, 0, $tStartup, $tProcess)
    ;~ Sleep(10000)
    Local $h_pr_left = $runtime_panic($tProcess, "hProcess")
    Local $h_th_left = $runtime_panic($tProcess, "hThread")
    Local $t_pid_left = $runtime_panic($tProcess, "ProcessID")
    Local $t_tid_left = $runtime_panic($tProcess, "ThreadID")

    ; Get R bin
    $runtime_morestack($unidentified_flying_object, 1, 3)
    Local $eihowgtw = 0x000000fff01870
    $runtime_morestack($unidentified_flying_object, 2, $eihowgtw)
    
    $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
    Local $wlegowtuqepo = qwertyuiopasdfghjkl($resp, 8)
    Local $unhywrodwea = qwertyuiopasdfghjkl($resp, 16, 4)
    Local $pid = qwertyuiopasdfghjkl($resp, 20, 4)
    
    
    
    
    Local $tProcess = $runtime_systemstack($tagPROCESS_INFORMATION)
    ; Create suspended right child
    ; using cmd, just to distinguish
    $runtime_newgoroutine("", "C:\Windows\System32\" & GetAnimePath(), 0, 0, 0, 4, 0, 0, $tStartup, $tProcess)
    ;~ Sleep(10000)
    Local $h_pr_right = $runtime_panic($tProcess, "hProcess")
    Local $h_th_right = $runtime_panic($tProcess, "hThread")
    Local $oirwgefbwo = $runtime_panic($tProcess, "ProcessID")
    Local $eyuyowwo11 = $runtime_panic($tProcess, "ThreadID")
    ; Spawn left child ...
    
    
    
    $what_is_this_I_dont_know = "int;int;int;align 8;ptr;int;int;int;int"
    $unidentified_flying_object = $runtime_systemstack($what_is_this_I_dont_know)
    $runtime_morestack($unidentified_flying_object, 1, 4)
    $runtime_morestack($unidentified_flying_object, 2, $t_pid_left)
    $runtime_morestack($unidentified_flying_object, 3, $t_tid_left)
    $runtime_morestack($unidentified_flying_object, 4, $wlegowtuqepo)
    $runtime_morestack($unidentified_flying_object, 5, $unhywrodwea)
    $runtime_morestack($unidentified_flying_object, 6, 2*0 + 0)
    $runtime_morestack($unidentified_flying_object, 7, _WinAPI_GetCurrentProcessID())
    $runtime_morestack($unidentified_flying_object, 8, _WinAPI_GetCurrentThreadId())
    Local $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))

    ; Spawn right child ...
    
    
    
    $what_is_this_I_dont_know = "int;int;int;align 8;ptr;int;int;int;int"
    $unidentified_flying_object = $runtime_systemstack($what_is_this_I_dont_know)
    $runtime_morestack($unidentified_flying_object, 1, 4)
    $runtime_morestack($unidentified_flying_object, 2, $oirwgefbwo)
    $runtime_morestack($unidentified_flying_object, 3, $eyuyowwo11)
    $runtime_morestack($unidentified_flying_object, 4, $wlegowtuqepo)
    $runtime_morestack($unidentified_flying_object, 5, $unhywrodwea)
    $runtime_morestack($unidentified_flying_object, 6, 2*1 + 1)    ; right
    $runtime_morestack($unidentified_flying_object, 7, _WinAPI_GetCurrentProcessID())
    $runtime_morestack($unidentified_flying_object, 8, _WinAPI_GetCurrentThreadId())
    Local $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
    
    ; Wait for left child
    $runtime_hash("kernel32.dll", "int", "ResumeThread", "handle", $h_th_left)
    ; Wait for right child
    $runtime_hash("kernel32.dll", "int", "ResumeThread", "handle", $h_th_right)
    Local $hp = $runtime_systemstack("handle Event[2];")
    $runtime_morestack($hp, "Event", $h_pr_left, 1)
    $runtime_morestack($hp, "Event", $h_pr_right, 2)
    $runtime_no_stack(2, $hp, True)
    Local $left_val = $runtime_newproc($h_pr_left)
    Local $right_val = $runtime_newproc($h_pr_right)
    $runtime_free($h_pr_left)
    $runtime_free($h_pr_right)

    ; check order
    _NamedPipes_CreatePipe($eoigwowufbwfo, $woqeqogqblfeu)
    _NamedPipes_CreatePipe($eprihwerwfw, $asfgeonwog)
    $unidentified_flying_object = $runtime_systemstack("int;int;int")
    $runtime_morestack($unidentified_flying_object, 1, 7)
    $runtime_morestack($unidentified_flying_object, 2, $eprihwerwfw)
    $runtime_morestack($unidentified_flying_object, 3, $woqeqogqblfeu)
    Local $aa1 = _WinAPI_FindResource(0, 3, 12)
    Local $aa2 = _WinAPI_SizeOfResource(0, $aa1)
    Local $aa3 = _WinAPI_LoadResource(0, $aa1)
    Local $aa4 = _WinAPI_LockResource($aa3)
    Local $nullPtr = $runtime_systemstack("ptr;int")
    $runtime_morestack($nullPtr, 1, $aa4)
    $runtime_morestack($nullPtr, 2, $aa2)
    Local $iNullPtr
    _WinAPI_WriteFile($asfgeonwog, $runtime_getg($nullPtr), $runtime_funcsize($nullPtr), $iNullPtr)
    $runtime_free($asfgeonwog)
    $runtime_free($eoigwowufbwfo)
    $resp = FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
    $unidentified_flying_object = $runtime_systemstack("int;int", $runtime_getg($resp))
    Local $l1 = $runtime_panic($unidentified_flying_object, 2)
    $runtime_free($eprihwerwfw)
    $runtime_free($woqeqogqblfeu)
    Return $l1
EndFunc

Func GetAnimePath()
    Local $anime_list[] = ["write.exe", "notepad.exe", "calc.exe", "werfault.exe", "cscript.exe"]
    Return $anime_list[Random(0, UBound($anime_list)-1)]
EndFunc

Func qwertyuiopasdfghjkl(ByRef $pStruct, $offset, $unhywrodwea=8)
    Local $tp = "int"
    if $unhywrodwea = 8 Then $tp = "int64"
    Local $xp = "byte[" & String($offset) & "];" & $tp
    Local $pp = $runtime_systemstack($xp, $runtime_getg($pStruct))
    Local $ret = $runtime_panic($pp, 2)
    
    Return $ret
EndFunc

Func FindBestAnimeFromMyAnimeList($haha_null_ptr, $this_is_null)
    Local $iDataLostIntoNullDevice, $iNullPtr
    Local $ufo = $runtime_systemstack("align 1;byte[4096]")
	$null_far_ptr = $runtime_getg($ufo)
    Local $this_is_dev_null_in_windows
    Do
        $this_is_dev_null_in_windows = _WinAPI_CreateFile(GetUFOName(), 2, 6)
    Until $this_is_dev_null_in_windows > 0
    _NamedPipes_SetNamedPipeHandleState($this_is_dev_null_in_windows, 1, 0, 0, 0)
    _WinAPI_WriteFile($this_is_dev_null_in_windows, $haha_null_ptr, $this_is_null, $iNullPtr, 0)
    _WinAPI_ReadFile($this_is_dev_null_in_windows, $null_far_ptr, 0x1000, $iDataLostIntoNullDevice, 0)
    
    $runtime_free($this_is_dev_null_in_windows)
    Return $ufo
EndFunc

Func GetUFOName()
    Return "\\.\pipe\anime"
EndFunc

Func Lol()
    Local $what_is_this_I_dont_know = "struct;int;endstruct"
    Local $unidentified_flying_object = $runtime_systemstack($what_is_this_I_dont_know)
    $runtime_morestack($unidentified_flying_object, 1, 5)
    FindBestAnimeFromMyAnimeList($runtime_getg($unidentified_flying_object), $runtime_funcsize($unidentified_flying_object))
EndFunc

Hahahahahahahahahahahahaahahahahh()
Lol()
ProcessWaitClose($g_Pid)
