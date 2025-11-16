;=====================================================
; main.asm - Complete Secure Data Locker System
;=====================================================

INCLUDE Irvine32.inc

.data
; Debug messages
separator DB "|",0
noteSeparator DB "|",0

debugBuildStart DB "DEBUG: Building filename for note ",0
debugBuildEnd DB "DEBUG: Built filename = ",0
; Debug messages
debugViewStart DB "DEBUG: ViewAllNotes started",0
debugNoteCount DB "DEBUG: noteCount = ",0
debugCurrentNote DB "DEBUG: Processing note ",0
debugFilename DB "DEBUG: Filename = ",0
debugFileHandle DB "DEBUG: File handle = ",0
debugBytesRead DB "DEBUG: Bytes read = ",0
debugNoteContent DB "DEBUG: Note content = ",0
debugNoteSkipped DB "DEBUG: Note skipped (file not found or empty)",0

msgNoteFailed DB "Failed to add note!",0
newline DB 0Dh, 0Ah, 0
fixedNotesPrefix DB "notes_",0
msgNoteMissing DB " [FILE NOT FOUND]",0
msgTooManyNotes DB "Maximum notes reached! Cannot add more.",0
notesArray     BYTE 10 DUP(512 DUP(0))  ; 10 notes, each 512 chars
noteCount      DWORD 0
maxNotes       EQU 10

; User login info
currentUser       BYTE 32 DUP(0)        
recUser           BYTE 20 DUP(0)        
recPin            BYTE 20 DUP(0)        
recUserLen        DWORD 0               
recPinLen         DWORD 0               
inputBuf          BYTE 512 DUP(?)       
fileName          BYTE "users.dat",0    
fileUser          BYTE 20 DUP(0)        
filePin           BYTE 20 DUP(0)        
hFile             DWORD ?
bytesRead         DWORD ?
bytesWritten      DWORD ?
loginSuccessFlag  DWORD 0

; Notes management
notesFileName     BYTE 64 DUP(0)
noteBuf           BYTE 512 DUP(?)       
compressedBuf     BYTE 1024 DUP(?)      
encryptedBuf      BYTE 1024 DUP(?)      
tempBuf           BYTE 1024 DUP(?)      
currentNoteIndex  DWORD 0
caesarShift       BYTE 3                

; Messages
msgEnterUsername  DB "Enter username: ",0
msgEnterPIN       DB "Enter PIN: ",0
msgRegSuccess     DB "Registration successful!",0
msgRegFail        DB "Registration failed!",0
msgAddNote        DB "Enter your note (max 500 chars): ",0
msgNoteAdded      DB "Note added successfully!",0
msgNoNotes        DB "No notes found.",0
msgNotesHeader    DB "=== Your Notes ===",0
msgNoteNumber     DB "Note ",0
msgColon          DB ": ",0
msgEnterNoteIndex DB "Enter note number to view: ",0
msgInvalidIndex   DB "Invalid note number!",0
msgDeleteNote     DB "Enter note number to delete: ",0
msgNoteDeleted    DB "Note deleted successfully!",0
msgModifyNote     DB "Enter note number to modify: ",0
msgEnterNewNote   DB "Enter new note content: ",0
msgNoteModified   DB "Note modified successfully!",0
msgChangePIN      DB "Enter new PIN: ",0
msgPINChanged     DB "PIN changed successfully!",0
msgNotImplemented DB "Feature not implemented yet!",0

; Menu messages
menuMsg1 db "1. Register",0
menuMsg2 db "2. Login",0
menuMsg3 db "3. Exit",0
mainMenuMsg1 db "1. Add Note",0
mainMenuMsg2 db "2. View All Notes",0
mainMenuMsg3 db "3. View Note by Index",0
mainMenuMsg4 db "4. Delete Note",0
mainMenuMsg5 db "5. Modify Note",0
mainMenuMsg6 db "6. Change PIN",0
mainMenuMsg7 db "7. Logout",0
menuPrompt db "Choose option: ",0
msgWelcome db "Welcome, ",0
msgFail db "Login failed!",0
msgBye db "Exiting program.",0

.code
;-----------------------------------------------------
; Utility Procedures
;-----------------------------------------------------
CopyInputToRecord PROC
    push esi
    push edi
    push edx
    push eax
    
    xor ecx, ecx
CIP_loop:
    mov al, [esi+ecx]
    cmp al, 0
    je CIP_done
    cmp al, 0Dh
    je CIP_done
    cmp al, 0Ah
    je CIP_done
    inc ecx
    cmp ecx, 20
    jl CIP_loop
CIP_done:
    xor edx, edx
CIP_copy:
    cmp edx, ecx
    jge CIP_pad
    mov al, [esi+edx]
    mov [edi+edx], al
    inc edx
    jmp CIP_copy
CIP_pad:
    mov eax, 20
    sub eax, edx
    cmp eax, 0
    je CIP_return
CIP_pad_loop:
    mov byte ptr [edi+edx], 0
    inc edx
    dec eax
    jnz CIP_pad_loop
CIP_return:
    mov ecx, edx
    
    pop eax
    pop edx
    pop edi
    pop esi
    ret
CopyInputToRecord ENDP

Encrypt PROC
    push esi
    push ecx
    push eax
    
    test ecx, ecx
    jz EnDone
EnLoop:
    mov al, [esi]
    add al, 3
    mov [esi], al
    inc esi
    loop EnLoop
EnDone:
    pop eax
    pop ecx
    pop esi
    ret
Encrypt ENDP

Decrypt PROC
    push esi
    push ecx
    push eax
    
    test ecx, ecx
    jz DeDone
DeLoop:
    mov al, [esi]
    sub al, 3
    mov [esi], al
    inc esi
    loop DeLoop
DeDone:
    pop eax
    pop ecx
    pop esi
    ret
Decrypt ENDP

AddNoteSimple PROC
    pushad
    
    ; Get note input
    mov edx, OFFSET msgAddNote
    call WriteString
    mov edx, OFFSET noteBuf
    mov ecx, SIZEOF noteBuf
    call ReadString
    
    cmp eax, 0
    je AddNoteDone
    
    ; Build filename
    call BuildNotesFileName
    
    ; SIMPLIFIED: Save raw note without compression/encryption
    mov edx, OFFSET notesFileName
    call OpenInputFile
    mov hFile, eax
    
    cmp eax, INVALID_HANDLE_VALUE
    jne AppendToFile
    
    mov edx, OFFSET notesFileName
    call CreateOutputFile
    mov hFile, eax
    jmp WriteNote
    
AppendToFile:
    call CloseFile
    mov edx, OFFSET notesFileName
    call OpenInputFile
    mov hFile, eax
    mov eax, hFile
    mov edx, 0
    mov ecx, 2
    call SetFilePointer
    
WriteNote:
    ; Write note length
    mov word ptr [tempBuf], ax
    mov eax, hFile
    mov edx, OFFSET tempBuf
    mov ecx, 2
    call WriteToFile
    
    ; Write note data
    mov eax, hFile
    mov edx, OFFSET noteBuf
    mov ecx, eax  ; length from ReadString is still in EAX
    call WriteToFile
    
    call CloseFile
    
    mov edx, OFFSET msgNoteAdded
    call WriteString
    call Crlf
    
AddNoteDone:
    popad
    ret
AddNoteSimple ENDP

;-----------------------------------------------------
; Build Notes Filename - FIXED VERSION
;-----------------------------------------------------
BuildNotesFileName PROC
    ; Simple, safe filename builder
    mov edi, OFFSET notesFileName
    
    ; Write "notes_"
    mov byte ptr [edi], 'n'
    inc edi
    mov byte ptr [edi], 'o'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 'e'
    inc edi
    mov byte ptr [edi], 's'
    inc edi
    mov byte ptr [edi], '_'
    inc edi
    
    ; Append username
    mov esi, OFFSET currentUser
CopyUsername:
    mov al, [esi]
    cmp al, 0
    je AddExtension
    mov [edi], al
    inc esi
    inc edi
    jmp CopyUsername
    
AddExtension:
    ; Add ".dat"
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], 'd'
    inc edi
    mov byte ptr [edi], 'a'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 0
    
    ret
BuildNotesFileName ENDP

;-----------------------------------------------------
; Add Note - FIXED VERSION
;-----------------------------------------------------
; Temporary solution: Store multiple notes in same file separated by "|"
; Alternative: Store all notes in one file separated by a special character
AddNote PROC
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; Check if we have space for more notes
    mov eax, noteCount
    cmp eax, maxNotes
    jge TooManyNotes
    
    ; Get note input
    mov edx, OFFSET msgAddNote
    call WriteString
    mov edx, OFFSET noteBuf
    mov ecx, SIZEOF noteBuf
    call ReadString
    
    cmp eax, 0
    je AddNoteDone
    
    ; Copy note to notesArray
    mov esi, OFFSET noteBuf
    mov edi, noteCount
    imul edi, 512  ; Each note is 512 bytes
    add edi, OFFSET notesArray
    mov ecx, eax
    inc ecx  ; Include null terminator
    rep movsb
    
    ; Increment note count
    inc noteCount
    
    mov edx, OFFSET msgNoteAdded
    call WriteString
    call Crlf
    jmp AddNoteDone

TooManyNotes:
    mov edx, OFFSET msgTooManyNotes
    call WriteString
    call Crlf

AddNoteDone:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
AddNote ENDP

BuildSingleNotesFileName PROC
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    mov edi, OFFSET notesFileName
    
    ; Use current directory
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], '\'
    inc edi
    
    ; Write "notes_"
    mov byte ptr [edi], 'n'
    inc edi
    mov byte ptr [edi], 'o'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 'e'
    inc edi
    mov byte ptr [edi], 's'
    inc edi
    mov byte ptr [edi], '_'
    inc edi
    
    ; Append username
    mov esi, OFFSET currentUser
AppendUsername:
    mov al, [esi]
    cmp al, 0
    je AddExtension
    mov [edi], al
    inc esi
    inc edi
    jmp AppendUsername
    
AddExtension:
    ; Add ".dat"
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], 'd'
    inc edi
    mov byte ptr [edi], 'a'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 0
    
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret
BuildSingleNotesFileName ENDP
ViewAllNotes PROC
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; Display header
    mov edx, OFFSET msgNotesHeader
    call WriteString
    call Crlf
    call Crlf

    ; Check if we have any notes
    cmp noteCount, 0
    je NoNotesFound
    
    ; Display each note
    mov ecx, 0  ; Start from note 0

DisplayLoop:
    ; Calculate address of current note
    mov esi, ecx
    imul esi, 512
    add esi, OFFSET notesArray
    
    ; Display note number and content
    mov edx, OFFSET msgNoteNumber
    call WriteString
    mov eax, ecx
    inc eax  ; Show 1-based index to user
    call WriteDec
    mov edx, OFFSET msgColon
    call WriteString
    mov edx, esi
    call WriteString
    call Crlf
    
    ; Next note
    inc ecx
    cmp ecx, noteCount
    jl DisplayLoop
    
    jmp ViewNotesDone

NoNotesFound:
    mov edx, OFFSET msgNoNotes
    call WriteString
    call Crlf

ViewNotesDone:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
ViewAllNotes ENDP

DeleteNote PROC
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; Get note index to delete
    mov edx, OFFSET msgDeleteNote
    call WriteString
    call ReadInt
    dec eax  ; Convert to 0-based index
    
    ; Validate index
    cmp eax, 0
    jl InvalidIndex
    cmp eax, noteCount
    jge InvalidIndex
    
    ; Shift all subsequent notes up
    mov ecx, eax  ; Current index to delete
    
ShiftLoop:
    mov esi, ecx
    inc esi
    cmp esi, noteCount
    jge ShiftDone
    
    ; Calculate source and destination addresses
    mov edi, ecx
    imul edi, 512
    add edi, OFFSET notesArray
    
    mov esi, ecx
    inc esi
    imul esi, 512
    add esi, OFFSET notesArray
    
    ; Copy note up
    push ecx
    mov ecx, 512
    rep movsb
    pop ecx
    
    inc ecx
    jmp ShiftLoop

ShiftDone:
    ; Decrement note count
    dec noteCount
    
    mov edx, OFFSET msgNoteDeleted
    call WriteString
    call Crlf
    jmp DeleteDone

InvalidIndex:
    mov edx, OFFSET msgInvalidIndex
    call WriteString
    call Crlf

DeleteDone:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
DeleteNote ENDP

BuildNotesFileNameWithCounterForDisplay PROC
    ; Same as BuildNotesFileNameWithCounter but uses ECX instead of noteCount
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    mov edi, OFFSET notesFileName
    
    ; Write "notes_"
    mov esi, OFFSET fixedNotesPrefix
    mov ecx, 6
    rep movsb
    
    ; Append username
    mov esi, OFFSET currentUser
AppendUsername:
    mov al, [esi]
    cmp al, 0
    je AddCounter
    mov [edi], al
    inc esi
    inc edi
    jmp AppendUsername
    
AddCounter:
    mov byte ptr [edi], '_'
    inc edi
    
    ; Convert ECX to string (note number)
    mov eax, ecx  ; Use the counter from ECX
    mov ebx, 10
    xor ecx, ecx
    
ConvertLoop:
    xor edx, edx
    div ebx
    push dx
    inc ecx
    test eax, eax
    jnz ConvertLoop
    
PopLoop:
    pop ax
    add al, '0'
    mov [edi], al
    inc edi
    loop PopLoop
    
AddExtension:
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], 'd'
    inc edi
    mov byte ptr [edi], 'a'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 0
    
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret
BuildNotesFileNameWithCounterForDisplay ENDP

BuildNotesFileNameWithCounter PROC
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov edi, OFFSET notesFileName
    
    ; Use absolute path to current directory
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], '\'
    inc edi
    
    ; Write "notes_"
    mov byte ptr [edi], 'n'
    inc edi
    mov byte ptr [edi], 'o'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 'e'
    inc edi
    mov byte ptr [edi], 's'
    inc edi
    mov byte ptr [edi], '_'
    inc edi
    
    ; Append username
    mov esi, OFFSET currentUser
AppendUsername:
    mov al, [esi]
    cmp al, 0
    je AddCounter
    mov [edi], al
    inc esi
    inc edi
    jmp AppendUsername
    
AddCounter:
    ; Add underscore
    mov byte ptr [edi], '_'
    inc edi
    
    ; Convert ECX to string (note number)
    mov eax, ecx
    mov ebx, 10
    push ecx
    xor ecx, ecx
    
ConvertLoop:
    xor edx, edx
    div ebx
    push dx
    inc ecx
    test eax, eax
    jnz ConvertLoop
    
PopLoop:
    pop ax
    add al, '0'
    mov [edi], al
    inc edi
    loop PopLoop
    
    pop ecx
    
AddExtension:
    ; Add ".dat"
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], 'd'
    inc edi
    mov byte ptr [edi], 'a'
    inc edi
    mov byte ptr [edi], 't'
    inc edi
    mov byte ptr [edi], 0
    
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret
BuildNotesFileNameWithCounter ENDP

; Check if file exists - returns 1 in EAX if exists, 0 if not
CheckFileExists PROC
    push edx
    push eax
    
    mov edx, OFFSET notesFileName
    call OpenInputFile
    cmp eax, INVALID_HANDLE_VALUE
    je FileNotExists
    
    ; File exists - close it and return 1
    call CloseFile
    mov eax, 1
    jmp CheckDone
    
FileNotExists:
    mov eax, 0
    
CheckDone:
    pop eax
    pop edx
    ret
CheckFileExists ENDP

;-----------------------------------------------------
; View All Notes - FIXED VERSION
;-----------------------------------------------------


;-----------------------------------------------------
; Placeholder functions for unimplemented features
;-----------------------------------------------------
ViewNoteByIndex PROC
    mov edx, OFFSET msgNotImplemented
    call WriteString
    call Crlf
    ret
ViewNoteByIndex ENDP


ModifyNote PROC
    mov edx, OFFSET msgNotImplemented
    call WriteString
    call Crlf
    ret
ModifyNote ENDP

ChangePIN PROC
    mov edx, OFFSET msgNotImplemented
    call WriteString
    call Crlf
    ret
ChangePIN ENDP

;-----------------------------------------------------
; User Management (same as before)
;-----------------------------------------------------
RegisterUser PROC
    pushad
    
    ; Get username
    mov edx, OFFSET msgEnterUsername
    call WriteString
    mov edx, OFFSET inputBuf
    mov ecx, SIZEOF inputBuf
    call ReadString

    mov esi, OFFSET inputBuf
    mov edi, OFFSET recUser
    call CopyInputToRecord
    mov recUserLen, ecx

    ; Get PIN
    mov edx, OFFSET msgEnterPIN
    call WriteString
    mov edx, OFFSET inputBuf
    mov ecx, SIZEOF inputBuf
    call ReadString

    mov esi, OFFSET inputBuf
    mov edi, OFFSET recPin
    call CopyInputToRecord
    mov recPinLen, ecx

    ; Encrypt PIN for storage
    mov esi, OFFSET recPin
    mov ecx, recPinLen
    call Encrypt

    ; Save to file
    mov edx, OFFSET fileName
    call CreateOutputFile
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je RegFailed
    
    ; Write username (20 bytes)
    mov eax, hFile
    mov edx, OFFSET recUser
    mov ecx, 20
    call WriteToFile
    cmp eax, 0
    je RegFailed
    
    ; Write PIN (20 bytes)
    mov eax, hFile
    mov edx, OFFSET recPin
    mov ecx, 20
    call WriteToFile
    cmp eax, 0
    je RegFailed
    
    ; Close file
    mov eax, hFile
    call CloseFile
    
    mov edx, OFFSET msgRegSuccess
    call WriteString
    call Crlf
    jmp RegDone
    
RegFailed:
    mov edx, OFFSET msgRegFail
    call WriteString
    call Crlf
    
RegDone:
    popad
    ret
RegisterUser ENDP

LoginUser PROC
    pushad
    
    mov loginSuccessFlag, 0

    ; Get username
    mov edx, OFFSET msgEnterUsername
    call WriteString
    mov edx, OFFSET inputBuf
    mov ecx, SIZEOF inputBuf
    call ReadString
    mov esi, OFFSET inputBuf
    mov edi, OFFSET recUser
    call CopyInputToRecord
    mov recUserLen, ecx

    ; Get PIN
    mov edx, OFFSET msgEnterPIN
    call WriteString
    mov edx, OFFSET inputBuf
    mov ecx, SIZEOF inputBuf
    call ReadString
    mov esi, OFFSET inputBuf
    mov edi, OFFSET recPin
    call CopyInputToRecord
    mov recPinLen, ecx

    ; Encrypt the entered PIN for comparison
    mov esi, OFFSET recPin
    mov ecx, recPinLen
    call Encrypt

    ; Open file to validate
    mov edx, OFFSET fileName
    call OpenInputFile
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je LoginDone

    ; Read stored username
    mov eax, hFile
    mov edx, OFFSET fileUser
    mov ecx, 20
    call ReadFromFile
    mov bytesRead, eax
    cmp eax, 0
    je LoginDone
    
    ; Read stored PIN
    mov eax, hFile
    mov edx, OFFSET filePin
    mov ecx, 20
    call ReadFromFile

    ; Compare username
    mov esi, OFFSET recUser
    mov edi, OFFSET fileUser
    mov ecx, 20
    repe cmpsb
    jnz LoginDone

    ; Compare PIN
    mov esi, OFFSET recPin
    mov edi, OFFSET filePin
    mov ecx, 20
    repe cmpsb
    jnz LoginDone

    ; SUCCESS
    mov loginSuccessFlag, 1
    
    ; Store current username
    mov esi, OFFSET recUser
    mov edi, OFFSET currentUser
    mov ecx, recUserLen
    cmp ecx, 0
    je LoginDone
CopyUsername:
    mov al, [esi]
    mov [edi], al
    inc esi
    inc edi
    loop CopyUsername
    mov byte ptr [edi], 0

LoginDone:
    mov eax, hFile
    call CloseFile
    popad
    ret
LoginUser ENDP

;-----------------------------------------------------
; Main Menu After Login
;-----------------------------------------------------
MainMenu PROC
MainMenuLoop:
    call Crlf
    mov edx, OFFSET mainMenuMsg1
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg2
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg3
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg4
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg5
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg6
    call WriteString
    call Crlf
    mov edx, OFFSET mainMenuMsg7
    call WriteString
    call Crlf
    mov edx, OFFSET menuPrompt
    call WriteString
    
    call ReadChar
    call WriteChar
    call Crlf
    call Crlf
    
    sub al, '0'
    cmp al, 1
    je DoAddNote
    cmp al, 2
    je DoViewAllNotes
    cmp al, 3
    je DoViewNoteByIndex
    cmp al, 4
    je DoDeleteNote
    cmp al, 5
    je DoModifyNote
    cmp al, 6
    je DoChangePIN
    cmp al, 7
    je MainMenuDone
    jmp MainMenuLoop

DoAddNote:
    call AddNote
    jmp MainMenuLoop

DoViewAllNotes:
    call ViewAllNotes
    jmp MainMenuLoop

DoViewNoteByIndex:
    call ViewNoteByIndex
    jmp MainMenuLoop

DoDeleteNote:
    call DeleteNote
    jmp MainMenuLoop

DoModifyNote:
    call ModifyNote
    jmp MainMenuLoop

DoChangePIN:
    call ChangePIN
    jmp MainMenuLoop

MainMenuDone:
    ret
MainMenu ENDP

;-----------------------------------------------------
; Main Program
;-----------------------------------------------------
main PROC
    mov noteCount, 0

MenuLoop:
    call Crlf
    mov edx, OFFSET menuMsg1
    call WriteString
    call Crlf
    mov edx, OFFSET menuMsg2
    call WriteString
    call Crlf
    mov edx, OFFSET menuMsg3
    call WriteString
    call Crlf
    mov edx, OFFSET menuPrompt
    call WriteString
    
    call ReadChar
    call WriteChar
    call Crlf
    call Crlf
    
    sub al, '0'
    cmp al, 1
    je DoRegister
    cmp al, 2
    je DoLogin
    cmp al, 3
    je ExitProg
    jmp MenuLoop

DoRegister:
    call RegisterUser
    jmp MenuLoop

DoLogin:
    call LoginUser
    cmp loginSuccessFlag, 1
    je LoginSuccess
    mov edx, OFFSET msgFail
    call WriteString
    call Crlf
    jmp MenuLoop
DoDeleteNote:
    call DeleteNote
    jmp MenuLoop

LoginSuccess:
    mov edx, OFFSET msgWelcome
    call WriteString
    mov edx, OFFSET currentUser
    call WriteString
    call Crlf
    
    call MainMenu
    
    ; Clear login state
    mov loginSuccessFlag, 0
    mov byte ptr [currentUser], 0
    jmp MenuLoop

ExitProg:
    mov edx, OFFSET msgBye
    call WriteString
    call Crlf
    exit

main ENDP
END main
