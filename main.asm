;=====================================================
; main.asm - Complete Secure Data Locker System
;=====================================================

INCLUDE Irvine32.inc

.data

notesArray     BYTE 10 DUP(512 DUP(0))  ; 10 notes, each 512 chars
noteCount      DWORD 0
maxNotes       EQU 10

; Messages for new features
msgEnterNoteIndex DB "Enter note number to view: ",0
msgModifyNote     DB "Enter note number to modify: ",0
msgEnterNewNote   DB "Enter new note content: ",0
msgNoteModified   DB "Note modified successfully!",0
msgChangePIN      DB "Enter new PIN: ",0
msgPINChanged     DB "PIN changed successfully!",0
msgTooManyNotes   DB "Maximum notes reached! Cannot add more.",0
msgChangePINFailed DB "Failed to change PIN!",0
msgNoteFailed DB "Failed to add note!",0
newline DB 0Dh, 0Ah, 0
fixedNotesPrefix DB "notes_",0
msgNoteMissing DB " [FILE NOT FOUND]",0

; User login info
currentUser       BYTE 32 DUP(0)        
recUser           BYTE 20 DUP(0)        
recPin            BYTE 20 DUP(0)        
recUserLen        DWORD 0               
recPinLen         DWORD 0               
inputBuf          BYTE 512 DUP(?)       
fileName          BYTE 64 DUP(0)  
fileUser          BYTE 20 DUP(0)        
filePin           BYTE 20 DUP(0)        
hFile             DWORD ?
loginSuccessFlag  DWORD 0
fixedUsersPrefix  DB "user_",0


; Notes management
notesFileName     BYTE 64 DUP(0)
noteBuf           BYTE 512 DUP(?)           
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
msgInvalidIndex   DB "Invalid note number!",0
msgDeleteNote     DB "Enter note number to delete: ",0
msgNoteDeleted    DB "Note deleted successfully!",0


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
; Utility Procedures (Procedures for common tasks)
;-----------------------------------------------------

CopyInputToRecord PROC
; ===============================================================
    ; Scans input for newline/null, then pads the rest of the 
    ; 20-byte buffer with zeros to ensure clean file comparisons.
; ===============================================================
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
; ===============================================================
    ; Shifts every byte in the buffer up by 3 (Caesar Cipher +3).
; ===============================================================
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
; ===============================================================
    ; Shifts every byte in the buffer down by 3 (Caesar Cipher -3).
; ===============================================================
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

BuildNotesFileName PROC
; ===============================================================
    ; Constructs string "notes_[username].dat" dynamically.
; ===============================================================
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
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
BuildNotesFileName ENDP

BuildUserFileName PROC
; ===============================================================
    ; Constructs string ".\user_[username].dat" dynamically.
; ===============================================================
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov edi, OFFSET fileName
    mov byte ptr [edi], '.'
    inc edi
    mov byte ptr [edi], '\'
    inc edi

    ; Write "user_"
    mov byte ptr [edi], 'u'
    inc edi
    mov byte ptr [edi], 's'
    inc edi
    mov byte ptr [edi], 'e'
    inc edi
    mov byte ptr [edi], 'r'
    inc edi
    mov byte ptr [edi], '_'
    inc edi

    ; Append currentUser (up to first 0)
    mov esi, OFFSET currentUser
BU_AppendUser:
    mov al, [esi]
    cmp al, 0
    je BU_AddExt
    mov [edi], al
    inc esi
    inc edi
    jmp BU_AppendUser

BU_AddExt:
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
BuildUserFileName ENDP


;-----------------------------------------------------
; Section 2: Notes Functions (Procedures for notes manipulation)
;-----------------------------------------------------
AddNote PROC
; ===============================================================
    ; Calculates memory offset based on Note Count and stores input.
    ; Formula: Address = BaseArray + (NoteIndex * 512)
; ===============================================================
    push ebp
    mov ebp, esp
    pushad          ; Use pushad to save all registers easily

    ; Check capacity
    mov eax, noteCount
    cmp eax, maxNotes
    jge TooManyNotes

    ; Get input
    mov edx, OFFSET msgAddNote
    call WriteString
    mov edx, OFFSET noteBuf
    mov ecx, SIZEOF noteBuf
    call ReadString
    ; EAX now holds string length
    
    ; Calculate destination address in notesArray
    mov edi, noteCount
    imul edi, 512
    add edi, OFFSET notesArray

    ; --- FIX START: Clean the slot with Zeros first ---
    push eax        ; Save string length
    push edi        ; Save destination
    mov ecx, 512    ; Clear entire 512 byte slot
    mov al, 0
    rep stosb
    pop edi         ; Restore destination
    pop eax         ; Restore string length
    ; --- FIX END ---

    ; Copy note to notesArray
    mov esi, OFFSET noteBuf
    mov ecx, eax    ; Length of string
    inc ecx         ; Include null terminator
    rep movsb

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
    popad
    pop ebp
    ret
AddNote ENDP

ViewAllNotes PROC
; ===============================================================
    ;Iterate through the NotesArray using a counter.
    ;Print each note with its index.
; ===============================================================

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
; ===============================================================
    ; Removes note at Index X, then moves Note X+1 to X, X+2 to X+1...
    ; This prevents empty "holes" in the note list.
; ===============================================================
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

ViewNoteByIndex PROC
; ===============================================================
    ;Ask the user for a specific note's index
    ;Print the requested index
; ===============================================================

    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    
    ; Get note index from user
    mov edx, OFFSET msgEnterNoteIndex
    call WriteString
    call ReadInt
    dec eax  ; Convert to 0-based index
    
    ; Validate index
    cmp eax, 0
    jl InvalidIndex
    cmp eax, noteCount
    jge InvalidIndex
    
    ; Calculate address of the note
    mov esi, eax
    imul esi, 512
    add esi, OFFSET notesArray
    
    ; Display the note
    mov edx, OFFSET msgNoteNumber
    call WriteString
    mov eax, eax  ; We already have the 0-based index, but show 1-based to user
    inc eax
    call WriteDec
    mov edx, OFFSET msgColon
    call WriteString
    mov edx, esi
    call WriteString
    call Crlf
    jmp ViewByIndexDone

InvalidIndex:
    mov edx, OFFSET msgInvalidIndex
    call WriteString
    call Crlf

ViewByIndexDone:
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
ViewNoteByIndex ENDP

ModifyNote PROC
; ===============================================================
    ;Overwrite the notes by calculating its address
    ;Copy new user input into that slot
; ===============================================================
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; Get note index to modify
    mov edx, OFFSET msgModifyNote
    call WriteString
    call ReadInt
    dec eax  ; Convert to 0-based index
    
    ; Validate index
    cmp eax, 0
    jl InvalidIndexModify
    cmp eax, noteCount
    jge InvalidIndexModify
    
    ; Store the index in EBX
    mov ebx, eax
    
    ; Get new note content
    mov edx, OFFSET msgEnterNewNote
    call WriteString
    mov edx, OFFSET noteBuf
    mov ecx, SIZEOF noteBuf
    call ReadString
    
    cmp eax, 0
    je ModifyDone  ; If empty, do nothing
    
    ; Store the length
    mov ecx, eax
    
    ; Calculate address in notesArray: notesArray + (index * 512)
    mov edi, ebx
    imul edi, 512
    add edi, OFFSET notesArray
    
    ; Clear the old note (fill with zeros)
    push ecx
    push edi
    mov ecx, 512
    mov al, 0
    rep stosb
    pop edi
    pop ecx
    
    ; Copy the new note from noteBuf to notesArray position
    mov esi, OFFSET noteBuf
    ; EDI already points to the correct position in notesArray
    
    ; Copy the bytes
    cld
    rep movsb
    
    mov edx, OFFSET msgNoteModified
    call WriteString
    call Crlf
    jmp ModifyDone

InvalidIndexModify:
    mov edx, OFFSET msgInvalidIndex
    call WriteString
    call Crlf

ModifyDone:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
ModifyNote ENDP

ChangePIN PROC
; ===============================================================
    ;Updates User's PIN by encrypting it
    ;Overwrite the Previous Pin
; ===============================================================

    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; Get new PIN
    mov edx, OFFSET msgChangePIN
    call WriteString
    mov edx, OFFSET inputBuf
    mov ecx, SIZEOF inputBuf
    call ReadString
    
    ; Copy to recPin and encrypt
    mov esi, OFFSET inputBuf
    mov edi, OFFSET recPin
    call CopyInputToRecord
    mov recPinLen, ecx
    
    ; Encrypt the new PIN for storage
    mov esi, OFFSET recPin
    mov ecx, recPinLen
    call Encrypt
    
 
    ; Update this user's credential file: .\user_<currentUser>.dat
    call BuildUserFileName
    mov edx, OFFSET fileName
    call CreateOutputFile
    mov hFile, eax

    
    cmp eax, INVALID_HANDLE_VALUE
    je ChangePINFailed
    
    ; Copy currentUser to recUser for file storage
    mov esi, OFFSET currentUser
    mov edi, OFFSET recUser
    mov ecx, 20
    rep movsb
    
    ; Write username (20 bytes)
    mov eax, hFile
    mov edx, OFFSET recUser
    mov ecx, 20
    call WriteToFile
    cmp eax, 0
    je WriteFailed
    
    ; Write new PIN (20 bytes)
    mov eax, hFile
    mov edx, OFFSET recPin
    mov ecx, 20
    call WriteToFile
    cmp eax, 0
    je WriteFailed
    
    call CloseFile
    
    mov edx, OFFSET msgPINChanged
    call WriteString
    call Crlf
    jmp ChangePINDone

WriteFailed:
    mov edx, OFFSET msgChangePINFailed
    call WriteString
    call Crlf
    call CloseFile
    jmp ChangePINDone

ChangePINFailed:
    mov edx, OFFSET msgChangePINFailed
    call WriteString
    call Crlf

ChangePINDone:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret
ChangePIN ENDP





;-----------------------------------------------------
; Section 3: File Loading Procedures (Procedures for loading data into file)
;-----------------------------------------------------
SaveNotesToFile PROC
; ===============================================================
    ; Loops through RAM array and writes valid notes to file.
    ; Adds a newline between notes for readability.
; ===============================================================
    push ebp
    mov  ebp, esp
    pushad

    ; Build notes filename
    call BuildNotesFileName

    ; Create (overwrite) file
    mov  edx, OFFSET notesFileName
    call CreateOutputFile
    mov  hFile, eax
    cmp  eax, INVALID_HANDLE_VALUE
    je   SaveNotesExit

    ; If no notes, just close
    cmp  noteCount, 0
    jle  CloseAndExit

    ; Write noteCount * 512 bytes from notesArray
    mov  eax, hFile
    mov  edx, OFFSET notesArray
    mov  ecx, noteCount
    mov  ebx, 512
    imul ecx, ebx           ; ecx = noteCount * 512
    call WriteToFile        ; writes the raw bytes

CloseAndExit:
    mov  eax, hFile
    call CloseFile

SaveNotesExit:
    popad
    pop  ebp
    ret
SaveNotesToFile ENDP



LoadNotesFromFile PROC
; ===============================================================
    ; Read the data file into a temp buffer
    ; Copies the content of buffer into Notes Array
; ===============================================================
    push ebp
    mov  ebp, esp
    pushad

    ; Build notes filename
    call BuildNotesFileName

    ; Open file
    mov  edx, OFFSET notesFileName
    call OpenInputFile
    mov  hFile, eax
    cmp  eax, INVALID_HANDLE_VALUE
    je   NoNotesFile

    ; Read bytes
    mov  eax, hFile
    mov  edx, OFFSET notesArray
    mov  ecx, SIZEOF notesArray       
    call ReadFromFile                ; EAX = bytesRead
    
    ; --- FIX START: Save bytesRead before closing file ---
    push eax                         ; Save bytesRead to stack
    
    mov  eax, hFile
    call CloseFile                   ; EAX is now clobbered (returns success flag)

    pop eax                          ; Restore bytesRead from stack
    ; --- FIX END ---

    ; Compute noteCount = bytesRead / 512
    mov  ebx, 512
    xor  edx, edx
    div  ebx                         ; Now dividing the actual byte count
    mov  noteCount, eax
    jmp  LoadNotesExit

NoNotesFile:
    mov  noteCount, 0

LoadNotesExit:
    popad
    pop  ebp
    ret
LoadNotesFromFile ENDP



;-----------------------------------------------------
; Section 4:User Management
;-----------------------------------------------------
RegisterUser PROC
; ===============================================================
    ; Ask the user for name and PIN
    ; Format and Encrypt them
    ;Store them into .dat file
; ===============================================================
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

   ; Make this new user the currentUser (for filename building)
    mov esi, OFFSET recUser
    mov edi, OFFSET currentUser
    mov ecx, 20
    cld
    rep movsb
    mov byte ptr [currentUser+20], 0    ; null-terminate


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

    call BuildUserFileName          ; builds fileName based on currentUser

    mov edx, OFFSET fileName
    call CreateOutputFile           ; overwrites if user re-registers
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
    
    ; Write encrypted PIN (20 bytes)
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
; ===============================================================
    ; 1. Clears all buffers (Security).
    ; 2. Reads input (User/PIN).
    ; 3. Opens specific user file.
    ; 4. Compares Input vs File Content.
; ===============================================================
    pushad
    cld                 

    ; Clear fileUser buffer
    mov edi, OFFSET fileUser
    mov ecx, 20
    mov al, 0
    rep stosb

    ; Clear filePin buffer
    mov edi, OFFSET filePin
    mov ecx, 20
    mov al, 0
    rep stosb

    ; Clear recUser buffer
    mov edi, OFFSET recUser
    mov ecx, 20
    mov al, 0
    rep stosb

    ; Clear recPin buffer
    mov edi, OFFSET recPin
    mov ecx, 20
    mov al, 0
    rep stosb

    mov loginSuccessFlag, 0

    ; ---------------------------------------------------------
    ;  Get Inputs
    ; ---------------------------------------------------------
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

    ; Set currentUser from entered username
    mov esi, OFFSET recUser
    mov edi, OFFSET currentUser
    mov ecx, 20
    cld
    rep movsb
    mov byte ptr [currentUser+20], 0


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

    ; Encrypt entered PIN
    mov esi, OFFSET recPin
    mov ecx, recPinLen
    call Encrypt

    ; ---------------------------------------------------------
    ;. File Operations (open this user's credential file)
    ; ---------------------------------------------------------
    call BuildUserFileName         
    mov edx, OFFSET fileName
    call OpenInputFile

    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je LoginFailExit

    ; Read stored username
    mov eax, hFile
    mov edx, OFFSET fileUser
    mov ecx, 20
    call ReadFromFile
    ; Check if read failed
    cmp eax, 0
    je CloseAndFail

    ; Read stored PIN
    mov eax, hFile
    mov edx, OFFSET filePin
    mov ecx, 20
    call ReadFromFile

    ; CLOSE THE FILE IMMEDIATELY
    mov eax, hFile
    call CloseFile

    ; ---------------------------------------------------------
    ; 4. Comparisons (Safe now because buffers were zeroed)
    ; ---------------------------------------------------------
    
    ; Compare username
    mov esi, OFFSET recUser
    mov edi, OFFSET fileUser
    mov ecx, 20
    cld             ; Ensure forward comparison
    repe cmpsb
    jnz LoginFailExit

    ; Compare PIN
    mov esi, OFFSET recPin
    mov edi, OFFSET filePin
    mov ecx, 20
    cld             ; Ensure forward comparison
    repe cmpsb
    jnz LoginFailExit

    ; --- SUCCESS ---
    mov loginSuccessFlag, 1

    ; Update currentUser safely
    mov esi, OFFSET recUser
    mov edi, OFFSET currentUser
    mov ecx, 20
    cld
    rep movsb
    
    mov byte ptr [currentUser+20], 0 ; Null terminate
    call LoadNotesFromFile
    jmp LoginExit

CloseAndFail:
    mov eax, hFile
    call CloseFile

LoginFailExit:
    mov loginSuccessFlag, 0

LoginExit:
    popad
    ret
LoginUser ENDP


;-----------------------------------------------------
; Section 5: Main Menu
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
call SaveNotesToFile
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
