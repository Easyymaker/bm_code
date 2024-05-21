[org 0x7C00] ; bios maps us here
[bits 16] ; we start in real mode

%define CENTRY 0x7E00
; dont forget this is also defined in memory.h
%define MEMMAP 0x9000
%define PMAPL4 0xA000

; todo: more compatability in enabling the a20 line 

; fake BIOS parameter block so this works on a real machine
boot:
    jmp start
    TIMES 3-($-$$) DB 0x90   ; Support 2 or 3 byte encoded JMPs before BPB.

    ; Dos 4.0 EBPB 1.44MB floppy
    OEMname:           db    "mkfs.fat"  ; mkfs.fat is what OEMname mkdosfs uses
    bytesPerSector:    dw    512
    sectPerCluster:    db    1
    reservedSectors:   dw    1
    numFAT:            db    2
    numRootDirEntries: dw    224
    numSectors:        dw    2880
    mediaType:         db    0xf0
    numFATsectors:     dw    9
    sectorsPerTrack:   dw    18
    numHeads:          dw    2
    numHiddenSectors:  dd    0
    numSectorsHuge:    dd    0
    driveNum:          db    0
    reserved:          db    0
    signature:         db    0x29
    volumeID:          dd    0x2d7e5a1a
    volumeLabel:       db    "NO NAME    "
    fileSysType:       db    "FAT12   "


start:
    ; enable a20 line via BIOS
    ; TODO: more compatability by trying different a20 enabling methods 
    mov ax, 0x2403
    int 15h

    jmp 0x0000:init ; far jump to reload cs

init:
    xor ax, ax

    ; Set up segment registers.
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; place stack above since it grows away from us
    mov sp, boot


    ; load program into memory
    mov bx, CENTRY
    mov dh, 15
    ; dl should still contain the boot drive
    call read_disk

    ; load memory map
    ;mov di, MEMMAP
    ;call do_e820
    

    cld

    mov edi, PMAPL4
    jmp switch_longmode

;%include "print.asm"
%include "realdisk.asm"
%include "long.asm"
	;boot_msg dd "hello",0
	;msr_low dd 0
	;msr_high dd 0

; we in it boiz
[bits 64]
longmode:
;    mov ecx, 0x199
;    rdmsr
;    mov [msr_low],eax
;    mov [msr_high],edx
     mov eax, 0x12345678
     mov rdi, buffer+15
     mov ecx, 8
convert_loop:
    dec rdi
    and eax, 0x0F
    add al, '0'
    cmp al, '9'
    jle .skip
    add al, 7
.skip:
    stosb
    shr eax, 4
    loop convert_loop

    ; 打印字符串
    mov rsi, buffer
    call print_string

hang:
    hlt
    jmp hang
; 打印字符串函数
print_string:
    mov rbx, 0xB8000   ; 显存地址
    mov rcx, 16        ; 字符串长度
.next_char:
    lodsb
    cmp al, 0
    je .done
    mov [rbx], al
    add rbx, 2
    loop .next_char
.done:
    ret
    
    hlt 
    jmp CENTRY

; Pad out file.
buffer db "10000000", 0
times 510 - ($-$$) db 0
dw 0xAA55
