[bits 16]
print_char:
	mov ah, 0x0E	; teletype
	mov bh, 0x00	; Page no
	mov bl, 0x07	; text attribute: lightgrey font on black background
	int 0x10
	ret
	
print16_string:
	nextc:
		mov al, [si]	; al = *si
		inc si			; si++
		cmp al, 0		; if al=0 call exit
		je exit
		call print_char
		jmp nextc
		exit: ret

error:
	hlt
	jmp error

[bits 64]
print_string:
    ; RDI = 0xB8000 (VGA text mode base address)
    mov rdi, 0xB8000
    .next_char:
        lodsb
        cmp al, 0
        je .done
        ; 将字符写入VGA内存
        mov [rdi], ax
        add rdi, 2
        jmp .next_char
    .done:
        ret

print_msr:
    ; 打印高32位
    mov eax, dword [msr_high]
    call print_hex
    ; 打印低32位
    mov eax, dword [msr_low]
    call print_hex
    ret

; 打印16进制值例程（64位模式）
print_hex:
    mov rcx, 8
    .next_digit:
        rol eax, 4
        mov bl, al
        and bl, 0x0F
        cmp bl, 0x0A
        jl .is_digit
        add bl, 'A' - 0x0A
        jmp .print_digit
    .is_digit:
        add bl, '0'
    .print_digit:
        mov [rdi], bx
        add rdi, 2
        loop .next_digit
        ret
