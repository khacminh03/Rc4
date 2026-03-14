default rel
extern printf, fgets, strlen, scanf, __acrt_iob_func
global main, rc4, removeNewLine
; credit goes to: https://github.com/kmohamed2020/rc4/blob/master/RC4.c
section .data
    formatPrint db "%s", 0
    printEnterPlaintext db "Enter plaintext: ", 10, 0
    printEnterKey db "Enter key: ", 10, 0
    printCipherText db "Ciphertext: ", 10, 0
    formatHex db "%02x", 0
    len db 0
section .bss
    plaintext resb 256
    key resb 256
    ciphertext resb 256
    sbox resb 256
    tbox resb 256
section .text
removeNewLine:
    push rbp
    mov rbp, rsp
    sub rsp, 48
    .loop:
        mov bl, [rcx]
        cmp bl, 0
        je .done
        cmp bl, 10
        je .remove
        inc rcx
        jmp .loop
    .remove:
        mov byte [rcx], 0
    .done:
        add rsp, 48
        pop rbp
        ret
rc4:
    push rbp
    mov rbp, rsp
    sub rsp, 80
    mov [rbp - 8], rcx ; rcx = plaintext
    mov [rbp - 16], rdx ; rdx = key
    mov rcx, [rbp - 16] ; rcx = key
    call strlen
    mov [rbp - 24], rax ; [rbp - 24] = strlen(key)
    
    xor r8, r8
    .loopInitSbox:
        cmp r8, 256
        jge .initStatePermutation
    .startInitSbox: 
        ; for(int i = 0 ; i < 256 ; i++)
        ; {
        ;     S[i]=i;
        ;     T[i]= key[i % keyLen];
        ; }
        xor rdx, rdx
        xor rax, rax   
        lea rax, [rel sbox]
        mov byte [rax + r8 * 1], r8b ; sbox[i] = r8
        mov rax, r8
        mov rcx, [rbp - 24]
        xor rdx, rdx
        div rcx ; rdx = i % strlen(key)
        xor rax, rax 
        mov rax, [rbp - 16] ; rax = key
        mov r9b, byte [rax + rdx * 1] ; r9 = key[i % strlen(key)]
        xor rax, rax
        lea rax, [rel tbox]
        mov byte [rax + r8 * 1], r9b
        inc r8
        jmp .loopInitSbox
    .initStatePermutation:
        xor rcx, rcx ; rcx = i = 0
        xor r8, r8 ; r8 = j = 0
        xor r9, r9
    .statePermution:
        ; for(int i = 0 ; i < 256; i++)
        ; {
        ;     j = ( S[i] + T[i] + j ) % 256;
            
        ;     //Swap S[i] & S[j]
        ;     tmp = S[j];
        ;     S[j]= S[i];
        ;     S[i] = tmp;
        ; }       
        cmp rcx, 256
        jge .initEncryptRc4
        .startStatePermutation:
            lea rax, [rel sbox]
            mov r9b, byte [rax + rcx]
            lea rax, [rel tbox]
            add r9b, byte [rax + rcx]; r9 = sbox[i] + tbox[i]
            add r9d, r8d ; r9 = (sbox[i] + tbox[i] + j)
            mov rax, r9
            mov r12, 256
            div r12 ; rdx = (sbox[i] + tbox[i] + j) % 256
            mov r8, rdx ; j = rdx
            ; tmp = S[j]
            ; S[j]= S[i]
            ; S[i] = tmp
            xor rax, rax
            xor r11, r11
            lea rax, [rel sbox]
            mov r9b, byte [rax + r8] ; tmp = sbox[j]
            mov r11b, byte [rax + rcx] ; tmp1 = sbox[i]
            mov byte [rax + r8], r11b ; sbox[j] = tmp1 = sbox[i]
            mov byte [rax + rcx], r9b ; sbox[i] = tmp
            inc rcx
            jmp .statePermution
    .initEncryptRc4:
        xor rax, rax
        mov rcx, [rbp - 8] ; rcx = data
        call strlen
        mov [rbp - 32], rax ; [rbp - 32] = strlen(data)
        xor rcx, rcx ; x = 0
        xor r8, r8 ; i = 0
        xor r9, r9 ; j = 0
        xor r10, r10
        .startEncryptRc4:
            cmp rcx, [rbp - 32] ; rcx < strlen(data)
            jge .initPrintCipher
            .EncryptingRc4:
                ; i = (i+1) % 256
                ; j = (j + S[i])% 256
                inc r8 ; r8 += 1
                mov rax, r8
                mov r10, 256
                div r10 
                mov r8, rdx ; i = (i + 1) % 256
                xor rax, rax
                lea rax, [rel sbox]
                add r9b, byte [rax + r8] ; j = j + sbox[i]
                mov rax, r9
                mov r10, 256
                div r10
                mov r9, rdx ; j = (j + sbox[i]) % 256
                xor r10, r10
                xor r11, r11
                lea rax, [rel sbox]
                mov r10b, byte [rax + r9] ; tmp = sbox[j]
                mov r11b, byte [rax + r8] ; tmp1 = sbox[i]
                mov byte [rax + r9], r11b ; sbox[j] = sbox[i]
                mov byte [rax + r8], r10b ; sbox[i] = tmp
                xor r10, r10
                ; t = (S[i] + S[j]) % 256
                lea rax, [rel sbox]
                mov r10b, byte [rax + r8] ; r10b = sbox[i]
                mov r11b, byte [rax + r9] ; r11b = sbox[j]
                add r10, r11
                mov rax, r10
                mov r10, 256
                div r10
                xor r10, r10
                xor r11, r11
                mov r10, rdx ; t = r10 = (S[i] + S[j]) % 256
                ; result[x]= data[x]^S[t]
                mov rbx, [rbp - 8] ; rbx = *data
                mov r11b, byte [rbx + rcx] ; r11b = data[x]
                lea rax, [rel sbox]
                mov r12b, byte [rax + r10] ; r12b = sbox[t]
                xor r11, r12 ; data[x] ^ sbox[t]
                lea rax, [rel ciphertext]
                mov byte [rax + rcx], r11b ; ciphertext[x] = data[x] ^ sbox[t]
                inc rcx
                jmp .startEncryptRc4
    .initPrintCipher:
        lea rdx, [rel formatPrint]
        lea rcx, [rel printCipherText]
        call printf
        lea rcx, [rel ciphertext]
        call strlen
        mov [rbp - 40], rax
        xor rcx, rcx
        xor r12, r12
        .startPrintCiphertext:
            cmp r12, [rbp - 40]
            jge .done
            lea rax, [rel ciphertext]
            lea rcx, [rel formatHex]
            movzx edx, byte [rax + r12]
            call printf
            inc r12
            jmp .startPrintCiphertext
    .done:
        add rsp, 48
        pop rbp
        ret
main:
    push rbp
    mov rbp, rsp
    sub rsp, 48
    xor rax, rax
    lea rdx, [rel formatPrint]
    lea rcx, [rel printEnterPlaintext]
    call printf
    mov ecx, 0
    call __acrt_iob_func
    mov [rbp - 4], rax
    mov r8, [rbp - 4]
    mov rdx, 256
    lea rcx, [rel plaintext]
    call fgets
    lea rcx, [rel plaintext]
    call removeNewLine
    lea rdx, [rel formatPrint]
    lea rcx, [printEnterKey]
    call printf
    mov r8, [rbp - 4]
    mov rdx, 256
    lea rcx, [rel key]
    call fgets
    lea rcx, [rel key]
    call removeNewLine
    lea rdx, [key]
    lea rcx, [plaintext]
    call rc4
    add rsp, 48
    pop rbp
    ret
    