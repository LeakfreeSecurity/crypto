;
; 32-bit x86 ASM implementation of SIMON 32/64 block cipher
; Author: Jos Wetzels
; 
;
; Simon is a family of lightweight (balanced feistel) block ciphers optimized for hardware performance, released by the NSA in 2013.
; See: http://eprint.iacr.org/2013/404.pdf
;
; The implementation below is SIMON 32/64 with blocksize 32, keysize 64 and 32 rounds.
;

;
; SIMON 32/64 sanity test
;
; Out:
;   EAX = 0 on success, EAX != 0 on failure
;
_sanity_test:

    XOR EAX, EAX
    MOV EBX, EAX
    MOV EDX, EAX
    MOV ESI, EAX
    MOV EDI, EAX

    MOV DI, 0x0100      ; K0
    MOV DX, 0x0908      ; K1
    MOV SI, 0x1110      ; K2
    MOV BX, 0x1918      ; K3

    MOV ECX, 32         ; Round count
    SUB ESP, 2*32       ; Key schedule memory
    MOV EAX, ESP
    CALL _schedule_key

    MOV ESI, EAX
    MOV EAX, 0x65656877 ; Plaintext

    CALL _simon_encrypt

    ; EAX = Ciphertext, ESI = key schedule
    CALL _simon_decrypt

    XOR EAX, 0x65656877 ; Decrypted plaintext
    RET

;
; SIMON 32/64 encrypt
;
; In:
;   EAX = plaintext
;   ESI = key schedule memory address
;
; Out:
;   EAX = ciphertext
;
_simon_encrypt:
    PUSH DI

    MOV ECX, 0
    _simon_e_loop:
        MOV DI, WORD [ESI+ECX*2]
        CALL _simon_round_f
        INC ECX
        CMP ECX, 32
        JNE _simon_e_loop

    POP DI
    RET

;
; SIMON 32/64 decrypt
;
; In:
;   EAX = ciphertext
;   ESI = key schedule memory address
;
; Out:
;   EAX = plaintext
;
_simon_decrypt:
    PUSH DI

    MOV CX, 31
    _simon_d_loop:
        ROL EAX, 16
        MOV DI, WORD [ESI+ECX*2]
        CALL _simon_round_f
        ROL EAX, 16
        DEC CX
        CMP CX, -1
        JNE _simon_d_loop

    POP DI

    RET

;
; SIMON 32/64 key scheduler
;
; In:
;   EAX = memory address for schedule storage
;   DI = K0
;   DX = K1
;   SI = K2
;   BX = K3
;   ECX = number of rounds
;
; Out:
;   EAX = address pointing to memory filled with round keys
;
_schedule_key:

    PUSH ECX

    MOV WORD [EAX+0], DI
    MOV WORD [EAX+2], DX
    MOV WORD [EAX+4], SI
    MOV WORD [EAX+6], BX

    MOV CX, 4

    _expansion_loop:
        CALL _expand_key_f
        MOV WORD [EAX + ECX*2], BX
        INC ECX
        CMP ECX, DWORD [ESP]
        JNE _expansion_loop

    POP ECX

    RET

;
; SIMON 32/64 key expansion function
;
; In:
;   DI = K0
;   DX = K1
;   SI = K2
;   BX = K3
;   CX = round index
;
; Out:
;   DI = K1
;   DX = K2
;   SI = K3
;   BX = KR
;
_expand_key_f:

    PUSH DX
    PUSH SI
    PUSH BX

    PUSH AX
    PUSH CX

    ;
    ; Periodic sequence
    ;    

    PUSH 0x9BC34AF4
    PUSH 0xCD6125FA

    ; Q, R  = ((I-4) / 8)
    XOR AH, AH
    MOV AL, CL
    SUB AL, 4
    MOV CL, 8
    DIV CL

    ; AH = R, AL = Q
    ; Take Rth bit of Qth byte in periodic sequence

    MOV CL, AH
    XOR AH, AH
    MOV ESI, ESP
    ADD SI, AX

    ; AL = bitmask (10000000 >> AH)
    MOV AL, 0x80
    ROR AL, CL

    ; (BYTE [ESP + AL]) & (10000000 >> AH)
    AND AL, BYTE [ESI]
    INC CL
    ROL AL, CL
    MOV SI, AX

    ADD ESP, 8

    POP CX
    POP AX

    ; Expand key

    XOR DI, 0xFFFC  ; K0 ^ C
    XOR DI, SI      ; K0 ^ C ^ SEQ(I-4)

    ROR BX, 3       ; K3 >> 3
    XOR BX, DX      ; (K3 >> 3) ^ K1
    MOV DX, BX      ; (K3 >> 3) ^ K1
    ROR BX, 1       ; ((K3 >> 3) ^ K1) >> 1
    XOR DI, BX      ; (K0 ^ C ^ SEQ(I-4)) ^ (((K3 >> 3) ^ K1) >> 1)
    XOR DI, DX      ; (K0 ^ C ^ SEQ(I-4)) ^ (((K3 >> 3) ^ K1) >> 1) ^ ((K3 >> 3) ^ K1)

    MOV BX, DI
    POP SI
    POP DX
    POP DI

    RET

;
; SIMON 32/64 round function
;
; In:
;   EAX = plaintext
;   DI = round key
;   CX = round index
;
; Out:
;   EAX = ciphertext
;
_simon_round_f:

    PUSH DX
    PUSH BX

    XOR DI, AX       ; K ^ R
    ROL EAX, 16
    MOV DX, AX
    MOV BX, AX

    PUSH AX

    ; Feistel round
    ROL AX, 1        ; L << 1
    ROL DX, 8        ; L << 8
    ROL BX, 2        ; L << 2
    AND AX, DX       ; (L << 1) & (L << 8)
    XOR AX, BX       ; ((L << 1) & (L << 8)) ^ (L << 2)
    XOR AX, DI       ; (((L << 1) & (L << 8)) ^ (L << 2)) ^ (R ^ K)

    ROL EAX, 16
    POP AX

    POP BX
    POP DX

    RET