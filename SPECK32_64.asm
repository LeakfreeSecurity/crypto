;
; 32-bit x86 ASM implementation of SPECK 32/64 block cipher
; Author: Jos Wetzels
; 
;
; Speck is a family of lightweight (balanced feistel) block ciphers optimized for software performance, released by the NSA in 2013.
; See: http://eprint.iacr.org/2013/404.pdf
;
; The implementation below is SPECK 32/64 with blocksize 32, keysize 64 and 22 rounds.
;

;
; SPECK 32/64 sanity test
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

    MOV ECX, 22         ; Round count
    SUB ESP, 2*22       ; Key schedule memory
    MOV EAX, ESP
    CALL _schedule_key

    MOV ESI, EAX
    MOV EAX, 0x6574694c ; P

    CALL _speck_encrypt

    ; EAX = Ciphertext, ESI = key schedule
    CALL _speck_decrypt

    XOR EAX, 0x6574694c ; Decrypted plaintext
    RET

;
; SPECK 32/64 encrypt
;
; In:
;   EAX = plaintext
;   ESI = key schedule memory address
;
; Out:
;   EAX = ciphertext
;
_speck_encrypt:
    PUSH BX
    PUSH DX

    MOV ECX, 0
    _speck_e_loop:
        MOV DX, WORD [ESI+ECX*2]

        ; BX = R
        MOV BX, AX
        ; swap halves
        ROL EAX, 16
        ; AX = L

        CALL _speck_feistel_f

        ; swap halves
        ROL EAX, 16
        ; BX = R'
        MOV AX, BX

        INC ECX
        CMP ECX, 22
        JNE _speck_e_loop

    POP DX
    POP BX
    RET

;
; SPECK 32/64 decrypt
;
; In:
;   EAX = ciphertext
;   ESI = key schedule memory address
;
; Out:
;   EAX = plaintext
;
_speck_decrypt:
    PUSH BX
    PUSH DX

    MOV CX, 21
    _speck_d_loop:
        MOV DX, WORD [ESI+ECX*2]

        ; BX = R
        MOV BX, AX
        ; swap halves
        ROL EAX, 16
        ; AX = L

        CALL _speck_feistel_inv_f

        ; swap halves
        ROL EAX, 16
        ; BX = R'
        MOV AX, BX

        DEC CX
        CMP CX, -1
        JNE _speck_d_loop

    POP DX
    POP BX
    RET

;
; SPECK 32/64 key scheduler
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

    MOV WORD [EAX+0], DI    ; round_key[0] = K[0]

    ; llist
    SUB ESP, 2*24
    MOV EDI, ESP

    PUSH ECX

    MOV WORD [EDI+0], DX    ; llist[0] = K[1]
    MOV WORD [EDI+2], SI    ; llist[1] = K[2]
    MOV WORD [EDI+4], BX    ; llist[2] = K[3]

    MOV CX, 1

    _expansion_loop:
        CALL _expand_key_f

        MOV WORD [EAX + ECX*2], BX      ; round key
        MOV WORD [EDI + ECX*2 + 4], DX  ; l-list element

        INC ECX
        CMP ECX, DWORD [ESP]
        JNE _expansion_loop

    POP ECX
    ADD ESP, 2*24

    RET

;
; SPECK 32/64 key expansion function
;
; In:
;   EAX = memory address for schedule storage
;   EDI = memory address for l-list storage
;   CX = round index
;
; Out:
;   BX = KR
;   DX = l-list element
;
_expand_key_f:

    PUSH AX

    MOV EDX, ECX
    DEC DX                      ; DX = i = (CX-1)

    MOV BX, WORD [EAX + EDX*2]  ; BX = round_key[i]
    MOV AX, WORD [EDI + EDX*2]  ; AX = llist[i]

    CALL _speck_feistel_f

    MOV DX, AX
    POP AX

    RET

;
; SPECK 32/64 feistel function
;
; In:
;    AX = L
;    BX = R
;    DX = Ki
;
; Out:
;   EAX = ciphertext
;
_speck_feistel_f:
    ; n = 16 => alpha = 7, beta = 2
    ROR AX, 7   ; (L >> alpha)
    ADD AX, BX  ; ((L >> alpha) + R mod word_size)
    XOR AX, DX  ; L' = (((L >> alpha) + R mod word_size) ^ Ki)
    ROL BX, 2   ; (R << beta)
    XOR BX, AX  ; R' = ((R << beta) ^ (((L >> alpha) + R mod word_size) ^ Ki))
    RET

;
; SPECK 32/64 inverse feistel function
;
; In:
;    AX = L
;    BX = R
;    DX = Ki
;
; Out:
;   EAX = ciphertext
;
_speck_feistel_inv_f:
    ; n = 16 => alpha = 7, beta = 2
    XOR BX, AX  ; (R ^ L)
    ROR BX, 2   ; (R ^ L) >> beta
    XOR AX, DX  ; (L ^ Ki)
    SUB AX, BX  ; (L ^ Ki) - ((R ^ L) >> beta) mod word_size
    ROL AX, 7   ; (((L ^ Ki) - ((R ^ L) >> beta) mod word_size) << alpha)
    RET