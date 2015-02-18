;
; 32-bit x86 ASM implementation of SIMON 32/64 block cipher
; Author: Jos Wetzels
; 
;
; Simon is a family of lightweight (balanced feistel) block ciphers optimized for hardware performance, released by the NSA in 2013.
; See: http://eprint.iacr.org/2013/404.pdf
;
; The implementation below is SIMON 32/64 with blocksize 32, keysize 64 and 32 rounds and has not been optimized yet.
; Currently, only encryption is supported with key expansion integrated in the round function.
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

    MOV EAX, 0x65656877 ; Plaintext
    MOV DI, 0x0100      ; K0
    MOV DX, 0x0908      ; K1
    MOV SI, 0x1110      ; K2
    MOV BX, 0x1918      ; K3

    CALL _simon_encrypt

    XOR EAX, 0xC69BE9BB ; Ciphertext
    RET

;
; SIMON 32/64 encryption function
;
; In:
;   EAX = plaintext
;   DI = K0
;   DX = K1
;   SI = K2
;   BX = K3
;
; Out:
;   EAX = ciphertext
;
_simon_encrypt:

    MOV CX, 0
    _simon_e_loop:
        CALL _simon_round
        INC CX
        CMP CX, 32
        JNE _simon_e_loop

    RET

;
; SIMON 32/64 round function
;
; In:
;   EAX = plaintext
;   DI = K0
;   DX = K1
;   SI = K2
;   BX = K3
;   CX = round index
;
; Out:
;   EAX = ciphertext
;   DI = K1
;   DX = K2
;   SI = K3
;   BX = KR
;
_simon_round:

    PUSH DX
    PUSH SI
    PUSH BX

    CMP CX, 4
    JL _feistel_round

    _expand_key:    
        PUSH AX
        PUSH CX

            PUSH 0x9BC34AF4 ; periodic sequence
            PUSH 0xCD6125FA ; periodic sequence

            ; AL, AH  = ((I-4) / 8)
            XOR AH, AH
            MOV AL, CL
            SUB AL, 4
            MOV CL, 8
            DIV CL

            MOV CL, AH
            XOR AH, AH
            MOV ESI, ESP
            ADD SI, AX

            ; AL = (10000000 >> AH)
            MOV AL, 0x80
            ROR AL, CL

            ; (zi)j is AH-th bit of AL-th byte in periodic sequence
            AND AL, BYTE [ESI]

            INC CL
            ROL AL, CL

            ; SI = SEQ(I-4)
            MOV SI, AX

            ADD ESP, 8

        POP CX
        POP AX

        XOR DI, 0xFFFC  ; K0 ^ C
        XOR DI, SI      ; K0 ^ C ^ SEQ(I-4)

        ROR BX, 3       ; K3 >> 3
        XOR BX, DX      ; (K3 >> 3) ^ K1
        MOV DX, BX      ; (K3 >> 3) ^ K1
        ROR BX, 1       ; ((K3 >> 3) ^ K1) >> 1
        XOR DI, BX      ; (K0 ^ C ^ SEQ(I-4)) ^ (((K3 >> 3) ^ K1) >> 1)
        XOR DI, DX      ; (K0 ^ C ^ SEQ(I-4)) ^ (((K3 >> 3) ^ K1) >> 1) ^ ((K3 >> 3) ^ K1)

    _feistel_round:
        MOV SI, AX
        ROL EAX, 16
        MOV DX, AX
        MOV BX, AX

        PUSH AX

            ROL AX, 1        ; L << 1
            ROL DX, 8        ; L << 8
            ROL BX, 2        ; L << 2
            XOR SI, DI       ; R ^ K
            AND AX, DX       ; (L << 1) & (L << 8)
            XOR AX, BX       ; ((L << 1) & (L << 8)) ^ (L << 2)
            XOR AX, SI       ; (((L << 1) & (L << 8)) ^ (L << 2)) ^ (R ^ K)
            ROL EAX, 16

        POP AX

    _shift_key:
        MOV BX, DI
        POP SI
        POP DX
        POP DI

    _end_simon_round:

        RET