format PE64 console
entry start

include 'win64a.inc'

section '.data' data readable writeable 
    information_s db "PE PARSER",10,0
    dos_format    db '--- DOS HEADER ---', 10,\
                     'Magic: %X (%c%c)', 10,\
                     'e_cp:  %d', 10,\
                     'e_lfanew: 0x%X', 10, 0

    lin db "---------------------------",10,0

    file_format db '--- FILE HEADER ---', 10,\
                   'Machine: 0x%X', 10,\
                   'Sections: %d', 10,\
                   'TimeDateStamp: 0x%X', 10, 0

    opt_format db '--- OPTIONAL HEADER ---', 10,\
              'Entry Point: 0x%X', 10,\
              'Image Base:  0x%llX', 10,\
              'Size of Image: 0x%X', 10, 0

    dir_format db '--- DATA DIRECTORIES ---', 10,\
              'Export Table RVA: 0x%X (Size: 0x%X)', 10,\
              'Import Table RVA: 0x%X (Size: 0x%X)', 10, 0

    sec_format db '--- SECTION [%d] ---', 10,\
              'Name: %.8s', 10,\
              'VAddress: 0x%X', 10,\
              'RawOffset: 0x%X', 10, 0

    dll_format db 'Imported DLL: %s', 10, 0
    func_format db '    |-- Funcion: %s', 10, 0
    ord_format  db '    |-- Ordinal:  %d', 10, 0

    peb_format db '--- PEB DEBUGG ---', 10,\
                 'BeingDebugged: %d', 10, 0


    hMod dq 0

section '.text' code readable executable
start:
                sub rsp, 48h                

                lea rcx, [information_s]
                call [printf]
                call [_getch]

                xor rcx, rcx 
                call [GetModuleHandleA]
                mov [hMod], rax 

                cmp word [rax], 0x5A4D
                jne exit_program

                mov rbx, rax                
    
                lea rcx, [dos_format]       
                movzx rdx, word [rbx]       
                mov r8, rdx
                and r8, 0xFF                
                mov r9, rdx
                shr r9, 8                   

                movzx rax, word [rbx + 0x04] 
                mov [rsp + 32], rax         
    
                mov eax, dword [rbx + 0x3C]
                mov [rsp + 40], rax         

                call [printf]
                lea rcx, [lin]
                call[printf]

                mov eax, dword [rbx + 0x3C]
                add rbx, rax                
    
                cmp dword [rbx], 0x00004550
                jne exit_program

                movzx rdx, word [rbx+4]
                movzx r8, word [rbx+6]
                mov r9d, dword [rbx+8]

                lea rcx, [file_format]
                call[printf]
                call[_getch]

                lea rcx, [lin]
                call[printf]

                mov edx, dword[rbx+40]
                mov r8, qword[rbx+48]
                mov r9d, dword[rbx+80]

                lea rcx, [opt_format]
                call[printf]
                call[_getch]

                lea rcx, [lin]
                call[printf]

                mov edx, dword[rbx+136]
                mov r8d, dword[rbx+136+4]

                mov r9d, dword[rbx+144]

                mov eax, dword[rbx+144+4]
                mov [rsp+32], rax 

                lea rcx, [dir_format]
                call[printf]
                call[_getch]

                lea rcx, [lin]
                call[printf]

                movzx rsi, word [rbx + 6]    
                movzx rax, word [rbx + 20]   
                lea r12, [rbx + 24]          
                add r12, rax                 
    
                xor r13, r13                 

.section_loop:
                inc r13                      
    
                push rsi                     
                push r12                     
                push r13                     
    
                sub rsp, 40                  

                lea rcx, [sec_format]        
                mov rdx, r13                 
                lea r8, [r12]                
                mov r9d, dword [r12 + 12]    
    
                mov eax, dword [r12 + 20]    
                mov [rsp + 32], rax 

                call [printf]
                call[_getch]
    
                add rsp, 40                  
                pop r13 r12 rsi              

                add r12, 40                  
                dec rsi                      
                jnz .section_loop            

                lea rcx, [lin]
                call[printf]

                mov eax, dword [rbx + 144]   
                test eax, eax
                jz .all_done
    
                mov r14, [hMod]
                add r14, rax                

.dll_loop:
                mov eax, dword [r14 + 12]   
                test eax, eax               
                jz .all_done

                lea rcx, [dll_format]       
                mov rdx, [hMod]
                add rdx, rax                
                mov r9, rdx                 

                push r14 r9                 
                sub rsp, 32                 
                call [printf]
                add rsp, 32
                pop r9 r14

                mov eax, dword [r14]        
                test eax, eax               
                jnz .has_int
                mov eax, dword [r14 + 16]   

.has_int:
                mov r10, [hMod]
                add r10, rax                

.next_function:
                mov r11, [r10]              
                test r11, r11               
                jz .skip_to_next_dll

                mov rax, 0x8000000000000000
                test r11, rax
                jnz .skip_func_name         

                add r11, [hMod]             
                add r11, 2                  

                push r14 r10 r9             
                sub rsp, 32                 
                lea rcx, [func_format]      
                mov rdx, r11                
                call [printf]
                add rsp, 32
                pop r9 r10 r14

.skip_func_name:
                add r10, 8                  
                jmp .next_function

.skip_to_next_dll:
                call [_getch]               
                add r14, 20                 
                jmp .dll_loop

.all_done:
                call DEBUGGED

DEBUGGED:
                lea rcx, [lin]
                call[printf]

                mov rbx, [gs:60h]
                movzx eax, byte [rbx+0x02]

                xor rdx, rdx 
                mov dl, al 

                lea rcx, [peb_format]
                call[printf]
                call[_getch]
                ret

exit_program:
                call [_getch]
                xor rcx, rcx
                call [ExitProcess]

section '.idata' import data readable
    library kernel32, 'KERNEL32.DLL',\
            msvcrt,   'MSVCRT.DLL'

    import kernel32,\
           GetModuleHandleA, 'GetModuleHandleA',\
           ExitProcess,      'ExitProcess'

    import msvcrt,\
           printf, 'printf',\
           _getch, '_getch'
