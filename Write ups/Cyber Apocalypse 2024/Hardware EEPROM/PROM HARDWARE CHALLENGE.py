# 48 54 42 7b 41 54 32 38 43 31 36 5f 45 45 50 52 4f 4d 5f 73 33 63 32 33 74 5f 31 64 21 21 21 7d
# HTB{AT28C16_EEPROM_s3c23t_1d!!!}
# https://pdf1.alldatasheet.com/datasheet-pdf/view/56113/ATMEL/AT28C16.html

from pwn import *
context.log_level = 'debug'
conn = remote('94.237.61.21', 35799)
print(conn.clean())
conn.sendline('set_we_pin(0)')
conn.sendline('set_ce_pin(5)')
conn.sendline('set_oe_pin(5)')
received_bytes = []

for i in range(32):
    # i=31
    modified_array = [5, 12.0, 5, 5, 5, 5, 0, 0, 0, 0, 0]
    binary_array = [0] * 5
    i2 = i
    ar =  [int(j) for j in [*bin(i2)[2:].rjust(5, '0')]]
    print(ar)
    for j in range(5):
        if ar[j] == 1:
            print(ar[j])
            modified_array[j+6] = 5

    conn.sendline(f'set_address_pins({modified_array})')
    conn.sendline('read_byte()')
    print(conn.clean())

conn.close()

