# exploringVMP
temp location for sharing cool discoveries made while researching VMP [VMProtect 3.6 Ultimate DEMO]

02/12/2024 - at this rate I won't be sharing stuff so i'm just braindumping it... files are messes 

uses [pefile](https://github.com/erocarrera/pefile) and [iced_x86](https://github.com/icedland/iced)

- there are patterns you can make to find instructions that correspond to push someEncryptedAddr, call vmenter.
    - you can check if they're valid by confirming you can use the offset to calculate the address that corresponds to the push someEncryptedAddr portion (see image below in
  the section "Statically obtaining valid addresses for 'VM enter' and decrypting them.")

- also applicable to the decryption routine used to calculate location of the next starting point of the bytecode and location of table containing handlers 

# MUST READ

### VMProtect
* https://0xnobody.github.io/devirtualization-intro/
* https://www.msreverseengineering.com/blog/2014/6/23/vmprotect-part-0-basics
* https://blog.back.engineering/17/05/2021/
* https://www.mitchellzakocs.com/blog/vmprotect3
* https://whereisr0da.github.io/blog/posts/2021-01-05-vmp-1/
* https://secret.club/2021/09/08/vmprotect-llvm-lifting-1.html

### VMs
* https://synthesis.to/2021/10/21/vm_based_obfuscation.html
* https://www.msreverseengineering.com/blog/2018/2/21/devirtualizing-finspy-phase-4-second-attempt-at-devirtualization
* https://cis.temple.edu/~qzeng/papers/deobfuscation-icics2017.pdf
* https://blog.esetafrica.com/wp-content/uploads/2018/01/ESET%E2%80%99s-guide-to-deobfuscating-and-devirtualizing-FinFisher.pdf
* https://github.com/st4ckh0und/AntiOreans-CodeDevirtualizer

# stuff

made use of [my tool](https://github.com/mibho/x64dbg-vmp-trace) 

### Statically obtaining valid addresses for 'VM enter' and decrypting them.

![image](https://github.com/mibho/exploringVMP/assets/86342821/34d00143-16bb-4662-bf97-43131821e1bc)

![image](https://github.com/mibho/exploringVMP/assets/86342821/f94b0c1f-3f93-4f5e-bb0a-688537c69fc8)

no obvious relationships... 
  - no effect on read direction of bytecode
  - doesn't affect if push/ret or jmp qword ptr
  - only the DWORD portion of the addresses are used



![image](https://github.com/mibho/exploringVMP/assets/86342821/c5fec7d2-6cd5-4352-b1a1-9a58ad9e371c)

'scan' for 20 byte patterns that fit the requirement of:

```
push <encrypted_addr>
call vm_enter_fn
```

![image](https://github.com/mibho/exploringVMP/assets/86342821/47fd71e2-4d66-47f8-accd-24660d1fe2c8)


### Bytecode addresses scattered all around

![image](https://github.com/mibho/exploringVMP/assets/86342821/9fa5c11a-5162-49c4-a501-fb77818c9763)

![image](https://github.com/mibho/exploringVMP/assets/86342821/6c987270-a41d-4a78-8497-5e9533169817)

![image](https://github.com/mibho/exploringVMP/assets/86342821/ed834d6b-eb78-47e8-bc7b-80c1dee86a0c)


![image](https://github.com/mibho/exploringVMP/assets/86342821/4b3c887c-6a7a-46f1-b75b-ce6fbe5700c0)

![image](https://github.com/mibho/exploringVMP/assets/86342821/b3770c0e-eb0e-4442-8317-1ea7c802c8e0)


### Anti-disassembly tricks

this was one of the coolest things i saw (each binary seems to have a couple of these grouped together near the end)

![image](https://github.com/mibho/exploringVMP/assets/86342821/79baf84b-e228-4a06-bb1b-04b56a559bdc)


after manually re-analyzing 

![image](https://github.com/mibho/exploringVMP/assets/86342821/49986bd3-4dd3-4ba0-b367-e7ec2f3db748)





