---
title: Mapped Section Injection
date: 2026-06-09
categories:
  - Learning
  - Reverse Engineering
tags:
  - malware
  - learning
  - reverse engineering
  - injection
---
### What it is
Imagine you and a coworker are working on the same project. You, being the project leader, create a collaborative space that you can both access. As the project lead, any changes made by you to the project they can see, and any tasks you create in the shared space they are voluntold to do. This is basically what mapping injection is. A mapped space of memory is shared between processes (the collaborative space) and anything done within the shared memory space  is carried out for both processes. The malicious process (project leader) can place a payload within this shared map then force the other process (coworker) to execute it by pointing to its address. This is where mapping injection can really takeoff because it now can force a legitimate process to execute its payload either by process injection, APC injection, or thread hijacking.

This places mapping injection into multiple sub techniques within MITRE:
[T1055](https://attack.mitre.org/techniques/T1055/):
	[T1055.002 - PE Injection](https://attack.mitre.org/techniques/T1055/002/)
	[T1055.003 - Thread Hijacking](https://attack.mitre.org/techniques/T1055/003/)
	[T1055.004 - APC Injection](https://attack.mitre.org/techniques/T1055/004/)

### How this is done and why
The way mapping injection works is by using 3 WinAPIs `CreateFileMapping`, `MapViewOfFile`, and `MapViewOfFile2`. `CreateFileMapping` creates a file mapping object that maps to a files content on disk into memory, then `MapViewOfFile` takes the handle of the mapping object returned by `CreateFileMapping` and maps it into the address space of a process. `MapViewOfFile2` is used to map that same mapping object's address into a remote process. A malicious payload is then written to the mapped section which will be updated for both the `MapViewOfFile` and the `MapViewOfFile2`. Now that another process shares that same mapped address of malicious code the legitimate remote process/thread is created in a suspended state. Then it gets told that its next instruction (EIP or RIP) is the malicious code's address in memory. Once the thread or process is resumed it results in the malicious payload being executed.
The reason this is used in malware is because with other techniques that use things like `VirtualAlloc` and `VirtualAllocEx` they create 'private' memory types, and these types are heavily monitored by any decent EDR or AV. When performing mapping injections the memory type that is created is of the 'mapped' type which is used by other applications like DLLs and other common executables. This creates a lot of noise for the malicious action to hide in and away from EDR. 

### The Reverse
Now the big question is how would you catch this in the wild?
This took me a bit to figure out as I wasn't sure where to look if I wanted to catch the payload before execution. Eventually, what I landed on was the `MapViewOfFile` WinAPI. My thought process was if the payload needs to be placed within the shared memory space it has to be updated in the map view.

![MapViewOfFile BP](assets/img/Mapping-Injection/MapViewOfFile-bp.png)

I place a breakpoint at the `MapViewOfFile` WinAPI and ran the debugger. This lands me at the address that `MapViewOfFile` is called. What I'm looking for is the base address of where the payload will be stored, that way when it is populated with the payload I will be able to see it and extract it. More than likely this will be in the RAX register since it will be returned by this function. For the returned function to show up I will need to hit 'Execute until return' once at the `MapViewOfFile` breakpoint. This will populate an address in the RAX register. From there right click and follow the address that is currently at RAX in the dump.

![Follow in Dump](assets/img/Mapping-Injection/Follow-in-dump.png)

At the first byte in the dump I place a hardware breakpoint, because I want to catch it not execute it. Notice that it is empty to make space for the payload.

![Hardware BP](assets/img/Mapping-Injection/Hardware-bp.png)

Now all that is left to do is continue to run the application, and like that it pauses at my hardware breakpoint and the malicious payload is in the dump.

![Payload Found](assets/img/Mapping-Injection/Payload-found.png)

From here you can extract the payload get is hashes and start diving into what all it does. :)

### Conclusion
This technique avoids the use of `VirtualAlloc` and `VirtualAllocEx` to create a less detectable memory type by using section mapping. It's a great demonstration of just how deep the bag of evasion tradecraft can be. The deeper I go into malware analysis and reverse engineering, the more apparent it becomes that the pattern recognition that so many reverse engineers say "jumps out at them" is all from hands on experience. There is so much still to learn and the techniques are ever growing, I know this can feel disheartening. But this is where everyone starts. If you're on this path keep moving forward and you will get there; every analyst writing the technical blogs you're reading now all stood here. 