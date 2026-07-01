---
title: Old but Gold
date: 2026-07-01
categories:
  - Malware
  - WannaCry
  - Ransomware
tags:
  - cybersecurity
  - malware
  - wannacry
  - ransomware
  - multistage
  - reverse engineering
  - static analysis
  - cti
---


I have been working towards reverse engineering native Portable Executables(PE) for awhile now and although I haven't finished Maldev Academy I have become impatient. Hence I decided to throw myself a softball and look at an older piece of malware. In comes WannaCry; in 2017 this thing wreaked havoc all over the world and is still known as one of the largest ransomware attacks in history. It had worm like tendencies as it spread over the globe by taking advantage of an SMB vulnerability [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) commonly known as Eternal Blue, which was found in a massive amount of Windows machines in use back then. Nowadays researchers know WannaCry like the back of their hand and any threat actor wanting to use it would get absolutely nowhere. 

With all that said, WanaCry (from a learning standpoint) it's practically a goldmine. Because it's so old and well documented, if you can't figure it out, someone somewhere has a writeup just waiting for you to read. This is what I like to call a learning opportunity! 

With this in mind I decided to go into WannaCry blind, that way if I crack it I have proof of progress and if I don't I have plenty of learning opportunities to take advantage of. Win win.

As usual I went looking for WanaCry on Malwarebazaar, and to my surprise found a sample that was posted fairly recently.

![Bazaar](assets/img/WannaCry/Bazaar.png)

### Getting into the sample

I instantly wanted to throw this thing at every tool I could think of and start tearing it to pieces. Instead I took a step back and thought about how to best approach it in  a more structured way, I needed to work on my methodology so I have a repeatable process I can follow.

I started by taking look at the surface level of the sample by uploading it to Detect It Easy(DIE). 
This showed me very little in its initial scan overview.

![DIE-Scan](assets/img/WannaCry/DIE-scan.png)

But the imports were very promising.

![DIE-Imports](assets/img/WannaCry/DIE-imports.png)

As soon as I seen the imports I took interest in the `CreateFileA` API, I also made note of the `IsDebuggerPresent` API meaning there are anti analysis techniques present.

Now that I had a target to go after I imported the sample into Ghidra and went digging. Once I found the `CreateFileA` API I looked at its call tree to see what functions called it. This is when I came across the "PlayGame" function.

![CreateFileA](assets/img/WannaCry/Createfile-func.png)

The PlayGame function seems to do 2 things: call `sprintf` with a string argument of "C:\WINDOWS\mssecsvc.exe" then calls 2 other functions.

![PlayGame](assets/img/WannaCry/PlayGame.png)

The first function called is loading what could possibly be another payload from its resources (.rsc) section and writing it to a file that I am betting is the above mentioned "mssecsvc.exe".

![First-Func](assets/img/WannaCry/Func-1014.png)

In the second function I noticed the `CreateProcessA` [API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) being called with its creation flag set to 0x8000000 ([Create_No_Window](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)).

![Second-Func](assets/img/WannaCry/Func-10f8.png)


I noticed that all three of these reference an address location `&DAT_18000d2a0` which reinforces my idea that this loads a payload from the resource section, writes it into "mssecsvc.exe", then executes it stealthy via the `CreateProcessA` API. That means this thing is multi staged!

### Stage 1

Looking at the samples resource section in PEStudio instantly confirms that it had a second payload hidden within itself. 

![Stage1](assets/img/WannaCry/Stage1.png)

I dump it to file to start digging into it next.

![Stage1-Dump](assets/img/WannaCry/Stage1-dump.png)

I noticed there were some extra characters before MZ, `00 D0 38 00`. I looked into this before making any changes to the binary and found out this is more than likely padding to throw off detection, notice how DIE reports it as an unknown binary.

![DIE-unknown](assets/img/WannaCry/DIE-unknown.png)

To get around this I open the dump in a hex editing tool called [010 Editor](https://www.sweetscape.com/010editor/) and remove the padding.

![010](assets/img/WannaCry/010.png)

Now when uploading to DIE the results are what you would typically see from a PE, with warnings about malicious content this time.

![DIE-stage1](assets/img/WannaCry/DIE-Stage1.png)

The imports for Stage1 are very interesting. It looks like it loads another payload from its resource section and also calls out to a URL.

![Stage1-Kernel32](assets/img/WannaCry/stage1-kernel32-imports.png)
![Stage1-WinInet](assets/img/WannaCry/Stage1-Wininet.png)

Going straight for the `InternetOpenUrl` API you can see it builds out a URL on the stack (http://www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com) reaches out to it and then performs a function.

![InternetOepnUrl](assets/img/WannaCry/InternetOpenUrl.png)

The function it executes after has another function in it that does a few things, most notably it calls yet another function.

![Stage1-Func](assets/img/WannaCry/func-8090.png)

The first one creates a service with an all to familiar name "mssecsvc2.0" and makes it an [auto start service](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea) for persistence.

![CreateService](assets/img/WannaCry/autostart.png)
![Function-Tree](assets/img/WannaCry/tree.png)

Based on what else you can see in the function tree the second function loads a payload from the resource section once again. 


### Final Payload

I throw Stage1 into PEStudio and it instantly recognizes there is an executable in the resources section.

![PEStudio-final](assets/img/WannaCry/pestudio-final.png)

Having DIE scan it, it is in fact a PE.

![DIE-final](assets/img/WannaCry/stage2-die.png)

The imports for the final stage tell a lot. We see it not only creating files but also reading them and moving them, there are also references to registry editing and possibly encryption.

![stage2-32import](assets/img/WannaCry/s2-kernal.png)
![Stage2-Advapi](assets/img/WannaCry/s2-advapi-imports.png)

I throw it into Ghidra and this time I start at the entry point and notice that of all the functions called only the last one has any arguments.

![Func-arg](assets/img/WannaCry/func-arg.png)

Now this function seemed to be where all the magic happens. It mentions copying an executable named tasksche.exe which may have been dropped by the previous payload or  utilizes "mssecsvc.exe" in some way, either way I am thinking it is for persistence via a scheduled task that runs a service that starts automatically. 

![Main-func](assets/img/WannaCry/Main-func.png)

There are 3 other functions worth note here as well.  The first one seems to be creating registry key entries most likely for more persistence.

![Reg](assets/img/WannaCry/reg.png)

The second one has a hardcoded argument of "WNcry@2ol7" and loads something from its resource section.

![Loadrsc](assets/img/WannaCry/loadrsc.png)

This last one at first glance looks like it is doing a lot of creating, reading, writing, moving, and deleting of files, but before I get into that, I wanted to take a look at the function called right before all of this takes place.

![FileManipulation](assets/img/WannaCry/file-mani.png)

Just as I suspected it is running the files through an encrypting process, renaming them, and then deleting the originals.

![Encrypt](assets/img/WannaCry/encrypt.png)


### The Zip
As mentioned earlier the final payload loads something from its resources section and one of the arguments for the function that performs this is "WNcry@2ol7". Well come to find out it was a self extracting zip file that contained some very interesting findings. 

![zipextract](assets/img/WannaCry/zipextract.png)

As you can see there are multiple different file types in use here.

b.wnry is an image with instructions on how to decrypt your files presumably after you have paid them.

![bwnry](assets/img/WannaCry/bwnry.png)

c.wnry is a list of tor addresses and the URL to download tor browser.

![c.wnry](assets/img/WannaCry/cwnry.png)

r.wnry is a list of questions and answers providing the victim with ways to pay the ransom and even support if needed.

![r.wnry](assets/img/WannaCry/rwnry.png)

s.wnry was another Zip file that contained a bunch of dlls, that by just looking at their imports is what is used for encryption of the victims documents.

![s.wnry](assets/img/WannaCry/swnry.png)
![encrypt-imports](assets/img/WannaCry/encrypt-imports.png)

And finally the msg folder contained the ransom note in a plethora of languages.

![msg](assets/img/WannaCry/msg.png)
### Conclusions
The initial payload was a resource based dropper that would create a file that would be executed later as a service. The embedded payload from the dropper (stage 1) also contained an additional payload in its resources section (stage 2). Where stage 1  differs from the dropper is that stage 1 would reach out to a URL before writing its payload (stage 2) to disk and creating it as an auto starting service. The final payload (stage 2) yet again included something in its resources section, this time a self extracting archive. Stage 2 set registry keys, loaded the file from its resources section, and handled the encryption once the dlls were loaded from the self extracting archive. The self extracting archive also included tor addresses, ransom notes, and  instructions for the victims to follow for payment and recovery of their data.


Even though this was a much older piece of malware it was a much needed win in my book. It gave me the hands on experience I have been needing since I first started wanting to reverse engineer malware. My main focus was static analysis and it will be for awhile until I feel like I have a good solid grip on it to give myself a strong base before moving into dynamic analysis. I also really enjoyed picking up on the patterns that this malware author used, like the choice to embed their stages inside the resources section. From what I understand this is part of how threat hunters ID and profile malware families that threat actors like to use which helps with their hunting process.


## IOCs

**Hashes:**

| Filename                                                             | SHA-256                                                          |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| 20f6007455a6cffcd1f2bb0614c00530a2f5cc96efedd2e49a67aa16bf66e3af.exe | 20f6007455a6cffcd1f2bb0614c00530a2f5cc96efedd2e49a67aa16bf66e3af |
| b.wnry                                                               | d5e0e8694ddc0548d8e6b87c83d50f4ab85c1debadb106d6a6a794c3e746f4fa |
| c.wnry                                                               | 055c7760512c98c8d51e4427227fe2a7ea3b34ee63178fe78631fa8aa6d15622 |
| r.wnry                                                               | 402751fa49e0cb68fe052cb3db87b05e71c1d950984d339940cf6b29409f2a7c |
| s.wnry                                                               | d3c861a53f14fc9c85258b8dfcda074af81506578b9a00afcf08177c62d2c135 |
| Stage1.dump                                                          | 026f1e8f1473723486085794d6112f7673d9315decb44907252bcef280425294 |
| Stage2.dump                                                          | 837aa77b122962862d55e37c10f1544db08aaaf095d877e6265d7025334343b5 |
| thezip.dump                                                          | c9126aaf37b2cb3f5945224f74f290f35d82459fd02e2b1e8a1b0525cdc01206 |
| m_bulgarian.wnry                                                     | 40b37e7b80cf678d7dd302aaf41b88135ade6ddf44d89bdba19cf171564444bd |
| m_chinese (simplified).wnry                                          | 845d0e178aeebd6c7e2a2e9697b2bf6cf02028c50c288b3ba88fe2918ea2834a |
| m_chinese (traditional).wnry                                         | 5c7f6ad1ec4bc2c8e2c9c126633215daba7de731ac8b12be10ca157417c97f3a |
| m_croatian.wnry                                                      | 3f33734b2d34cce83936ce99c3494cd845f1d2c02d7f6da31d42dfc1ca15a171 |
| m_czech.wnry                                                         | 5afa4753afa048c6d6c39327ce674f27f5f6e5d3f2a060b7a8aed61725481150 |
| m_danish.wnry                                                        | a75bb44284b9db8d702692f84909a7e23f21141866adf3db888042e9109a1cb6 |
| m_dutch.wnry                                                         | 2c95bef914da6c50d7bdedec601e589fbb4fda24c4863a7260f4f72bd025799c |
| m_english.wnry                                                       | 26fd072fda6e12f8c2d3292086ef0390785efa2c556e2a88bd4673102af703e5 |
| m_filipino.wnry                                                      | d8489f8c16318e524b45de8b35d7e2c3cd8ed4821c136f12f5ef3c9fc3321324 |
| m_finnish.wnry                                                       | 1adfee058b98206cb4fbe1a46d3ed62a11e1dee2c7ff521c1eef7c706e6a700e |
| m_french.wnry                                                        | 9bd38110e6523547aed50617ddc77d0920d408faeed2b7a21ab163fda22177bc |
| m_german.wnry                                                        | 2adc900fafa9938d85ce53cb793271f37af40cf499bcc454f44975db533f0b61 |
| m_greek.wnry                                                         | e13cc9b13aa5074dc45d50379eceb17ee39a0c2531ab617d93800fe236758ca9 |
| m_indonesian.wnry                                                    | 23e5e738aad10fb8ef89aa0285269aff728070080158fd3e7792fe9ed47c51f4 |
| m_italian.wnry                                                       | 49f2c739e7d9745c0834dc817a71bf6676ccc24a4c28dcddf8844093aab3df07 |
| m_japanese.wnry                                                      | 7e491e7b48d6e34f916624c1cda9f024e86fcbec56acda35e27fa99d530d017e |
| m_korean.wnry                                                        | 552aa0f82f37c9601114974228d4fc54f7434fe3ae7a276ef1ae98a0f608f1d0 |
| m_latvian.wnry                                                       | a0356696877f2d94d645ae2df6ce6b370bd5c0d6db3d36def44e714525de0536 |
| m_norwegian.wnry                                                     | cb5da96b3dfcf4394713623dbf3831b2a0b8be63987f563e1c32edeb74cb6c3a |
| m_polish.wnry                                                        | 519ad66009a6c127400c6c09e079903223bd82ecc18ad71b8e5cd79f5f9c053e |
| m_portuguese.wnry                                                    | bd9f4b3aedf4f81f37ec0a028aabcb0e9a900e6b4de04e9271c8db81432e2a66 |
| m_romanian.wnry                                                      | 70c0f32ed379ae899e5ac975e20bbbacd295cf7cd50c36174d2602420c770ac1 |
| m_russian.wnry                                                       | 02932052fafe97e6acaaf9f391738a3a826f5434b1a013abbfa7a6c1ade1e078 |
| m_slovak.wnry                                                        | e64178e339c8e10eac17a236a67b892d0447eb67b1dcd149763dad6fd9f72729 |
| m_spanish.wnry                                                       | 72f20024b2f69b45a1391f0a6474e9f6349625ce329f5444aec7401fe31f8de1 |
| m_swedish.wnry                                                       | 146f61db72297c9c0facffd560487f8d6a2846ecec92ecc7db19c8d618dbc3a4 |
| m_turkish.wnry                                                       | 6db650836d64350bbde2ab324407b8e474fc041098c41ecac6fd77d632a36415 |
| m_vietnamese.wnry                                                    | 1f21838b244c80f8bed6f6977aa8a557b419cf22ba35b1fd4bf0f98989c5bdf8 |
| libeay32.dll                                                         | 58be53d5012b3f45c1ca6f4897bece4773efbe1ccbf0be460061c183ee14ca19 |
| libevent-2-0-5.dll                                                   | 77a250e81fdaf9a075b1244a9434c30bf449012c9b647b265fa81a7b0db2513f |
| libevent_core-2-0-5.dll                                              | 5cd126b4f8c77bdf0c5c980761a9c84411586951122131f13b0640db83f792d8 |
| libevent_extra-2-0-5.dll                                             | 957d58061a42ca343064ec5fb0397950f52aedf0594a18867d1339d5fbb12e7e |
| libgcc_s_sjlj-1.dll                                                  | 9aeccf88253d4557a90793e22414868053caaab325842c0d7acb0365e88cd53b |
| libssp-0.dll                                                         | f28caebe9bc6aa5a72635acb4f0e24500494e306d8e8b2279e7930981281683f |
| ssleay32.dll                                                         | bd70ba598316980833f78b05f7eeaef3e0f811a7c64196bf80901d155cb647c1 |
| zlib1.dll                                                            | e68f79d90f58dea50c8f28a525153476167e407da77aaa265cba2e2e9f0914b7 |

**IPs:**

| IP                                                           |
| ------------------------------------------------------------ |
| http://www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com |
| gx7ekbenv2riucmf[.]onion                                     |
| 57g7spgrzlojinas[.]onion                                     |
| xxlvbrloxvriy2c5[.]onion                                     |
| 76jdd2ir2embyv47[.]onion                                     |
| cwwnhwhlz52maqm7[.]onion                                     |

#### MITRE ATT&CK and Malware Behavior Catalog:


**[Dropper](https://mandiant.github.io/capa/explorer/#/analysis?rdoc=https://raw.githubusercontent.com/W4llyw/Blog/refs/heads/main/Capa/WanaCry/WanaCry-Loader.json)**

**[Stage 1](https://mandiant.github.io/capa/explorer/#/analysis?rdoc=https://raw.githubusercontent.com/W4llyw/Blog/refs/heads/main/Capa/WanaCry/WanaCry-Stage1.json)**

**[Stage 2](https://mandiant.github.io/capa/explorer/#/analysis?rdoc=https://raw.githubusercontent.com/W4llyw/Blog/refs/heads/main/Capa/WanaCry/WanaCry-Stage2.json)**
