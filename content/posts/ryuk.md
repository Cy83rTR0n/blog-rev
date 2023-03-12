---
title: "Ryuk"
date: 2023-03-12T17:13:36Z
draft: false
---

# Ryuk Malware

Below details are for stage 1

| Name | Ryuk Malware |
| --- | --- |
| 1. MD5	 | 5ac0f050f93f86e69026faea1fbb4450 |
| 2. SHA-1 | 9709774fde9ec740ad6fed8ed79903296ca9d571 |
| 3. SHA-256 | 23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2 |
| 4. File type	 | Win32 EX |

## Overview

It is a 2 stage malware, where the first stage when initiated suddenly vanishes from the system and drops the second stage to carry out the task of privilege escalation, persistence, and process injection. The details about how it carries out each stage are mentioned further in the report.

## Preliminary Analysis

### Snapshot from VirusTotal

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/25ce00c3-f8cf-4b21-8625-22f592338700/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T172500Z&X-Amz-Expires=86400&X-Amz-Signature=7c88a4a5921905da1ddb629a2a6bb748abef4bfa3ed9846b1c24b7ad483f4553&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

### Snapshot from HybridAnalysis

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%201.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/9dce3852-6754-4e9e-a370-88b4e9679204/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175655Z&X-Amz-Expires=86400&X-Amz-Signature=f21db4ac33d1a21651e088b5e11d2e2cb04f22b0a5fb3d0aa07098f0b02779f2&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

### MITRE ATT&CK Analysis

- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Exfiltration

**For better Visuals and info refer to the given links**

[https://www.hybrid-analysis.com/sample/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/5b78ac487ca3e1394667d414](https://www.hybrid-analysis.com/sample/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/5b78ac487ca3e1394667d414)

[https://www.virustotal.com/gui/file/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/](https://www.virustotal.com/gui/file/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/)

## Basic Analysis of Stage I

At the very start, we see that the ransomware tries to retrieve the Major version of the system and based on it drops the second stage either in of the specified paths.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%202.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/59291cd2-1dce-4182-8e50-4291008ad394/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175740Z&X-Amz-Expires=86400&X-Amz-Signature=eaea78f64aae69de96732aa4ca4c23e37c2aa4b38823c40529ab27560154a1ff&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

## Dynamic Analysis of Stage I

Later we see that an executable is made on the fly whose name is random 5 characters. later is appended with .exe extension.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%203.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/c31f2e7e-354c-4b28-9043-a6645fdf42c6/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175809Z&X-Amz-Expires=86400&X-Amz-Signature=77aaa2a51a6b54697edce71187404202aec926a275b6143ed3916a0df536d958&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

Later when it tries to create the file in the directory incase it fails the name of the file is kept as ryuV.exe, Hence a ‘V’ being replaced in place of ‘k’.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%204.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/1d37a588-899a-4fca-a1ba-0c809e805afc/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175840Z&X-Amz-Expires=86400&X-Amz-Signature=a6f5a7c922e0f8d72e2ccb2df2482ad045c7a3ea43f2a9fc1ec202622020daf0&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

After creation of the file, its time to load the malicious code inside of it. For this stage 1 checks whether the current process is running in 64 bit or 32 bit operating system using IsWowProcess(). Based on the result stage 1 loads code into the newly created file.

For getting the relevant imports of dlls Ryuk uses LoadlibraryA(”Kernel32.dll”) and GetProcAddress().

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%205.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/244f7bf8-709d-4827-9225-fd1590d14069/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175901Z&X-Amz-Expires=86400&X-Amz-Signature=8f4dd19483813393b1ecab9df3224f38918d405f604c41db7454b5fd7f349589&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

Finally once the file is ready Ryuk uses ShellExecuteW() to commit the file to the specified directory.

## Stage II

| SHA256 | 8b0a5fb13309623c3518473551cb1f55d38d8450129d4a3c16b476f7b2867d7d |
| --- | --- |

### Analysis

Well, this part is still a little mystery to me, however referring to the old analysis I came to this point once stage I has completed its job of making the second one it passes to it as a command line argument and deletes itself.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%206.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/0579e4c1-a944-4534-8903-568f0ed3012a/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T175926Z&X-Amz-Expires=86400&X-Amz-Signature=cbb4a42e9be55c375ae88f9bbb704d719cefea51dcf316b6882ed18660604125&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

To gain Persistence the ransomware uses the trick to add a run key to the registry.

![Untitled](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/5ac31cdc-1f31-4515-82c6-f07689daa04c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180003Z&X-Amz-Expires=86400&X-Amz-Signature=22bce52284100c451b4e50b5a7e91c1d66e924ff2f97cbdaedce74684f0a24f6&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject)

the full command goes like 

```powershell
C:\Windows\System32\cmd.exe /C REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "svchos" /t REG_SZ /d "C:\users\Public\BPWPc.exe" /f
```

Further we check that whether the current user has a “SeDebugPrivilege” using its LUID. Incase it is not there it adjust the privilege using AdjustTokenPrivileges(). Hence Privilege of the current process is escalated because we need special permissions to perform the next attack.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%208.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/0b20f569-71c7-4220-87c8-ccdff64689f2/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180029Z&X-Amz-Expires=86400&X-Amz-Signature=bf549ececfba9e07a5fb50d07e5c4c32d7a8d63db4a98fe01229fc9721c4e612&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

Next the ryuk looks whether the Domain name is NTA or not. Based on that it set the values of the array in which different process’s details are collected.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%209.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/12f70da7-f4ad-4916-b348-c8ae8b09469e/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180047Z&X-Amz-Expires=86400&X-Amz-Signature=294688b1ce1d5561e65ee7d97c3e85794e4b623381697ddf3bda9d01be0ae07c&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

In the following screenshots we see that ryuk uses process injection technique. It does this by virtually allocating room for the code and then writing to it.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2010.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/6e44b263-7626-4175-a625-459b64016074/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180110Z&X-Amz-Expires=86400&X-Amz-Signature=f9a4958c64005dc0539d595864be533e2a4e69433f2ea6663a4acd4e6b73717e&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2011.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/d3cbb82f-b9a0-4480-b688-4f9d2c8b4e2f/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180127Z&X-Amz-Expires=86400&X-Amz-Signature=58d8117962cab4a56660c5393d376a6e828ecb6aaf8c5c7d0e96be09415772b8&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

### Encryption Process

For encryption purposes the malware uses 

- CryptEncrypt
- CryptGenKey
- CryptDecrypt
- CryptAquireContextW
- CryptDestroyKey
- CryptDeriveKey
- CryptImportKey

They are all a part of ADVapi32.dll 

Each encryption thread starts by generating a random 256 AES encryption. 

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2012.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/85f12bb2-f91a-411e-8a18-bc7877433853/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180156Z&X-Amz-Expires=86400&X-Amz-Signature=d49ef906bd6e5331ed99f657e302946473a6f289d8366bbd6a92bf42f8622f41&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2013.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/e1b24189-a827-4022-a35e-ca0a9745906f/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180215Z&X-Amz-Expires=86400&X-Amz-Signature=92f6a87d3f58d5cea8055938454e88296e3fc3f4d4080b22e8f8a5b453f38898&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

After every file is encrypted we see that “HERMES” is being padded to each and every file

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2014.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/ddf7233b-1d4a-4cb3-8f85-008af8ad9bb1/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180236Z&X-Amz-Expires=86400&X-Amz-Signature=95d972b2d22d906849faa7efaf1abb9c25b1eb3beb9b293e24beed8665858ee6&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

it checks if a file is going to get encrypted twice.

![Untitled]([Ryuk%20Malware%201c5ef46338974ae08252bd9df54da398/Untitled%2015.png](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/1b9c71a2-f2f9-458d-b277-bf4a979c42a8/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230312%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230312T180258Z&X-Amz-Expires=86400&X-Amz-Signature=5bcba113064edcd3c537e73576e92bee98450fe7a6eada31b8366dd721a89708&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22Untitled.png%22&x-id=GetObject))

The important apis used in malware are as follows :

- CryptEncrypt
- CryptGenKey
- CryptDecrypt
- CryptAquireContextW
- CryptDestroyKey
- CryptDeriveKey
- CryptImportKey
- VirtualFree
- WriteProcessMemory
- VirtualAllocEx
- LookupPrivilegeValue
- GetProcAddress
- AdjustTokenPrivilege
- ShellExecuteW
- FreeLibrary
- CreateRemoteThread
