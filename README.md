# Intel SGX Tutorial and Demo
(c) 2023 - Graham Ade

Licensed under [GPLv3](https://www.gnu.org/licenses/)

A program utilizing Intel Software Guard Extensions (SGX) to create an enclave and store secrets.

The guide will walk you through building and installing the Intel SGX Driver, SDK (Software Development Kit), and PSW (Platform Software) on Debian/Ubuntu-based GNU/Linux systems.

## Introduction

### What is Intel SGX?

Intel Software Guard Extensions (SGX) is a security technology designed to enchance the protection of sensitive code and data on Intel processors.  SGX enables the creation of secure enclaves, which are isolated regions of memory that shield code and data from unauthorized access, even by privileged software.  These enclaves provide confidentiality and integrity guarantees, ensuring that sensitive computations and data remain protected even in the presence of malware or compromised system software.  SGX allows developers to build applications that leverage these secure enclaves for enhanced security and confidentiality.  The Intel SGX ecosystem consists of Intel SGX SDK for enclave development, the Intel SGX PSW for enclave management, and harware support provided by specific Intel processors.

### What is the Intel SGX SDK?

The Intel SGX SDK, or Software Development Kit, is a collection of tools, libraries, and documentation provided by Intel for developers to create applications that leverage Intel Software Guard Extensions (SGX) technology.  SGX is a security feature available on certain Intel processors that enables the creation of secure enclaves, which are isolated regions of memory that protect sensitive code and data from unauthorized access, even by privileged software.  The SDK provides APIs and tools that allow developers to build applications that utilize these secure enclaves for enhanced security and confidentiality.

### What is the Intel SGX PSW?

The Intel SGX PSW, or Platform Software, is a component of the Intel Software Guard Extensions (SGX) technology.  It is a software layer that runs on the system and manages the execution of applications within SGX enclaves.  The SGX PSW includes various components such as the Enclave Manager, the Enclave Loader, and the Enclave Page Cache.

The Enclave Manager is responsible for managing the lifecycle of enclaves, including creating, loading, and destroying enclaves.  It ensures that the endclaves are properly initialized and securely executed.

The Enclave Loader is responsible for securely loading the enclave code and data into the enclave's protected memory region.  It verifies the integrity of the enclave code and sets up the necessary data structures for enclave execution.

The Enclave Page Chace manages the secure paging of enclave memory.  It handles the encryption and decryption of enclave pages, ensuring the confidentiality and integrity of enclave data.

Overall, the Intel SGX PSW plays a crucial role in facilitating the secure execution of applications within SGX enclaves, providing protection for sensitive code and data from unauthorized access.

## Table of Contents

- [Overview of Intel SGX Internals](#OverviewInternals)
- [Overview of Intel SGX Externals](#OverviewExternals)
- [Frequently Asked Questions](#FAQ)
- [Intel SGX Driver](#Driver)
- [Install Dependencies](#InstallDependencies)
- [Download Linux SGX SDK](#DownloadSGX)
- [Build Intel SGX SDK](#BuildSDK)
- [Build Intel SGX PSW](#BuildPSW)
- [Install Intel SGX SDK](#InstallSDK)
- [Install Intel SGX PSW](#InstallPSW)

***

<h2 id="OverviewInternals">Overview of Intel SGX Internals</h2>

### Introduction

Intel SGX is a technology that was developed to meet the needs of the Trusted Computing industry for enterprise server environments (and some consumer-grade hardware), in a similar fashion to "ARM TrustZone" or "RISC-V PMP (Physical Memory Protection)".  It allows user-land (Ring 3) code to create private memory regions, called enclaves, that are isolated from other processes running at the same or higher privilege levels.  The code running inside the enclave is effectively isolated from other applications, the operating system, kernel, hypervisor, etc.

It was introduced in 2015 with the sixth-generation Intel Core processor family based on the Skylake microarchitecture.  SGX support can be checked by executing the "CPUID" instruction with the "Structured Extended Feature Leaf" flag set, and checking if the second bit of the "EBX" register is set.  To be able to use SGX, it must be enabled in the BIOS, and only certain BIOSes support SGX-enabled processors.

### Overview

The implementation of Intel SGX can be summarized in a few points:

- An application is split into two parts: a secure part and an insecure part.
- The application launches the enclave, which is placed in protected memory.
- When an enclave function is called, only the code within the enclave can see its data, all external access is blocked.  When the enclave function is finished, no enclave data is transferred to the insecure part of the application.

![SGX_Process_View](/images/SGX_Process_View.png?raw=true "SGX Process View")

The secure execution environment is part of the host process.  This means:

- The application contains its own code, data, and the enclave.
- The enclave contains its own code and data.
- SGX protects the confidentiality and integrity of the code and data in the enclave.
- Enclave entry points are predetermined during compilation.
- Multi-threading is supported.
- An enclave can access its application's memory, but not vice versa.

![SGX_Memory_View](/images/SGX_Memory_View.png?raw=true "SGX Memory View")

### Instructions

Intel SGX defines 18 new instructions: 13 used by the supervisor and 5 by the user.  All these instructions are implemented in microcode so that their behavior can be modified.

#### Supervisor Instruction Set

- EADD = Add a page
- EBLOCK = Block an EPC page
- ECREATE = Create an enclave
- EDBGRD = Read data by debugger
- EBDGWR = Write data by debugger
- EINIT = Initialize an enclave
- ELDB = Load an EPC page as blocked
- ELDU = Load an EPC page as unblocked
- EPA = Add a version array
- EREMOVE = Remove a page from EPC
- ETRACE = Activate EBLOCK checks
- EWB = Write back/invalidate an EPC page

#### User Instruction Set

- EENTER = Enter an enclave
- EEXIT = Exit an enclave
- EGETKEY = Create a cryptographic key
- EREPORT = Create a cryptographic report
- ERESUME = Re-enter an enclave

### Structures

Intel SGX also defines 13 new data structures: 8 are used for enclave management, 3 for memory page management, and 2 for resources management.

- SGX Enclave Control Structure (SECS)
- Thread Control Structure (TCS)
- State State Area (SSA)
- Page Information (PAGEINFO)
- Security Information (SECINFO)
- Paging Crypto MetaData (PCMD)
- Version Array (VA)
- Enclave Page Cache Map (EPCM)
- Enclave Signature Structure (SIGSTRUCT)
- EINIT Token Structure (EINITTOKEN)
- Report (REPORT)
- Report Target Info (TARGETINFO)
- Key Request (KEYREQUEST)

### Memory

#### Enclave Page Cache (EPC)

Enclave code and data are placed in a special memory area called the "Enclave Page Cache" (EPC).  This memory area is encrypted using the "Memory Encryption Engine" (MEE) a dedicated part of SGX-enabled processors.  External reads on the memory bus can only observe encrypted data.  Pages are only decrypted when inside the physical processor core.  Keys are generated at boot-time and are stored within the processor.

The traditional page check is extended to prevent external accesses to the EPC pages.

![SGX_EPC](/images/SGX_EPC.png?raw=true "SGX EPC")

#### Enclave Page Cache Map

The "Enclave Page Cache Map" (EPCM) structure is used to store the pages' state.  It is located inside the protected memory and its size limits the size of the EPC.  This is set via the BIOS and can be a maximum of 128MB.  It contains the configuration, permissions, and type of each page.

### Memory Management

#### Structures

Page Information (PAGEINFO) - The PAGEINFO structure is used as a parameter to EPC management instructions to reference a page.  It contains its linear and virtual addresses and pointers to SECINFO and SECS structures.

Security Information (SECINFO) - The SECINFO structure is used to store page metadata: access rights (read/write/execute) and type (SECS, TCS, REG, or VA).

Paging Crypto MetaData (PCMD) - The PCMD structure is used to track the metadata associated to an evicted page.  It contains the identity of the enclave the page belongs to, a pointer to a SECINFO structure, and a MAC.

Version Array (VA) - The VA structure is used to store the version numbers of pages evicted from the EPC.  It is a special page type that contains 512 slots of 8 bytes to store the version numbers.

#### Instructions

EPA - This instruction allocates a 4kB memory page that will contain the page's version number array (VA) to protect against replay.  Each element is 64-bits long.

EBLOCK - This instruction blocks all accesses to the page being prepared for eviction.  All future accesses to this page will result in a page fault ("page blocked").

ETRACK - This instruction evicts a page from the EPC.  The page must have been properly prepared; it must be blocked and must not be referenced by the TLB.  Before writing it into the external memory, the page is encrypted, a version number and metadata are generated, and a final MAC is performed.

ELDB/ELDU - This instruction loads into memory a previously evicted page regardless if it is in a blocked state or not.  It checks the MAC of the metadata, version number from the corresponding VA entry, and the page encrypted content.  If the verification succeeds, the page content is decrypted and placed inside the chosen EPC page and the corresponding VA entry is deleted.

#### Explanation

The EPC memory is defined by the BIOS and limited in size.  SGX has a way for removing a page from the EPC, placing it in unprotected memory, and restoring it later.  Pages maintain the same security properties thanks to the EPC page management instructions, that allow page encryption and the generation of additional metadata.  A page connot be removed until all the cache entries referencing this page have been removed form all processor cores.  Content is exported or imported with a granularity of a page, which is 4kB.

![SGX_Page_Management](/images/SGX_Page_Management.png?raw=true "SGX Page Management")

### Memory Content

SGX Enclave Control Structure (SECS) - Each enclave is associated with a SECS structure, which contains its metadata (e.g. its hash and size).  It is not accessible by any secure or insecure code, only by the processor itself.  It is also immutable once it is instantiated.

Thread Control Structure (TCS) - Each enclave is associated with at least one TCS structure, which indicates an execution point into the enclave.  Since SGX supports multi-threading, an enclave can have as many active threads as it has TCS.  Like the SECS structure, it is only accessible by the processor and is immutable.

Save State Area (SSA) - Each TCS is associated with at least one SSA structure, which is used to save the processor's state during the exceptions and interrupt handling.  It is written when exiting the enclave and read when resuming the enclave.

Stack and Heap - Each enclave can use its stack and heap.  The RBP and RSP registers are saved when entering and exiting the enclave, but their value is not changed.  The heap is not handled internally.  Enclaves need their own allocator.

![SGX_Memory_Content](/images/SGX_Memory_Content.png?raw=true "SGX Memory Content")

### Processor - Enclave Creation

#### Measures

Enclave Measure - Each enclave is represented by a hash of both its attributes and the position, content, and protection of its pages.  Two enclaves with the same hash are identical.  This measure is called MRENCLAVE and is used to check the integrity of the enclave.

Signer Measure - Each enclave is also signed by its author.  MRSIGNER contains the hash of the public key of the author.  MRENCLAVE and MRSIGNER are produced using the SHA-256 hash function.

#### Structures

EINIT Token Structure (EINITTOKEN) - The EINITTOKEN structure is used by the EINIT instruction to check if an enclave is allowed to execute.  It contains the attributes, hash, and signer identity of the enclave.  It is authenticated using a HMAC performed with the "Launch Key".

Enclave Signature Structure (SIGSTRUCT) - Each enclave is associated with a SIGSTRUCT structure, which is signed by its author and contains the enclave measure, signer public key, version number (ISV, reflecting the security level), and product identifier (ISVPRODID, to distinguish between enclaves from the same author).  It ensures that the enclave hasn't been modified, and then, resigned with a different key.

#### Instructions

ECREATE - This instruction instantiates a new enclave, defining its address space and root of trust.  This information is stored in a newly allocated SECS.

EADD - This instruction adds a new page to the enclave.  The operating system is solely responsible for choosing the page and its content.  The inital entry for the EPCM denotes the page type and its protection.

EEXTEND - This instruction adds a page's content to the enclave measure by a block of 256 bytes.  It must be called 16 times to add a complete page to the measure (4kB).

EINIT - This instruction checks that the enclave corresponds to its EINITTOKEN (same measure and attributes) before initializing it.  It also checks that the token is signed with the "Launch Key".

EREMOVE - This instruction permanently removes a page from the enclave.

![SGX_Signature_Check](/images/SGX_Signature_Check.png?raw=true "SGX Signature Check")

#### Explanation

1 - The application requests the loading of its enclave into memory.

2 - The ECREATE instruction creates and fills the SECS structure.

3 - Each page is loaded into protected memory using the EADD instruction.

4 - Each page is added to the measure of the enclave using the EEXTEND instruction.

5 - The EINIT instruction finalizes the enclave creation.

![SGX_Enclave_Creation](/images/SGX_Enclave_Creation.png?raw=true "SGX Enclave Creation")

### Processor - Enclave Entry / Exit

#### Instructions

EENTER - This instruction transfers the control from the application to a predetermined location within the enclave.  It checks that the TCS is free and purges the TLB entries.  It then puts the processor in enclave mode and saves the RSP / RBP and XCR0 registers.  Finally, it disables the "Precise Event Based Sampling" (PEBS) to make the enclave execution appear as one giant instruction.

EEXIT - This instruction puts the process back in its original mode and purges the TLB entries for addresses located within the enclave.  Control is transferred to the address located within the application and specified in the RBX register and the TCS structure is freed.  The enclave needs to clear it registers before exiting to prevent data leaks.

#### Explanation

Enclave Entry

1 - EENTRY instruction is executed.

2 - The application context is saved.

3 - The processor is put into "enclave mode".

Enclave Exit

1 - EEXIT instruction is executed.

2 - The processor is put into "normal mode".

![SGX_Enclave_Lifecycle](/images/SGX_Enclave_Lifecycle.png?raw=true "SGX Enclave Lifecycle")

### Processor - Interrupt Handling

#### Instructions

ERESUME - This instruction restores the context from the current SSA and resumes the execution.

#### Explanation

Interruptions and exceptions result in "Asynchronous Enclave Exits" (AEX).  The "Asychronous Exit Pointer" (AEP) points to a handler located inside the application that will resume the execution after the exception has been handled by the "Interrupt Service Routine" (ISR).  The handler can decide to resume or not to resume the execution of the enclave by executing the ERESUME instruction.

When an AEX occurs, the context of the enclave is saved in the current SSA and the application context is restored.  The enclave context is restored when the ERESUME instruction is executed.  The TCS contains a counter denoting the current SSA forming a stack of contexts.

Handling an Interruption

1 - The interruption or exception arrives at the processor.

2 - The enclave context is saved, and the application context is restored.

3 - The execution continues in the handler of the operating system.

4 - The handler returns (IRET) to the AEP, a trampoline function.

5 - AEP executes ERESUME if it decides to resume enclave execution.

6 - The enclave context previously saved is restored.

7 - The execution resumes where it stopped within the enclave.

![SGX_Interrupt_Handling](/images/SGX_Interrupt_Handling.png?raw=true "SGX Interrupt Handling")

### Processor - Sealing

#### Instructions

EGETKEY - This instruction is used by an enclave to access the different keys provided by the platform.  Each key enables a different operation (sealing, attestation).

#### Explanation

When an enclave is instantiated, its code and data are protected from external access.  When it stops, all of its data is lost.  Sealing is a way of securely saving the data outside of an enclave, for example on a hard drive.  The enclave must retrieve its "Seal Key" using the EGETKEY instruction.  It uses this key to encrypt and ensure its data integrity.  The algorithm used is chosen by the enclave author.

Using the Enclave Identity

The sealing can be done using the encalve identity.  The key derivation is then based on the value of MRENCLAVE.  Two distinct enclaves have different keys, but also two version of the same enclave which prevents the local migration of data.

Using the Signer Identity

The sealing can also be done using the signer identity.  The key derivation is then based on the value of MRSIGNER.  If two versions of an enclave share the same key, then they each can read the sealed data.  If multiple separate enclaves are signed using the same key, then they can read each other's data.

Security Version Number (SVN)

Older versions of an enclave should not be allowed to read data sealed by a newer version of an enclave.  To prevent this, the "Security Version Number" (SVN) is used.  It is a counter incremented after each update impacting the security of the enclave.  Keys are derived using the SVN in a way that an enclave can retrieve the keys corresponding to the current, or older, security level, but not newer.

### Processor - Attestation

#### Structures

Key Request (KEYREQUEST) - The KEYREQUEST structure is used as an input to the EGETKEY instruction.  It chooses which key to get and also additional parameters that might be needed for key derivation.

Report Target Info (TARGETINFO) - The TARGETINFO structure is used as an input for the EREPORT instruction.  It is used to identify which enclave (hash and attributes) will be able to verify the REPORT generated by the processor.

Report (REPORT) - The REPORT structure is the output of the EREPORT instruction.  It contains the enclave's attributes, measure, signer identity, and some user data to share between the source and destination enclaves.  The processor performs a MAC over this structure using the "Report Key".

#### Instructions

EREPORT - This instruction is used by the enclave to generate a REPORT structure containing information about it and is authenticated using the "Report Key" of the destination enclave.

#### Explanation

The enclave code and data are in plaintext before its initialization.  While sections could technically be encrypted, the decryption key cannot be preinstalled as this would not provide any additional security.  Secrets (keys) have to come from outside the system.  The enclave must be able to prove to a third-party that it can be trusted (has not been tampered with) and is executing on a legitimate platform.

Two types of attestation exist:

Local Attestation

1 - A channel must have already been established between enclave A and enclave B.  It is used by enclave A to retrieve the MRENCLAVE of enclave B.

2 - Enclave A calls EREPORT with the MRENCLAVE of enclave B to generate a signed report for the latter.

3 - Enclave B calls EGETKEY to retrieve its "Report Key" and verify the MAC of the EREPORT structure.  If valid, the enclave is the one expected and running on a legitimate platform.

![SGX_Local_Attestation](/images/SGX_Local_Attestation.png?raw=true "SGX Local Attestation")

Remote Attestation

Remote attestation requires an architectural enclave called the "Quoting Enclave" (QE).  This enclave verifies and transforms the REPORT (locally verifiable) into a QUOTE (remotely verifiable) by signing it with another special key, the "Provisioning Key".

1 - Initially, the enclave informs the application that it needs a secret located outside of the platform.  The application establishes a secure communication with a server.  The server responds with a challenge to prove that the enclave executing has not been tampered with and that the platform it executes on is legitimate.

2 - The application gives the "Quoting Enclave" identity and the challenge to its enclave.

3 - The enclave generates a manifest including the challenge answer and an ephemeral public key that will be used later to secure the communications between the server and the enclave.  It generates a hash of the manifest that it includes in the user data section of the EREPORT instruction.  The instruction generates a REPORT for the "Quoting Enclave" that ties the manifest to the enclave.  The enclave passes the REPORT to the application.

4 - The application transfers the REPORT to the "Quoting Enclave" for verification and signing.

5 - The QE retrieves its "Report Key" using the EGETKEY instruction and verifies the REPORT.  It creates the QUOTE structure and signs it using its "Provisioning Key" before giving it back to the application.

6 - The application sends the QUOTE and associated manifest to the server for verification.

7 - The server uses the attestation service provided by Intel to validate the QUOTE signature.  It then checks the manifest integrity using the hash from the QUOTE user data.  Finally, it makes sure that the manifest contains the expected answer to the challenge.

![SGX_Remote_Attestation](/images/SGX_Remote_Attestation.png?raw=true "SGX Remote Attestation")

### Conclusion

This section has explained how SGX works internally at the processor / memory level.

***

<h2 id="OverviewExternals">Overview of Intel SGX Externals</h2>

### Introduction

The following is an explanation on how the application interacts with its enclave and the different pieces of software in the SGX SDK and PSW.  At the end, known attacks against SGX and concerns with the technology are addressed.

### Interactions

Conceptually, an SGX enclave can be seen as a black box that is capable of executing any arbitrary algorithm.  This black box can communicate with the outside world using three different ways presented below:

#### Enclave Calls (ECALLs)

The application can invoke a predefined function inside the enclave, passing input parameters and pointers to shared memory within the application.  Thos invocations from the application to the enclave are called ECALLs.

#### Outside Calls (OCALLs)

When an enclave executes, it can perform an OCALL to a predefined function in the application.  Contrary to an ECALL, an OCALL cannot share enclave memory with the application, so it must copy the parameters into the application memory before the OCALL.

#### Asynchronous Exit (AEX)

The execution can also exit an encllave because of an interruption or an exception.  These enclave exit events are called "Asynchronous Exit Events" (AEX).  They can transfer control from the enclave to the application from arbitrary points inside the enclave.

### Programming

#### Trusted Code Base (TCB)

Developing an application that uses an SGX enclave requires the programmer to identify the resources that must be protected, the data structure containing those resources, and the code that manages them.  Then, everything that has been identified must be placed inside the enclave.  An enclave file is a library that is compatible with the traditional operating system loaders.  It contains the code and data of the enclave, which is in plaintext on the disk.

#### Interface Functions

The interface between the application and its enclave must be designed carefully.  An enclave declares which functions can be called by the application and which functions from the application the enclave can call.  Enclave input parameters can be observed and modified by the non-secure code, so they must be checked extensively.  As an enclave cannot directly access the services of the OS, but it must call back to its application.  Those calls should not expose any confidential information and also are not guaranteed to be performed as expected by the enclave.

#### Software Development Kit (SDK)

The "Software Development Kit" (SDK) provides developers with everything they need to develop an SGX-enabled application.  It is composed of a tool to generate the interface functions between the application and the enclave, a tool to sign the enclave before using it, a tool to debug it, and a tool to measure application / enclave performance.  It also contains templates and smaple projects to develop an enclave using Visual Studio under Windows or using Makefiles under GNU/Linux.

#### Platform Software (PSW)

The "Platform Software" (PSW) is the software stack that allows SGX-enabled applications to execute on the target platform.  It is available for Windows and GNU/Linux operating systems and is composed of four major parts:

- A driver that provides access to the hardware features;
- Multiple support libraries for execution and attestation;
- The architectural enclaves necessary for the environment to run;
- A service to load and communicate with the enclaves.

#### Architectural Enclaves

To allow the secure environment to execute, several "Architectural Enclaves" (AE) are needed.  They are provided and signed by Intel.  They enforce launch policies, perform the provisioning and attestation processes, and more.

##### Launch Enclave

The "Launch Enclave" (LE) is the enclave responsible for distributing EINITTOKEN structures to other enclaves wishing to execute on the platform.  It checks the signature and identity of the enclave to ensure that they are valid.  To generate the tokens, the Launch Enclave uses the "Launch Key".  The Launch Enclave is the only enclave able to access this key.

##### Provisioning Enclave

The "Provisioning Enclave" (PvE) is the enclave responsible for retrieving the "Attestation Key" by communicating with the "Intel Provisioning Service" servers.  It proves the authenticity of the platform using a certificate provided by the PcE.

##### Provisioning Certificate Enclave

The Provisioning Certificate Enclave (PcE) is the enclave responsible for signing the processor certificate used by the PvE.  It signs the processor certificate wit the "Provisioning Key" which is only accessible by the PcE.  The PvE and PcE are implemented as a single enclave.

##### Quoting Enclave

The "Quoting Enclave" (QE) is the enclave responsible for providing trust for the identity of an enclave and the environment where it executes during the remote attestation process.  It decrypts the "Attestation Key" that it receives from the PvE and uses this key to transform a REPORT structure (locally verifiable) into a QUOTE structure (remotely verifiable).

##### Platform Service Enclaves

The "Platform Service Enclaves" (PSE) are architectural enclaves that offer other enclaves multiple services, like monotonous counters, trusted time, etc.  Those enclaves make use of the Management Engine (ME), an isolated and secure co-processor that manages the platform.

#### Key Directory

Each SGX-enabled processor contains two root keys which are stored inside e-fuses: the "Root Provisioning Key" (RPK) and the "Root Seal Key" (RSK).  The RPK is known to Intel to enable the remote attestation process, while the RSK is only known to the platform.  SGX was not designed to counter or prevent physical attacks, but efforts have been made to harden the processor against tampering and making the extraction of keys a very costly operation.  It is possible to read the e-fuses, but in a destructive way.  This is why the keys are stored encrypted on the e-fuses.  A "Physical Unclonable Function" (PUF) is used to store the symmetric key that is used to decipher the other keys during processor execution.

##### Root Keys

###### Root Provisioning Key

The first key created by Intel during the manufacturing process is the "Root Provisioning Key" (RPK).  This key is generated randomly on a dedicated "Hardware Security Module" (HSM) located inside a facility called the "Intel Key Generation Facility" (IKGF).  Intel is responsible for maintaining a database containing all keys produced by the HSM.  The RPKs are sent to multiple production facilities to be embedded inside the processor e-fuses.

###### Root Sealing Key

The second key located inside the e-fuses is called the "Root Sealing Key" (RSK).  Like the first key, it is guaranteed to differ statistically between each processor produced.  Contrary to the RSK, Intel erases every trace of these keys from their production chain after they have been incorporated into a processor in order for each platform to have a unique key only known to itself.

##### Key Derivation

By design, an enclave does not have access to the root keys, but it can access keys derived from the root keys.  The derivation function allows an enclave author to specify a key derivation policy.  These policies allow the use of trusted values like the MRENCLAVE, MRSIGNER, and/or the attributes of the enclave.  Enclaves cannot derive keys belonging to a MRENCLAVE or MRSIGNER of another enclave.  When the key derivation policy does not make use of a field, it is automatically set to zero.  As a result, even when non-specialized keys are available, specialized keys cannot be derived from them.

To add entropy coming from the user, a value called "Owner Epoch" is used as a parameter during the derivation process.  This value is configured at boot-time by the derivration of a password and saved during each power cycle in non-volatile memory.  This value must stay the same for an enclave to be able to retrieve the same keys.  On the contrary, this value must be changed when the platform owner chnages because it prevents the new owner from accessing the personal information of the old owner until the original password is restored.

![SGX_KDF](/images/SGX_KDF.png?raw=true "SGX KDF")

The SGX infrastructure supports TCB updates of its hardware and software components.  Each component has a SVN which is incremented after each security update.  A new SVN leads to a new "Sealing Key".  There exists a process allowing a newer TCB to access the "Sealing Keys" of older TCBs to allow for data migration.  Old TCBs cannot access the keys of newer TCBs.

![SGX_Key_Recovery](/images/SGX_Key_Recovery.png?raw=true "SGX Key Recovery")

##### Derived Keys

###### Provisioning Key

This key is derived from the RPK and used as a root of trust (tied to the TCB version) between the "Intel Provisioning Service" and the processor.  As admitting a non-SGX processor into a group of legitimate SGX processors compromise the remote attestation for all processors, extreme precautions must be taken to disallow access to the "Provisioning Key".  Currently, the "Launch Enclave" gives access to this key only if the enclave is signed by Intel (the MRSIGNER of Intel is hard-coded in the "Launch Enclave" code).

###### Provisioning Seal Key

This key is derived from the RPK and RSK.  During the enrollment of a processor in the group, the private key of each platform is encrypted with this key and sent to the "Intel Attestation Service".  It must be noted that the private key cannot only be encrypted using the RPK because that would destroy the anonymous enrollment protocol used.  Similarly, the private key cannot be encrypted only using the RSK as it would allow non-privileged enclaves to access the private key of the platform.  Given the uncertainty of the generation process used for the RSK, it is possible taht Intel knows the private keys of each platform.

###### Launch Key

This key is derived from the RSK and is used by the "Launch Enclave" to generate an EINITTOKEN.  Each enclave that is not signed by Intel must obtain this token or the processor cannot instantiate it.  Only a specific MRSIGNER, whose private keys are only known to Intel, can access the "Launch Key".  In SGXv2, the MRSIGNER of the "Launch Enclave" can be changed programmatically, but it is not known how Intel applies access control to the "Provisioning Key".

###### Seal Key

This key is derived from the RSK and is used to encrypt data related to the current platform.  It is important not to use a non-specialized "Seal Key", either for encryption or authentication, because that would compromise the enclave's security.

###### Report Key

This key is derived from the RSK and is used for the local attestation process.

![SGX_Key_Overview](/images/SGX_Key_Overview.png?raw=true "SGX Key Overview")




***

<h2 id="FAQ">Frequently Asked Questions</h2>

### What Intel processors support SGX?

- Intel Core 6th generation (Skylake) processors
- Intel Core 7th generation (Kaby Lake) processors
- Intel Core 8th generation (Coffee Lake) processors
- Intel Core 9th generation processors
- Intel Core 10th generation (Cascade Lake / Ice Lake) processors
- Intel Xeon E3 v5 processors and newer
- Intel Xeon E5 v4 processors and newer
- Intel Xeon Scalable processors (Skylake-SP and Cascade Lake-SP) and newer
- Intel Atom processors based on the Apollo Lake microarchitecture and newer

SGX was removed from consumer grade processors starting on the 11th generation processor family.

### Can I run SGX software if I don't have an Intel processor with SGX?

No, you cannot run SGX software if you don't have an Intel processor with SGX support.

### My processor supports SGX, but I cannot run SGX applications.

You must enable SGX support on your mainboards BIOS.

***

<h2 id="Driver">Intel SGX Driver</h2>

Intel SGX Support in the Linux Kernel

The mainline Linux kernel has had built-in Intel SGX support since release 5.11.  The in-kernel Intel SGX driver requires the platform to support and be configured for flexible launch control (FLC).  Use the mainline kernel with Intel SGX support whenever possible.

There are two other kernel space (SGX driver) options available for special use cases:

- If you distribution kernel is older than version 5.11 or does not have the in-kernel Intel SGX Support, you can use the Intel SGX DCAP driver as a temporary solution before transitioning to kernel version 5.11 or later.  It provides an interface close to the mainline kernel and also requires the platform to support and to be configured for FLC (Flexible Launch Control).

  Get the [Intel SGX DCAP Driver](https://download.01.org/intel-sgx/latest/dcap-latest/linux/)

- If you need to use a non-FLC platform, the Intel SGX for Linux OS driver project hosts an out-of-tree driver.  This dirver is provided to support running Intel SGX enclaves on platforms that only support legacy launch control.  It may also be installed on platforms configured with FLC, but these platforms will only load production enclaves that conform to the legacy launch control policy.

  Get the [Intel SGX Out-of-Tree Driver](https://github.com/intel/linux-sgx-driver)

Note: Although the Intel SGX SDK and PSW are compatiable with all of these drivers, the legacy non-FLC driver and the Intel SGX DCAP driver are updated only for critical security fixes.  New features or functionalities implemented in the mainline kernel cannot be ported to the legacy non-FLC driver or Intel SGX DCAP driver due to limitations of being out-of-tree implementations.

***

<h2 id="InstallDependencies">Install Dependencies</h2>

  ```
  sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python3 libssl-dev git cmake perl libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip lsb-release libsystemd0
  sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
  ```

***

<h2 id="DownloadSGX">Download Linux SGX SDK & PSW</h2>

  ```
  git clone https://github.com/intel/linux-sgx.git
  cd linux-sgx && make preparation
  ```

  ```
  sudo cp external/toolset/debian10/* /usr/local/bin
  which ar as ld objcopy objdump ranlib
  ```

***

<h2 id="BuildSDK">Build Intel SGX SDK & the SDK Installer</h2>

  ```
  make sdk
  make sdk_install_pkg
  ```
  This will produce the 'sgx_linux_x64_sdk_2.19.100.3.bin' in the 'linux/installer/bin' directory.

***

<h2 id="BuildPSW">Build Intel SGX PSW & the PSW Installer</h2>

  ```
  make psw
  make deb_psw_pkg
  ```

***

<h2 id="InstallSDK">Install Intel SGX SDK</h2>


***

<h2 id="InstallPSW">Install Intel SGX PSW</h2>


