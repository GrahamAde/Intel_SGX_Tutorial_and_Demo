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

Intel SGX is a technology that was developed to meet the needs of the Trusted Computing industry for enterprise server environments (and some consumer-grade hardware), in a similar fashion to "ARM TrustZone" or "RISC-V PMP (Physical Memory Protection).  It allows user-land (Ring 3) code to create private memory regions, called enclaves, that are isolated from other processes running at the same or higher privilege levels.  The code running inside the enclave is effectively isolated from other applications, the operating system, kernel, hypervisor, etc.

It was introduced in 2015 with the sixth-generation Intel Core processor family based on the Skylake microarchitecture.  SGX support can be checked by executing the "CPUID" instruction with the "Structured Extended Feature Leaf" flag set, and checking if the second bit of the "EBX" register is set.  To be able to use SGX, it must be enabled in the BIOS, and only certain BIOSes support SGX-enabled processors.

### Overview

The implementation of Intel SGX can be summarized in a few points:

- An application is pslit into two parts: a secure part and an insecure part.
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

Intel SGX defines 18 new instructions: 13 used by the supervisor and 5 by the user.  All these instructions are implemented in microcode so that their behavior can be modified

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

The "Enclave Page Cache Map" (EPCM) structure is used to store the pages state.  It is located inside the protected memory and its size limits the size of the EPC.  This is set via the BIOS and can be a maximum of 128MB.  It contains the configuration, permissions, and type of each page.

### Memory Management

#### Structures

Page Information (PAGEINFO) - The PAGEINFO structure is used as a parameter to EPC management instructions to reference a page.  It contains its linear and virtual addresses and pointers to SECINFO and SECS structures.

Security Information (SECINFO) - The SECINFO structure is used to store page metadata: access rights (read/write/execute) and type (SECS, TCS, REG, or VA).

Paging Crypto MetaData (PCMD) - The PCMD structure is used to track the metadata associated to an evicted page.  It contains the identity of the enclave the page belongs to, a pointer to a SECINFO structure, and a MAC.

Version Array (VA) - The VA structure is used to store the version numbers of pages evicted from the EPC.  It is a special page type that contains 512 slots of 8 bytes to store the version numbers.

#### Instructions

EPA - This instruction allocates a 4kB memory page that will contain the page's version number array (VA) to protect against replay.  Each element is 64-bits long.

EBLOCK - This instruction blocks all accesses to the page being prepared for eviction.  All future accesses to this page will result in a page fault ("page blocked").

ETRACK - This instruction evicts a page from the EPC.  The page must have been prepared properly; it must be blocked and must not be refernced by the TLB.  Before writing it into the external memory, the apge is encrypted, a version number and metadata are generated, and a final MAC is performed.

ELDB/ELDU - This instruction loads into memory a previously evicted page regardless if it is in a blocked state or not.  It checks the MAC of the metadata, version number from the corresponding VA entry, and the page encrypted content.  If the verification succeeds, the page content is decrypted and placed inside the chosen EPC page and the corresponding VA entry is deleted.

#### Explanation

The EPC meory is defined by the BIOS and limited in size.  SGX has a way for removing a page from the EPC, placing it in unprotected memory, and restoring it later.  Pages maintain the same security properties thanks to the EPC page management instructions, that allow page encryption and the generation of additional metadata.  A page connot be removed until all the cache entries referencing this page have been removed form all processor cores.  Content is exported or imported with a granularity of a page, which is 4kB.

![SGX_Page_Management](/images/SGX_Page_Management.png?raw=true "SGX Page Management")

### Memory Content

SGX Enclave Control Structure (SECS) - Each enclave is associated with a SECS structure, which contains its metadata (e.g. its hash and size).  It is not accessible by any secure or insecure code, only by the processor itself.  It is also immutable once it is instantiated.

Thread Control Structure (TCS) - Each enclave is associated with at least one TCS structure, which indicates an execution point into the enclave.  As SGX supports multi-threading, an enclave can have as many active threads as it has TCS.  Like the SECS structure, it is only accessible by the processor and is immutable.

Save State Area (SSA) - Each TCS is associated with at least one SSA structure, which is used to save the processor's state during the exceptions and interrupt handling.  It is written when exiting the enclave and read when resuming the enclave.

Stack and Heap - Each enclave can use its stack and heap.  The RBP and RSP registers are saved when entering and exiting the enclave, but their value is not changed.  The heap is not handled internally.  Enclaves need their own allocator.

![SGX_Memory_Content](/images/SGX_Memory_Content.png?raw=true "SGX Memory Content")

### Processor - Enclave Creation

#### Measures

Enclave Measure - Each enclave is represented by a hash of boths its attributes and the position, content, and protection of its pages.  Two enclaves with the same hash are identical.  This measure is called MRENCLAVE and is used to check the integrity of the enclave.

Signer Measure - Each enclave is also signed by its author.  MRSIGNER contains the hash of the public key of the author.  MRENCLAVE and MRSIGNER are produced using the SHA-256 hash function.

#### Structures

EINIT Token Structure (EINITTOKEN) - The EINITTOKEN structure is used by the EINIT instruction to check if an enclave is allowed to execute.  It contains the attributes, hash, and signer identity of the enclave.  It is authenticated using a HMAC performed with the "Launch Key".

Enclave Signature Structure (SIGSTRUCT) - Each enclave is associated with a SIGSTRUCT structure, which is signed by its author and contains the enclave measure, signer public key, version number (ISV, reflecting the security level), and product identifier (ISVPRODID, to distinguish between enclaves from the same author).  It ensures that the enclave hasn't been modified, and then, resigned with a different key.

#### Instructions

ECREATE - This instruction instantiates a new enclave, defining its address space and root of trust.  This information is stored in a newly allocated SECS.

EADD - This instruction adds a new page to the enclave.  The operating system is solely responsible for choosing the page and its content.  The inital entry for the EPCM denotes the page type and its protection.

EEXTEND - This instruction adds a page's content to the enclave measure by a block of 256 bytes.  It must be called 16 times to add a complete page to the measure (4kB).

EINIT - This instruction checks that the enclave corresponds to its EINITTOKEN (same measure and attributes) before initializing it.  It also check s that the token is signed with the "Launch Key".

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

The sealing can also be done using the signer identity.  The key derivation is then based on the value of MRSIGNER.  Two distinct enclaves still have different keys, but two versions of an enclave share the same key and can read the sealed data.  IF multiple enclaves are signed using the same key, then they can read each other's data.

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


