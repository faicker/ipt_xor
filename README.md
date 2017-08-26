iptables xor module
===================
The XOR target enables the user to encrypt TCP and UDP traffic using a very simple xor encryption.  
**warning:** This is not a real encryption.


## Install
1. first install kernel-devel, iptables-devel and etc.
2. To compile the userpace so,
```bash
cd userspace;make libxt_XOR.so
cp libxt_XOR.so /lib64/xtables/
```
3. To compile the kernel module,
```bash
cd kernel;make
insmod xt_XOR.ko
```

## Usage

XOR takes one mandatory parameter.  
`--key key-value` where key-value is a byte used to xor with packet payloads.

## Example

To use this target between hosts 1.2.3.4 and 1.2.3.5.

### (on host A, 1.2.3.4)
```bash
iptables −t mangle −A OUTPUT -d 1.2.3.5 -p tcp --dport 1234 −j XOR −−key 0x61
iptables −t mangle −A INPUT -s 1.2.3.5 -p tcp --sport 1234 −j XOR −−key 0x61
```

### (on host B, 1.2.3.5)
```bash
iptables −t mangle −A OUTPUT −d 1.2.3.4 -p tcp --sport 1234 −j XOR −−key 0x61
iptables −t mangle −A INPUT −s 1.2.3.4 -p tcp --dport 1234 −j XOR −−key 0x61
```

### Notice

* Tested on Centos6.5(2.6.32-431.23.3.el6.x86_64).

### License

This project is under the MIT license. See the [LICENSE](LICENSE) file for the full license text.
