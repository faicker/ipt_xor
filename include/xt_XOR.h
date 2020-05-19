#ifndef _XT_XOR_H
#define _XT_XOR_H

#define XT_XOR_MAX_KEY_SIZE 64

struct xt_xor_info {
 unsigned char key;
 char keys[XT_XOR_MAX_KEY_SIZE + 1];
};

#endif /* _XT_XOR_H */
