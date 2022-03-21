#include <stdio.h>
#include <string.h>

#define _DEFINE_VAL(type, symbol) void f_##symbol (void (*fp)(type* (*ret)(void))){      static type symbol;     type* f() { return &symbol; }     fp(f); }
#define DEFINE_VAL(type, symbol) _DEFINE_VAL(type, symbol)

#define __GET_VAL(type, symbol, local_symbol, id) type* local_symbol; void g_##id(type* (*ret)(void)) {     local_symbol = ret(); } f_##symbol(g_##id);

#define _GET_VAL(type, symbol, local_symbol, id) __GET_VAL(type, symbol, local_symbol, id)
#define GET_VAL(type, symbol, local_symbol) _GET_VAL(type, symbol, local_symbol, __COUNTER__)
#define MOD Xe250d0
#define A Xda83cf
#define CNT Xcefe37
#define B X22badb
#define END X5bab1c
#define D Xb5d75b
#define C X5f628f
#define MUL X88417a

DEFINE_VAL(unsigned long long, D)
DEFINE_VAL(unsigned long long, A)
DEFINE_VAL(long long, CNT)
DEFINE_VAL(long long, MOD)
DEFINE_VAL(long long, MUL)
DEFINE_VAL(unsigned long long, B)
DEFINE_VAL(unsigned long long, C)
DEFINE_VAL(long long, END)


#define FLAG_LEN 47
#define ll long long
#define ull unsigned long long

int main(){
GET_VAL(unsigned long long, C, c4)
GET_VAL(unsigned long long, C, c14)
GET_VAL(long long, END, end1)
GET_VAL(unsigned long long, A, a6)
GET_VAL(unsigned long long, D, d6)
GET_VAL(unsigned long long, B, b4)
GET_VAL(long long, CNT, cnt9)
GET_VAL(unsigned long long, C, c8)
GET_VAL(long long, CNT, cnt6)
GET_VAL(unsigned long long, A, a3)
GET_VAL(unsigned long long, B, b3)
GET_VAL(long long, END, end2)
GET_VAL(long long, CNT, cnt3)
GET_VAL(unsigned long long, A, a7)
GET_VAL(unsigned long long, C, c3)
GET_VAL(unsigned long long, A, a4)
GET_VAL(unsigned long long, C, c7)
GET_VAL(long long, MUL, mul2)
GET_VAL(unsigned long long, D, d1)
GET_VAL(long long, CNT, cnt7)
GET_VAL(long long, CNT, cnt1)
GET_VAL(unsigned long long, D, d5)
GET_VAL(long long, CNT, cnt4)
GET_VAL(unsigned long long, C, c5)
GET_VAL(long long, MOD, mod1)
GET_VAL(unsigned long long, A, a1)
GET_VAL(unsigned long long, C, c13)
GET_VAL(unsigned long long, C, c16)
GET_VAL(unsigned long long, B, b1)
GET_VAL(unsigned long long, C, c11)
GET_VAL(long long, MUL, mul1)
GET_VAL(unsigned long long, C, c2)
GET_VAL(long long, MOD, mod3)
GET_VAL(unsigned long long, C, c1)
GET_VAL(unsigned long long, D, d7)
GET_VAL(long long, CNT, cnt10)
GET_VAL(long long, MUL, mul4)
GET_VAL(unsigned long long, C, c9)
GET_VAL(long long, END, end4)
GET_VAL(long long, CNT, cnt8)
GET_VAL(long long, MUL, mul3)
GET_VAL(unsigned long long, B, b2)
GET_VAL(long long, CNT, cnt5)
GET_VAL(unsigned long long, C, c6)
GET_VAL(unsigned long long, D, d3)
GET_VAL(long long, MOD, mod2)
GET_VAL(unsigned long long, D, d4)
GET_VAL(long long, END, end3)
GET_VAL(unsigned long long, C, c15)
GET_VAL(unsigned long long, D, d2)
GET_VAL(unsigned long long, A, a5)
GET_VAL(unsigned long long, A, a2)
GET_VAL(unsigned long long, C, c10)
GET_VAL(unsigned long long, C, c12)
GET_VAL(unsigned long long, B, b5)
GET_VAL(long long, CNT, cnt2)
// ORIGINAL_SOURCE



    *mod1 = (int)(1e9+7);
    *cnt1 = (ull)f_Xcefe37;
    *mul1 = (ull)f_X88417a;
    *end1 = (ull)f_X5bab1c;
    
    *a1 = (ull)f_Xda83cf * (ull)f_X22badb;
    *b1 = (ull)f_X5f628f * (ull)f_Xb5d75b;
    *c1 = (ull)f_Xe250d0 * (ull)f_Xcefe37;
    *d1 = (ull)f_X5bab1c * (ull)f_X88417a;

    unsigned char flag[FLAG_LEN + 1] = {0};
    scanf("%47s", flag);

    while (1) {
        *cnt2 *= *mul2;
        *cnt3 %= *mod2;
        if (*cnt4 == *end2) break;
        int i1 = (*cnt5 ^ *a2) % FLAG_LEN;
        int i2 = (*cnt6 ^ *b2) % FLAG_LEN;
        if (i1 != i2) {
            switch ((*c2 ^ *d2) % 5) {
            case 0:
                flag[i1] += *cnt7;
                flag[i2] -= *cnt8;
                break;
            case 1:
                flag[i1] ^= flag[i2];
                break;
            case 2:
                flag[i1] += flag[i2];
                break;
            case 3:
                flag[i1] -= flag[i2];
                break;
            case 4:
                flag[i1] ^= flag[i2];
                flag[i2] ^= flag[i1];
                flag[i1] ^= flag[i2];
                break;
            }
        }

        *a3 ^= *c3;
        *b3 ^= *d3;
        *a4 *= *a5;
        *d4 *= *a6;
        *d5 += *b4;
        *c4 += *d6;
    }

    unsigned char enc[FLAG_LEN + 1] = {
        0x3b, 0x7e, 0x8b, 0x1a, 0xbb, 0x4f, 0xd5, 0x97,
        0xa5, 0x80, 0xbe, 0xcf, 0xcb, 0x66, 0xfd, 0x87,
        0x75, 0x58, 0x11, 0x07, 0x1a, 0xe4, 0x0d, 0xe8,
        0x8b, 0x90, 0x21, 0x17, 0x42, 0x60, 0x08, 0xa5,
        0xf8, 0x3a, 0xa0, 0x89, 0x5a, 0x64, 0xa2, 0x7a,
        0x7d, 0x30, 0xe2, 0xa7, 0x38, 0x24, 0x39, 0x00
    };
    if (memcmp(flag, enc, FLAG_LEN) == 0){
        puts("correct");
        return 0;
    }
    else {
        return 1;
    }
}
