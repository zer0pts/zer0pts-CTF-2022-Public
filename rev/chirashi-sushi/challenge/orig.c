#include <stdio.h>
#include <string.h>

#define FLAG_LEN 47
#define ll long long
#define ull unsigned long long

int main(){
    ll _mod, _cnt, _mul, _end; // TMP_VAL_DECLARE
    ull _a, _b, _c, _d; // TMP_VAL_DECLARE

    _mod = (int)(1e9+7);
    _cnt = (ull)_f_cnt;
    _mul = (ull)_f_mul;
    _end = (ull)_f_end;
    
    _a = (ull)_f_a * (ull)_f_b;
    _b = (ull)_f_c * (ull)_f_d;
    _c = (ull)_f_mod * (ull)_f_cnt;
    _d = (ull)_f_end * (ull)_f_mul;

    unsigned char flag[FLAG_LEN + 1] = {0};
    scanf("%47s", flag);

    while (1) {
        _cnt *= _mul;
        _cnt %= _mod;
        if (_cnt == _end) break;
        int i1 = (_cnt ^ _a) % FLAG_LEN;
        int i2 = (_cnt ^ _b) % FLAG_LEN;
        if (i1 != i2) {
            switch ((_c ^ _d) % 5) {
            case 0:
                flag[i1] += _cnt;
                flag[i2] -= _cnt;
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

        _a ^= _c;
        _b ^= _d;
        _a *= _a;
        _d *= _a;
        _d += _b;
        _c += _d;
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
