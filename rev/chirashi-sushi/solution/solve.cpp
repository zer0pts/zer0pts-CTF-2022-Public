#include<bits/stdc++.h>
using ll = long long;
using ull = unsigned long long;
using byte = unsigned char;

using namespace std;

struct op {
    int i1;
    int i2;
    int code;
    op (int i1, int i2, int code) : i1(i1), i2(i2), code(code) {}
};


int main(){
    const int FLAG_LEN = 47;
    ll mod, cnt, mul, end; // TMP_VAL_DECLARE
    ull a, b, c, d; // TMP_VAL_DECLARE

    mod = (ll)(1e9+7);
    cnt = 0x4012d1LL;
    mul = 0x4013f7LL;
    end = 0x4015b0LL;

    a = 0x40123eLL * 0x40148aLL;
    b = 0x40151dLL * 0x4011abLL;
    c = 0x401364LL * 0x4012d1LL;
    d = 0x4015b0LL * 0x4013f7LL;

    unsigned char flag[FLAG_LEN + 1] = {
        0x3b, 0x7e, 0x8b, 0x1a, 0xbb, 0x4f, 0xd5, 0x97,
        0xa5, 0x80, 0xbe, 0xcf, 0xcb, 0x66, 0xfd, 0x87,
        0x75, 0x58, 0x11, 0x07, 0x1a, 0xe4, 0x0d, 0xe8,
        0x8b, 0x90, 0x21, 0x17, 0x42, 0x60, 0x08, 0xa5,
        0xf8, 0x3a, 0xa0, 0x89, 0x5a, 0x64, 0xa2, 0x7a,
        0x7d, 0x30, 0xe2, 0xa7, 0x38, 0x24, 0x39, 0x00
    };
    cout << "[+] calculating ops..." << endl;
    vector<op> ops;
    while (1) {
        cnt *= mul;
        cnt %= mod;
        if (cnt == end) break;
        int i1 = (cnt ^ a) % FLAG_LEN;
        int i2 = (cnt ^ b) % FLAG_LEN;
        int op = (c ^ d) % 5;
        if (i1 != i2) ops.emplace_back(i1, i2, op == 0 ? -cnt : op);
        a ^= c;
        b ^= d;
        a *= a;
        d *= a;
        d += b;
        c += d;
    }
    
    cout << "[+] rewinding..." << endl;
    reverse(ops.begin(), ops.end());
    for (auto [i1, i2, code] : ops) {
        if (code <= 0) {
            flag[i1] -= -code;
            flag[i2] += -code;
        }
        if (code == 1) {
            flag[i1] ^= flag[i2];
        }
        if (code == 2) {
            flag[i1] -= flag[i2];
        }
        if (code == 3) {
            flag[i1] += flag[i2];
        }
        if (code == 4) {
            flag[i1] ^= flag[i2];
            flag[i2] ^= flag[i1];
            flag[i1] ^= flag[i2];
        }
    }
    cout << "[+] flag: " << flag << endl;

    return 0;
}
