#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/random.h>
#include <setjmp.h>

#define FOR(var, s, e, block) {                 \
    int var;                                    \
    jmp_buf L ## var;                           \
    if ((var = setjmp(L ## var) + s) < e) {     \
      block;                                    \
      longjmp(L ## var, var - s + 1);           \
    }                                           \
  }

typedef unsigned char u8;
typedef struct {
  u8 key[80];
  u8 iv[40];
  u8 r[100];
  u8 s[100];
} DREAM;

void __nightmare_r(u8 r[], u8 ir, u8 cr)
{
  u8 tap[] = {0,1,3,4,5,6,9,12,13,16,19,20,21,22,25,28,37,38,41,42,45,46,50,52,54,56,58,60,61,63,64,65,66,67,71,72,79,80,81,82,87,88,89,90,91,92,94,95,96,97};
  u8 r_clocked[100];
  u8 fb = r[99] ^ ir, k = 0;

  FOR (i, 0, 100, {
      if (i == 0)
        r_clocked[0] = 0;
      else
        r_clocked[i] = r[i-1];
      if (i == tap[k]) {
        r_clocked[i] ^= fb;
        k++;
      }

      if (cr)
        r_clocked[i] ^= r[i];
    });

  memcpy(r, r_clocked, sizeof(r_clocked));
}

void __nightmare_s(u8 s[], u8 is, u8 cs)
{
  u8 comp0[] = {0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,0,0,0,0,1,0,1,0,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,0,0,0,1,1,0};
  u8 comp1[] = {0,1,0,1,1,0,0,1,0,1,1,1,1,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,1,0,1,1,1,0,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,0,0,1,0,0,1,1,0,0,0};
  u8 fb0[] = {1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1,0,0,0,1,1,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,0};
  u8 fb1[] = {1,1,1,0,1,1,1,0,0,0,0,1,1,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1,0,0,0,0,0,0,1,0,0,0,0,1};
  u8 s_i[100], s_clocked[100];

  u8 fb = s[99] ^ is;
  s_i[0] = 0;
  s_i[99] = s[98];

  FOR (i, 1, 99, {
      s_i[i] = s[i-1] ^ ((s[i] ^ comp0[i]) & (s[i+1] ^ comp1[i]));
    });

  if (cs == 0) {
    FOR (i, 0, 100, {
        s_clocked[i] = s_i[i] ^ fb0[i] ^ fb;
      });
  } else {
    FOR (i, 0, 100, {
        s_clocked[i] = s_i[i] ^ fb1[i] ^ fb;
      });
  }

  memcpy(s, s_clocked, sizeof(s_clocked));
}

void __nightmare(u8 r[], u8 s[], u8 mixing, u8 input_bit)
{
  u8 ir, is;
  u8 cr = s[1] ^ r[14];
  u8 cs = s[51] ^ r[4];

  if (mixing)
    ir = input_bit ^ s[50];
  else
    ir = input_bit;

  is = input_bit;
  __nightmare_r(r, ir, cr);
  __nightmare_s(s, is, cs);
}

u8 create_dream(DREAM *ctx) {
  u8 v = 0;
  FOR (i, 0, 8, {
      v |= (ctx->r[0] ^ ctx->s[0]) << i;
      __nightmare(ctx->r, ctx->s, 0, 0);
    });
  return v;
}

void initialize_dream(DREAM *ctx, u8 *b_key, u8 *b_iv)
{
  FOR (i, 0, 10, {
      FOR(j, 0, 8, {
          ctx->key[i*8+j] = (b_key[i] >> j) & 1;
          if (i < 8)
            ctx->iv [i*8+j] = (b_iv[i] >> j) & 1;
        });
    });

  FOR (i, 0, 100, {
      ctx->r[i] = ctx->s[i] = 0;
    });

  FOR (i, 0, 40, {
      __nightmare(ctx->r, ctx->s, 1, ctx->iv[i]);
    });
  FOR (i, 0, 80, {
      __nightmare(ctx->r, ctx->s, 1, ctx->key[i]);
    });
  FOR (i, 0, 100, {
      __nightmare(ctx->r, ctx->s, 1, 0);
    });
}

int encrypt_file(const char *filepath)
{
  DREAM *ctx;
  char *outpath;
  u8 b_key[10], b_iv[8], c;
  FILE *fin, *fout;

  outpath = (char*)malloc(strlen(filepath) + 5);
  sprintf(outpath, "%s.enc", filepath);
  if (!(fin = fopen(filepath, "rb"))) return -ENOENT;
  if (!(fout = fopen(outpath, "wb"))) return -EBUSY;
  free(outpath);

  ctx = (DREAM*)malloc(sizeof(DREAM));
  if (!ctx) return -ENOMEM;

  getrandom(b_key, 10, 0);
  getrandom(b_iv, 8, 0);

  initialize_dream(ctx, b_key, b_iv);
  while(!feof(fin)) {
    if (fread(&c, sizeof(u8), 1, fin) != 1) break;
    c ^= create_dream(ctx);
    fwrite(&c, sizeof(u8), 1, fout);
  }

  for (int i = 0; i < 13; i++) {
    c = 0;
    for (int j = 0; j < 8; j++) {
      if (i*8+j < 100)
        c |= ctx->r[i*8+j] << j;
    }
    fwrite(&c, sizeof(u8), 1, fout);
  }
  for (int i = 0; i < 13; i++) {
    c = 0;
    for (int j = 0; j < 8; j++) {
      if (i*8+j < 100)
        c |= ctx->s[i*8+j] << j;
    }
    fwrite(&c, sizeof(u8), 1, fout);
  }

  fclose(fin);
  fclose(fout);
  free(ctx);
}

void check_ascii(const char *filepath)
{
  u8 c;
  FILE *fp = fopen(filepath, "rb");
  if (!fp)
    goto die;

  while(!feof(fp)) {
    if (fread(&c, sizeof(u8), 1, fp) != 1) break;
    if (!isgraph(c) && c != '\n') goto die;
  }
  return;

 die:
  puts("[-] Invalid flag format");
  exit(1);
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    printf("Usage: %s <flag file>\n", argv[0]);
    return 1;
  }
  check_ascii(argv[1]);
  encrypt_file(argv[1]);
}
