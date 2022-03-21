#include <Windows.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "user32")
#pragma comment(lib, "advapi32")

#include "common.h"

#include <vector>
#include <fstream>

struct reslist {
  const char* name;
  const char* file_name;
} resources[] = {
  {"bootstrapper", "bootstrapper.exe"},
  {"animelistg", "anime_list/animelist.exe"},
  {"cmd", "cmd_open.exe"},
  {0, 0},
};

struct entry {
  UINT64 hash;
  UINT32 len;
  BYTE data[0];
};

auto hasher(const char* name) {
  const auto prime = 16777619U;
  const auto basis = 2166136261U;
  auto hash = basis;
  const auto len = strlen(name);
  for (size_t i = 0; i < len; ++i) {
    hash ^= name[i];
    hash *= prime;
  }
  return hash;
}

uint32_t jenkins_one_at_a_time_hash(const uint8_t* key, size_t length) {
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

std::vector<BYTE> readFile(const char* filename)
{
  // open the file:
  std::ifstream file(filename, std::ios::binary);

  // read the data:
  return std::vector<BYTE>(
    std::istreambuf_iterator<char>(file),
    std::istreambuf_iterator<char>()
    );
}

void write_i64(std::vector<BYTE>& vec, UINT64 val) {
  for (size_t i = 0; i < 8; ++i) {
    vec.push_back((val & 0xff));
    val >>= 8;
  }
}

// encrypt & decrypt
char key[] = "abO4oHxrfR03YwaX4KuEFUoV";
std::vector<BYTE> encrypt(std::vector<BYTE> data) {
  HCRYPTPROV hProv;
  CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
  HCRYPTHASH hHash;
  CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
  CryptHashData(hHash, (BYTE*)key, strlen(key), 0);
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey);
  std::vector<BYTE> ans{};
#define AES_KEY_SIZE 16
#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10)
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2)
  const auto chunk_size = OUT_CHUNK_SIZE;
  BYTE* chunk = new BYTE[chunk_size];
  DWORD out_len = 0;
  BOOL isFinal = FALSE;
  usize pos = 0, nRead = 0;
  for (; pos < data.size(); pos += chunk_size) {
    auto read_size = min(chunk_size, data.size() - pos);
    if (read_size < chunk_size) {
      isFinal = TRUE;
    }
    memcpy(chunk, &data[pos], read_size);
    out_len = read_size;
    CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size);
    // printf("encrypted chunk size: %d\n", out_len);
    for (usize j = 0; j < out_len; ++j)
      ans.push_back(chunk[j]);
  }
  delete[] chunk;
  CryptDestroyHash(hHash);
  CryptDestroyKey(hKey);
  CryptReleaseContext(hProv, 0);
  return ans;
}

int
main() {
  HANDLE h_updater;

  h_updater = BeginUpdateResourceW(L"task.exe", FALSE);
  if (!h_updater) {
    printf("BeginUpdateResource failed.\n");
    return 0;
  }

  std::vector<BYTE> payload;
  write_i64(payload, EGG_SIGNATURE);
  auto n_res = sizeof resources / sizeof * resources;
  write_i64(payload, n_res - 1);

  for (reslist* p = resources; *(LPVOID**)p; ++p) {
    auto data = readFile(p->file_name);
    auto hh = hasher(p->name);
    printf("[*] Adding %s, hash = %#016x\n", p->name, hh);
    write_i64(payload, hh);
    data = encrypt(data);
    write_i64(payload, data.size());
    // align to 8
    auto pad_size = data.size() & 7;
    payload.insert(std::end(payload), std::begin(data), std::end(data));
    if (pad_size)
      payload.insert(std::end(payload), 8 - pad_size, 0);
  }
  if (!UpdateResourceW(
    h_updater, (LPCWSTR)RT_RCDATA,
    L"SCR1PT", 0, payload.data(), payload.size()
  )) {
    auto lstErr = GetLastError();
    wprintf(L"Last Error: %08x\n", lstErr);
  }

  auto splash_pic = readFile("mkimg/image.png");
  if (!UpdateResourceW(
    h_updater, (LPWSTR)RT_ICON, MAKEINTRESOURCEW(12),
    2057, splash_pic.data(), splash_pic.size()
  )) {
    auto lstErr = GetLastError();
    wprintf(L"Failed to add splash: %08x\n", lstErr);
  }
  EndUpdateResourceW(h_updater, FALSE);
}