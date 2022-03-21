#include "hollow.h"
#include "common.h"
#include <windows.h>
#include <TlHelp32.h>
// #include "logger.h"
#include <map>
#include <vector>
#include <string>
#include <set>
#include <functional>
#include <sstream>
#include <queue>
#include "spng.h"

using namespace std;

#define PIPE_NAME       L"\\\\.\\pipe\\anime"
#define BUFFER_SIZE     0x1000
#define INVALID_HEIGHT  -1
#define INVALID_PID     -1
#define INVALID_TID     -1
// #define NUM_BITS        2
#define MAX_HEIGHT      NUM_BITS

using resource_t = pair<byte_ptr, usize>;

/**
 * @brief struct defs
 */

enum class Msg : u32 {
  Register,
  AddInputByte,
  GetHeight,
  GetData,
  Spawn,
  Quit,
  CliQuit,
  CheckOrder,
  OnceFlag,
};

struct client_id {
  i32 pid;
  i32 tid;

  client_id() : pid(INVALID_PID), tid(INVALID_TID) {}
  client_id(i32 pid, i32 tid) : pid(pid), tid(tid) {}
  bool operator==(const client_id& o) const {
    return pid == o.pid && tid == o.tid;
  }
  bool operator!=(const client_id& o) const {
    return !(*this == o);
  }
  bool operator<(const client_id& o) const {
    if (pid != o.pid)
      return pid < o.pid;
    return tid < o.tid;
  }
  bool ok() const {
    return pid != INVALID_PID && tid != INVALID_TID;
  }

  string to_str() const {
    char buffer[64]{};
    sprintf(buffer, "%d.%d", pid, tid);
    return string{ buffer };
  }
};

struct Node {
  Node* left;
  Node* right;
  client_id val;
  int color;

  Node() = default;
  Node(client_id v) : left(nullptr),
    right(nullptr), val(v) {}
};

isize handle_register(byte_ptr);
isize handle_add_input_byte(byte_ptr);
isize handle_get_height(byte_ptr);
isize handle_get_data(byte_ptr);
isize handle_spawn(byte_ptr);
isize handle_quit(byte_ptr);
isize handle_client_quit(byte_ptr);
isize handle_check_order(byte_ptr);

/**
 * @brief global data
 */
client_id root_id;
map<client_id, Node*> nodes;
map<Node*, Node*> parent_tbl;
set<client_id> registered_id_list;
vector<client_id> completed_list;
vector<BYTE> input;
map<Msg, function<isize(byte_ptr)>> handlers{
  {Msg::Register, handle_register},
  {Msg::AddInputByte, handle_add_input_byte},
  {Msg::GetHeight, handle_get_height},
  {Msg::GetData, handle_get_data},
  {Msg::Spawn, handle_spawn},
  {Msg::Quit, handle_quit},
  {Msg::CliQuit, handle_client_quit},
  {Msg::CheckOrder, handle_check_order},
};

void __node_to_str__(const Node* node, stringstream& io, string prefix) {
}

string node_to_str(const Node* node) {
#ifndef RELEASE
  stringstream io{};
  string prefix{};
  io << node->val.to_str() << '\n';
  __node_to_str__(node, io, prefix);
  return io.str();
#else
  return "";
#endif
}

/**
 * @brief Get ClientId for current process
 *
 */
auto get_self_id(void) {
  return client_id{
    (i32)(ULONG_PTR)(NtCurrentTeb()->ClientId.UniqueProcess),
    (i32)(ULONG_PTR)(NtCurrentTeb()->ClientId.UniqueThread),
  };
}

/**
 * @brief Get the parent pid object
 *
 * @param pid
 * @return i32
 */
auto get_parent_pid(i32 pid) {
  BOOL ok;
  i32 ppid = INVALID_PID;
  PROCESSENTRY32W info{};
  info.dwSize = sizeof info;

  HANDLE h_snap = xCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  for (ok = xProcess32FirstW(h_snap, &info); ok; ok = xProcess32NextW(h_snap, &info)) {
    if (info.th32ProcessID == (DWORD)pid) {
      ppid = (i32)info.th32ParentProcessID;
      break;
    }
  }
  xCloseHandle(h_snap);
  return ppid;
}

/**
 * @brief Get the main thread's id of process pid
 *
 * @param pid i32
 * @return i32 thread id of main thread of pid
 */
auto get_main_thread_id(i32 pid) {
  BOOL ok;
  ULONG64 min_time = ULONG_LONG_MAX;
  i32 m_tid = INVALID_TID;
  HANDLE h_thread;
  FILETIME create_time, exit_time, kernel_time, user_time;
  THREADENTRY32 info{};
  info.dwSize = sizeof info;

  HANDLE h_snap = xCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  for (ok = xThread32First(h_snap, &info); ok; ok = xThread32Next(h_snap, &info)) {
    if (info.th32OwnerProcessID == pid) {
      h_thread = xOpenThread(
        THREAD_QUERY_INFORMATION,
        FALSE,
        info.th32ThreadID
      );
      if (!h_thread)
        continue; // skip error
      BOOL rv = xGetThreadTimes(h_thread, &create_time,
        &exit_time, &kernel_time, &user_time);
      xCloseHandle(h_thread);
      if (!rv) {
        continue;
      }
      ULONG64 tmp_time = *(PULONG64)&create_time;
      if (tmp_time < min_time) {
        min_time = tmp_time;
        m_tid = (i32)info.th32ThreadID;
      }
    }
  }
  xCloseHandle(h_snap);
  return m_tid;
}

/**
 * @brief Get the parent process of id
 *
 * @param id
 * @return ClientId
 */
client_id get_parent(client_id id) {
  auto ppid = get_parent_pid(id.pid);
  auto tid = INVALID_TID;
  if (ppid != INVALID_PID) {
    tid = get_main_thread_id(ppid);
  }
  return client_id{ ppid, tid };
}

/**
 * @brief allocate memory
 *
 * @param size
 * @return auto
 */
inline auto alloc(size_t size) {
  auto ret = xHeapAlloc(MyHeap, HEAP_ZERO_MEMORY, size);
  if (!ret) {
    exit(1);
  }
  return ret;
}

/**
 * @brief free memory
 *
 * @param mem
 * @return auto
 */
inline auto mfree(LPVOID mem) {
  if (!mem) return;
  xHeapFree(MyHeap, 0, mem);
}


/**
 * @brief Compute the height of the process
 *
 * @param id
 * @return i32
 */
auto get_height(client_id id) {
  i32 height = 0;
  // i32 iter = 0;

  while (id.ok() && id != root_id) {
    id = get_parent(id);
    ++height;
    // ++iter;
  }
  if (id == root_id) {
    return height;
  }
  else {
    return -1;
  }
}

/**
 * @brief Get the child processes of id
 *
 * @param id
 * @return vector<ClientId>
 */
auto get_children(client_id id) {
  vector<client_id> ans;
  HANDLE h_snap;
  BOOL ok;
  PROCESSENTRY32W e{};
  e.dwSize = sizeof e;
  h_snap = xCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  for (ok = xProcess32FirstW(h_snap, &e); ok; ok = xProcess32NextW(h_snap, &e)) {
    if (e.th32ParentProcessID == id.pid) {
      if (wcsstr(e.szExeFile, L"conhost.exe"))
        continue;
      ans.emplace_back(
        e.th32ProcessID, get_main_thread_id(e.th32ProcessID)
      );
    }
  }
  return ans;
}

/**
 * @brief Get the process name
 *
 * @param pid
 * @return string
 */
string get_process_name(i32 pid) {
  string name = "<nil>";
  HANDLE h_snap;
  BOOL ok;
  PROCESSENTRY32W e{};
  e.dwSize = sizeof e;
  h_snap = xCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  for (ok = xProcess32FirstW(h_snap, &e); ok; ok = xProcess32NextW(h_snap, &e)) {
    if (e.th32ProcessID == pid) {
      wstring tmp{ e.szExeFile };
      name = string(begin(tmp), end(tmp));
      break;
    }
  }
  xCloseHandle(h_snap);
  return name;
}

/*
 * Inlined functions
 */

inline client_id from_pid(i32 pid) {
  // i32 get_main_thread_id(i32 pid);
  if (pid == INVALID_PID) {
    return { INVALID_PID, INVALID_TID };
  }
  return { pid, get_main_thread_id(pid) };
}

inline string nameof(client_id id) {
  // string get_process_name(i32 pid);
  if (!id.ok()) return "<nil>";
  string ans = to_string(id.pid) +
    "(" + get_process_name(id.pid) + ")";
  return ans;
}

inline client_id parentof(client_id id) {
  // ClientId get_parent(ClientId id);
  return get_parent(id);
}

/**
 * Major utility functions
 *
 */

 /**
  * @brief find_resource
  * returns address and size of resource
  * given hash
  * @param hash
  * @return resource_t
  */
resource_t find_resource(u32 hash) {
  usize nret;

  auto h_process = xOpenProcess(
    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
    FALSE, root_id.pid
  );
  if (!h_process) {
    return { nullptr, -1 };
  }

  // read peb of root pid
  PROCESS_BASIC_INFORMATION bInfo{};
  // HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

  // ((fn_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess"))
  //   (h_process, 0, &bInfo, sizeof bInfo, &nret);
  xNtQueryInformationProcess(h_process, 0, &bInfo, sizeof bInfo, &nret);

  // read image base
  byte_ptr image_base = nullptr;
  xReadProcessMemory(h_process,
    (byte_ptr)bInfo.PebBaseAddress + 0x10,
    &image_base, sizeof image_base, NULL);

  // search for marker
  auto haystack = byte_ptr(alloc(0x1000));
  usize offset{};
  byte_ptr egg_ptr = nullptr;
  bool fail = false;

  while (!egg_ptr && xReadProcessMemory(
    h_process, image_base + offset, haystack,
    0x1000, &nret
  )) {
    u8 magic[8]{};
    *(u64*)&magic[0] = EGG_SIGNATURE;
    for (usize i = 0; i < 0x1000 - 8; ++i) {
      usize n_mahouka{};
      for (size_t j = 0; j < 8; ++j)
      {
        n_mahouka += (magic[j] == haystack[i + j]);
      }
      if (n_mahouka == 8) {
        egg_ptr = image_base + offset + i;
        break;
      }
    }
    offset += 0x1000;
  }

  mfree(haystack);

  byte_ptr res_addr{};
  usize res_size{};
  if (!egg_ptr) {
    goto free_res;
  }

  // count resources
  usize n_res{};
  u8 buf[16];
  xReadProcessMemory(h_process, egg_ptr + 8, &n_res, 8, &nret);
  egg_ptr += 16;
  for (usize i = 0; i < n_res; ++i) {
    xReadProcessMemory(h_process, egg_ptr, buf, 16, &nret);
    egg_ptr += 16;
    auto s = *(u32*)(buf + 8);
    if (hash == *(u32*)(buf)) {
      res_size = s;
      res_addr = egg_ptr;
      break;
    }
    egg_ptr += s % 8 ? 8 - s % 8 : 0;
    egg_ptr += s;
  }

free_res:
  xCloseHandle(h_process);
  return { res_addr, res_size };
}

// #pragma comment(lib, "advapi32")

auto decrypt(HANDLE hpr, resource_t res) {
  char key[] = "abO4oHxrfR03YwaX4KuEFUoV";
  HCRYPTPROV hProv;
  xCryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
  HCRYPTHASH hHash;
  xCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
  xCryptHashData(hHash, (BYTE*)key, strlen(key), 0);
  HCRYPTKEY hKey;
  xCryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey);
  std::vector<BYTE> ans{};
#define AES_KEY_SIZE 16
#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10)
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2)
  const auto chunk_size = IN_CHUNK_SIZE;
  BYTE* chunk = new BYTE[chunk_size];
  DWORD out_len = 0;
  BOOL isFinal = FALSE;
  usize pos = 0, nRead = 0, totRead = 0;
  while (xReadProcessMemory(hpr, res.first + pos, chunk, IN_CHUNK_SIZE, &nRead)) {
    if (nRead == 0) break;
    totRead += nRead;
    pos += nRead;
    if (totRead >= res.second) {
      isFinal = TRUE;
    }
    // memcpy(chunk, &data[pos], read_size);
    // out_len = read_size;
    xCryptDecrypt(hKey, NULL, isFinal, 0, chunk, (PDWORD)&nRead);
    // printf("encrypted chunk size: %d\n", nRead);
    for (usize j = 0; j < nRead; ++j)
      ans.push_back(chunk[j]);
    memset(chunk, 0, chunk_size);
  }
  delete[] chunk;
  xCryptDestroyHash(hHash);
  xCryptDestroyKey(hKey);
  xCryptReleaseContext(hProv, 0);
  return ans;
}

/**
 * @brief spawn_helper
 * helper function to spawn processes
 *
 * @param target target process
 * @param source source process
 * @param res payload
 * @param mask flags
 */
auto spawn_helper(
  client_id target,
  client_id source,
  resource_t res,
  u32 mask) {

  HANDLE h_target_process = xOpenProcess(
    PROCESS_ALL_ACCESS, FALSE, target.pid
  );
  if (!h_target_process) {
    return;
  }

  HANDLE h_source_process = xOpenProcess(
    PROCESS_ALL_ACCESS, FALSE, source.pid
  );
  if (!h_source_process) {
    goto close_target;
  }

  HANDLE h_target_thread = xOpenThread(
    THREAD_ALL_ACCESS, FALSE, target.tid
  );
  if (!h_target_thread) {
    goto close_source;
  }

  auto decrypted_buf = decrypt(h_source_process, res);

  // inject payload
  auto peb_addr = (u64)Hollowing(
    h_target_process, h_target_thread,
    // h_source_process, get<0>(res), get<1>(res)
    h_source_process, decrypted_buf
  );
  std::vector<u8>().swap(decrypted_buf);
  auto ht = get_height(target);
  if (ht == INVALID_HEIGHT) {
    goto close_thread;
  }

  auto bit = input.back();
  bit >>= ht - 1; // TODO: check this
  bit %= 2;
  u8 value = mask % 2;
  value |= bit << 1;
  value |= (mask >> 1) << 2;
  value |= ((u32)(ht > MAX_HEIGHT)) << 3;
  auto target_node = new Node{ target };
  target_node->color = value % 2;
  target_node->color |= (value >> 2) % 2 << 1;
  nodes.try_emplace(target, target_node);


  // logger("Color: %s, Direction: %s, Bit: %d",
  //   (value >> 2 & 1) ? "R" : "G",
  //   (value & 1) ? "Right" : "Left",
  //   (value >> 1 & 1)
  // );

  // store the value
  xNtWriteVirtualMemory(
    h_target_process, (byte_ptr)peb_addr + 2,
    &value, 1, nullptr
  );

close_thread:
  xCloseHandle(h_target_thread);
close_source:
  xCloseHandle(h_source_process);
close_target:
  xCloseHandle(h_target_process);
}

/**
 * @brief haskell entry point
 *
 * @return i32
 */
i32 hs_main() {
  // Sleep(20000);
  auto h_pipe = xCreateNamedPipeW(
    PIPE_NAME, PIPE_ACCESS_DUPLEX,
    PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_READMODE_BYTE,
    1,
    PAGE_SIZE, PAGE_SIZE,
    0,
    nullptr
  );

  if ((i64)h_pipe <= 0) {
    return -1;
  }

  i32 ret_val = 0;
  auto ok = xConnectNamedPipe(h_pipe, nullptr) ?
    true : (MyLastErr == ERROR_PIPE_CONNECTED);
  if (!ok) {

    goto close_server_pipe;
  }

  usize nret;
  auto buffer = (byte_ptr)alloc(PAGE_SIZE);
  ok = xReadFile(h_pipe, buffer, PAGE_SIZE, (PDWORD)&nret, NULL);
  if (!ok || !nret) {

    goto free_buffer;
  }

  // loghex("ReadFile:", buffer, nret);
  auto p = handlers.find((Msg)*buffer);
  if (p != end(handlers)) {
    auto nbytes = p->second(buffer + 4);
    if (nbytes < 0) {
      ret_val = -nbytes;
    }
    else {
      xWriteFile(h_pipe, buffer, nbytes, NULL, NULL);
    }
  }
  // mfree(buffer);
  xFlushFileBuffers(h_pipe);
  xDisconnectNamedPipe(h_pipe);

free_buffer:
  mfree(buffer);
close_server_pipe:
  xCloseHandle(h_pipe);
  return ret_val;
}

/**
 * @brief rust binary entry point
 *
 * @return i32
 */
i32 rs_main() {
  auto self_id = get_self_id();

  root_id = parentof(self_id);
  if (!root_id.ok()) {
    // log_err("failed to get ppid for %s", self_id.to_str().c_str());
    return -1;
  }

  nodes[root_id] = new Node{ root_id };
  input.clear();
  while (hs_main() == 0);


  return 0;
}

/**
 * @brief main routine!
 *
 * @return i32
 */
 // i32 main() {
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
  // load_fn(0xb4c88397, 0xbc4da2be);
  // handle_once_flag(NULL);
  // return 0;
#ifndef RELEASE
  freopen("anime.log", "w", stdout);
#endif
  return rs_main();
}

/**
 * @brief register message
 *
 * [pid (4B)][tid (4B)]
 */
isize handle_register(byte_ptr buffer) {
  client_id id{
    *(i32*)buffer, *(i32*)(buffer + 4)
  };

  registered_id_list.insert(id);
  *(u32*)(buffer - 4) = 0xdead;
  return 4;
}

/**
 * @brief add input byte
 *
 * [byte (1B)]
 */
isize handle_add_input_byte(byte_ptr buffer) {

  input.emplace_back(*buffer);
  *(u32*)(buffer - 4) = 0xc0de;
  return 4;
}

/**
 * @brief get height
 *
 * [pid (4B)][tid (4B)]
 */
isize handle_get_height(byte_ptr buffer) {
  client_id id{
      *(i32*)buffer, *(i32*)(buffer + 4)
  };
  auto ht = get_height(id);

  *(u32*)(buffer - 4) = 0x12345678;
  *(u32*)(buffer + 0) = ht > MAX_HEIGHT;
  return 8;
}

/**
 * @brief get data
 *
 * [hash (4B)]
 */
isize handle_get_data(byte_ptr buffer) {
  u32 hash = *(u32*)buffer;

  auto res = find_resource(hash);
  *(u32*)(buffer - 4) = 0xbadf00d;
  *(u64*)(buffer + 4) = (u64)get<0>(res);
  *(u32*)(buffer + 12) = get<1>(res);
  *(u32*)(buffer + 16) = root_id.pid;
  *(u32*)(buffer + 20) = root_id.tid;
  return 4 + 4 + 8 + 4 + 4 + 4;
}

/**
 * @brief spawn process
 *
 * target_pid, target_tid, payload_addr, payload_size, flags
 */
isize handle_spawn(byte_ptr buffer) {
  client_id target{
    *(i32*)buffer,
    *(i32*)(buffer + 4),
  };
  resource_t res{
    *(byte_ptr*)(buffer + 12), *(u32*)(buffer + 20)
  };
  u32 flags = *(u32*)(buffer + 24);
  client_id source{
    *(i32*)(buffer + 28),
    *(i32*)(buffer + 32),
  };
  // if (!registered_id_list.count(source)) {
  //   
  //   *(u32*)(buffer - 4) = 0xcafebabe;
  //   *(i32*)(buffer) = -1;
  //   return 8;
  // }
  // parent_tbl[target] = source;

  // source.to_str().c_str(),
  //   target.to_str().c_str()
  //   );
    // auto source_node = new Node{ source };
    // nodes.try_emplace(source, source_node);
  spawn_helper(target, root_id, res, flags);
  *(u32*)(buffer - 4) = 0xcafebabe;
  *(i32*)(buffer) = 0;
  return 8;
}

isize handle_quit(byte_ptr buffer) {

  return -2;
}

/**
 * @brief node completes it's work
 * node_pid, node_tid
 * @param buffer
 * @return isize
 */
isize handle_client_quit(byte_ptr buffer) {
  auto pid = *(i32*)(buffer);
  auto tid = *(i32*)(buffer + 4);
  auto cl = client_id{ pid, tid };

  completed_list.emplace_back(cl);
  while (cl.ok() && cl != root_id) {

    auto pp = parentof(cl);

    if (!pp.ok()) break;
    // insert if not exists
    parent_tbl.try_emplace(nodes[cl], nodes[pp]);
    if (nodes[cl]->color % 2) {
      nodes[pp]->right = nodes[cl];
    }
    else {
      nodes[pp]->left = nodes[cl];
    }
    // parent_tbl[nodes[cl]] = nodes[pp];
    cl = pp;
  }

  return 4;
}

bool is_prime(usize n) {
  if (n == 2) return true;
  if (n < 2 || n % 2 == 0 && n > 2) return false;
  for (usize i = 3; i * i <= n; i += 2)
    if (n % i == 0) return false;
  return true;
}

isize handle_check_order(byte_ptr buffer) {


  string s{};
  deque<client_id> q{};
  q.emplace_back(root_id);
  while (q.size()) {
    auto curr = q.front();
    q.pop_front();
    s += to_string((nodes[curr]->color >> 1) % 2);
    for (auto child : { nodes[curr]->left, nodes[curr]->right }) {
      if (child) {
        q.emplace_back(child->val);
      }
    }
  }
  s.erase(0, 1);

  nodes.clear();
  nodes[root_id] = new Node{ root_id };
  parent_tbl.clear();
  registered_id_list.clear();
  completed_list.clear();
  // input.clear();
  auto h_read = (HANDLE) * (u32*)(buffer);
  auto h_write = (HANDLE) * (u32*)(buffer + 4);
  auto h_process = xOpenProcess(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
    FALSE, root_id.pid
  );


  HANDLE h_this_read, h_this_write;
  xDuplicateHandle(h_process, h_read, (HANDLE)-1,
    &h_this_read, 0, FALSE, DUPLICATE_SAME_ACCESS);
  xDuplicateHandle(h_process, h_write, (HANDLE)-1,
    &h_this_write, 0, FALSE, DUPLICATE_SAME_ACCESS);



  u8 pipe_buf[16];
  usize ret;
  xReadFile(h_this_read, pipe_buf, 16, (LPDWORD)&ret, NULL);
  auto addr = *(byte_ptr*)pipe_buf;
  auto size = *(u32*)(pipe_buf + 8);


  spng_ctx* ctx = spng_ctx_new(0);
  auto buf = byte_ptr(alloc(size));
  isize rem = (isize)size;
  isize offset = 0;
  while (rem > 0 && xReadProcessMemory(h_process, addr + offset, buf + offset, rem, &ret)) {
    offset += ret;
    rem -= ret;
  }
  // logger("GetLastError: %x", GetLastError());
  // loghex("read png:", buf, 32);
  spng_set_png_buffer(ctx, buf, size);
  usize out_size;
  spng_decoded_image_size(ctx, SPNG_FMT_RGB8, &out_size);
  auto out = (byte_ptr)alloc(out_size);
  spng_decode_image(ctx, out, out_size, SPNG_FMT_RGB8, 0);
  spng_ctx_free(ctx);


  extern usize last_index;
  string got{};
  usize cpos{};
  bool ok{ true };
  for (; cpos < s.size() && last_index < out_size; last_index += 3) {
    if (is_prime(last_index / 3)) {
      // got += to_string(out[i] & 1);
      ok &= out[last_index] % 2 == (s[cpos++] ^ 0x30);
    }
  }
  // logger("OK? %d", ok);
  // Sleep(5000);

  mfree(out);
  mfree(buf);

  xCloseHandle(h_this_read);
  xCloseHandle(h_this_write);
  xCloseHandle(h_process);

  *(u32*)buffer = ok ? 0 : (rand() % 1336 + 1);

  return 8;
}


usize last_index;