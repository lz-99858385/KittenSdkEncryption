/*#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits.h>
#include <unistd.h>
#include <sys/link.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <errno.h>

// ARM64 QNX 强制指令对齐+段属性，和加密端一致
#define CRYPT_FUNC __attribute__((section(".encrypt_text"), aligned(4), alloc, execinstr, pure))

// ARM64 QNX 原生硬件屏障指令
#define DSB_SYNC()  __asm__ __volatile__ ("dsb sy" ::: "memory", "cc")
#define ISB_SYNC()  __asm__ __volatile__ ("isb sy" ::: "memory", "cc")
#define MEM_BAR()   __asm__ __volatile__ ("" ::: "memory")

// ✅ 正确的ARM64 QNX缓存刷新函数 (end在前，start在后)
static inline void flush_arm64_cache(uint8_t* start, size_t len)
{
    if (!start || len == 0) return;
    uint8_t* end = start + len - 1;
    extern void __clear_cache(void*, void*);
    __clear_cache((void*)end, (void*)start);
    DSB_SYNC();
    ISB_SYNC();
    MEM_BAR();
}

// ✅ 极简解密工具类
class DecryptTool {
public:
    DecryptTool() = delete;
    ~DecryptTool() = delete;
    DecryptTool(const DecryptTool&) = delete;
    DecryptTool& operator=(const DecryptTool&) = delete;

    static void simple_xor_crypt(uint8_t* data, size_t len);

private:
    static const uint8_t XOR_KEY[16];
    static const size_t  XOR_KEY_LEN;
};

// ✅ 解密核心类
class Decryptor {
public:
    enum TargetType {
        TYPE_SO = 0,
        TYPE_STATIC_A = 1
    };

    static bool decrypt();
    static bool isDecrypted();
    static void setTargetInfo(TargetType type, const char* name = nullptr);

private:
    static TargetType g_target_type;
    static uintptr_t g_base_addr;
    static char TARGET_NAME[PATH_MAX];
    static bool g_is_decrypted;
    static char g_target_path[PATH_MAX];
    static bool g_target_loaded;

    bool is_address_accessible(uintptr_t addr, size_t len);
    bool is_target_so(const char* so_path) const;
    bool find_target_so_path();
    bool find_executable_path();
    bool decrypt_so_section_impl();
    bool decrypt_executable_section_impl();
    int dl_callback(const struct dl_phdr_info* info, size_t size) const;
    static int dl_callback_wrapper(const struct dl_phdr_info* info, size_t size, void* data);
    static Decryptor& getInstance();
    Decryptor() = default;
    ~Decryptor() = default;
    Decryptor(const struct Decryptor&) = delete;
    Decryptor& operator=(const struct Decryptor&) = delete;
};

#endif // DECRYPTOR_H
*/