#ifndef DECRYPTOR_LINUX_H
#define DECRYPTOR_LINUX_H

#pragma GCC diagnostic ignored "-Wattributes"

// ========== 必须放在第一行！！！解决dl_phdr_info不完整的唯一办法 ==========
#include <dlfcn.h>          // 直接暴露dl_phdr_info完整定义 + dl_iterate_phdr声明
// ========== 基础头文件 ==========
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <elf.h>
#include <libgen.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <limits.h>
#include <link.h>
#include <cstdint>
// ========== 保留宏定义 ==========
#define CRYPT_FUNC __attribute__((section(".encrypt_text")))
#define MEM_BAR()   __asm__ __volatile__ ("" ::: "memory")

// ========== 极简异或密钥（加密/解密共用，可自定义） ==========
static const uint8_t XOR_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
static const size_t XOR_KEY_LEN = sizeof(XOR_KEY) / sizeof(XOR_KEY[0]);

// ========== 缓存刷新函数（保留） ==========
static inline void flush_cache(uint8_t* start, size_t len)
{
    if (!start || len == 0) return;
    #ifdef __linux__
        // 增强缓存刷新：x86_64专用clflush + 通用clear_cache
        __builtin___clear_cache((char*)start, (char*)(start + len));
        // 循环刷新每个缓存行（x86_64缓存行64字节）
        const size_t cache_line = 64;
        for (size_t i = 0; i < len; i += cache_line) {
            __builtin_ia32_clflush(start + i);
        }
        __sync_synchronize(); // 内存屏障，确保刷新生效
    #else
        asm volatile("" ::: "memory");
    #endif
}

// ========== 反调试函数（保留，注释掉实际逻辑） ==========
void ptrace_anti_debug_check(void);

// ========== 极简DecryptTool类（仅异或解密） ==========
class DecryptTool {
public:
    DecryptTool() = delete;
    ~DecryptTool() = delete;
    DecryptTool(const DecryptTool&) = delete;
    DecryptTool& operator=(const DecryptTool&) = delete;
    
    // 核心：极简异或解密（加密端用相同逻辑加密）
    static void simpleXorDecrypt(uint8_t* data, size_t len) {
        if (!data || len == 0) return;
        // 循环异或密钥，100%可逆，无任何分段/位操作问题
        for (size_t i = 0; i < len; i++) {
            data[i] ^= XOR_KEY[i % XOR_KEY_LEN];
        }
    }
};

// ========== Decryptor类（结构保留，仅替换解密调用） ==========
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
    
    // 直接用完整定义的dl_phdr_info，无任何前向声明！
    int dl_callback(struct dl_phdr_info* info, size_t size) const;
    static int dl_callback_wrapper(struct dl_phdr_info* info, size_t size, void* data);
    
    static Decryptor& getInstance();
    Decryptor() = default;
    ~Decryptor() = default;
    Decryptor(const Decryptor&) = delete;
    Decryptor& operator=(const Decryptor&) = delete;
};

#endif // DECRYPTOR_LINUX_H
