#include "decryptor_linux.h"
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <libgen.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <algorithm>
#include <cpuid.h>  // x86_64缓存刷新依赖

// ===================== ptrace反调试函数（保留，注释核心逻辑） =====================
void ptrace_anti_debug_check(void) {
    MEM_BAR();
/*
    errno = 0;
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1 && errno == EPERM) {
        *(volatile uint64_t *)0x0 = 0xDEADBEEF;
        exit(-1);
    }
*/
    MEM_BAR();
}

// ===================== Decryptor 静态成员初始化 =====================
Decryptor::TargetType Decryptor::g_target_type = Decryptor::TYPE_SO;
uintptr_t Decryptor::g_base_addr = 0;
char Decryptor::TARGET_NAME[PATH_MAX] = {0};
bool Decryptor::g_is_decrypted = false;
char Decryptor::g_target_path[PATH_MAX] = {0};
bool Decryptor::g_target_loaded = false;

// ===================== Decryptor 核心实现 =====================
Decryptor& Decryptor::getInstance() {
    static Decryptor instance;
    return instance;
}

bool Decryptor::decrypt() {
    ptrace_anti_debug_check();

    Decryptor& instance = getInstance();
    if (g_is_decrypted) {
        printf("[Decryptor] Already decrypted\n");
        return true;
    }

    if (g_target_type == TYPE_SO && strlen(TARGET_NAME) == 0) {
        fprintf(stderr, "[Decryptor] Error: TYPE_SO need target name\n");
        return false;
    }

    printf("[Decryptor] Start decrypt (type: %d, name: %s)\n", g_target_type, TARGET_NAME);
    g_target_loaded = false;
    memset(g_target_path, 0, sizeof(g_target_path));
    g_base_addr = 0;

    bool ret = false;
    if (g_target_type == TYPE_SO) {
        ret = instance.decrypt_so_section_impl();
    } else if (g_target_type == TYPE_STATIC_A) {
        ret = instance.decrypt_executable_section_impl();
    }

    if (ret) {
        g_is_decrypted = true;
        printf("[Decryptor] Decrypt success!\n");
        MEM_BAR();
    } else {
        fprintf(stderr, "[Decryptor] Decrypt failed!\n");
    }
    return ret;
}

bool Decryptor::isDecrypted() { 
    return g_is_decrypted; 
}

void Decryptor::setTargetInfo(TargetType type, const char* name) {
    g_target_type = type;
    g_is_decrypted = false;
    g_target_loaded = false;
    memset(g_target_path, 0, sizeof(g_target_path));
    g_base_addr = 0;
    memset(TARGET_NAME, 0, sizeof(TARGET_NAME));
    
    if (name && strlen(name) > 0) {
        strncpy(TARGET_NAME, name, sizeof(TARGET_NAME)-1);
    }
    
    printf("[DEBUG] Set target: type=%d, name=%s\n", type, TARGET_NAME);
}

bool Decryptor::is_address_accessible(uintptr_t addr, size_t len) {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || addr == 0 || len == 0) return false;
    
    // 避免访问内核空间等非法地址
    if (addr >= (uintptr_t)0x7fffffffffff) return false;
    
    for (size_t i = 0; i < len; i += page_size) {
        volatile uint8_t* p = (volatile uint8_t*)(addr + i);
        uint8_t val = 0;
        errno = 0;
        // 显式转换volatile指针，解决memcpy类型错误
        memcpy(&val, (const void*)p, 1);
        if (errno != 0) return false;
        (void)val;
    }
    
    return true;
}

bool Decryptor::is_target_so(const char* so_path) const {
    return so_path && strlen(so_path) && strstr(so_path, TARGET_NAME) && strstr(so_path, ".so");
}

bool Decryptor::find_target_so_path() {
    if (strlen(TARGET_NAME) == 0) return false;
    
    g_target_loaded = false; 
    memset(g_target_path, 0, sizeof(g_target_path)); 
    g_base_addr = 0;
    
    dl_iterate_phdr(dl_callback_wrapper, this);
    
    if (!g_target_loaded) {
        void* so_handle = dlopen(TARGET_NAME, RTLD_LAZY | RTLD_NOLOAD);
        if (so_handle) {
            Dl_info dl_info;
            if (dladdr(so_handle, &dl_info) && dl_info.dli_fname) {
                strncpy(g_target_path, dl_info.dli_fname, sizeof(g_target_path)-1);
                g_base_addr = (uintptr_t)dl_info.dli_fbase;
                g_target_loaded = true;
            }
            dlclose(so_handle);
        }
    }
    
    return g_target_loaded;
}

bool Decryptor::find_executable_path() {
    g_target_loaded = false;
    memset(g_target_path, 0, sizeof(g_target_path));
    g_base_addr = 0;

    const bool has_target_name = (strlen(TARGET_NAME) > 0);

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) {
        fprintf(stderr, "[Decryptor] Failed to open /proc/self/maps: %s\n", strerror(errno));
        return false;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " r-xp ") == nullptr) continue;

        char* p_path = strchr(line, '/');
        if (!p_path) continue;

        char pathbuf[PATH_MAX] = {0};
        if (sscanf(p_path, "%s", pathbuf) != 1) continue;
        if (pathbuf[0] == '[') continue;

        if (has_target_name && strstr(pathbuf, TARGET_NAME) == nullptr) {
            continue;
        }

        uintptr_t addr = 0;
        if (sscanf(line, "%lx-", &addr) != 1 || addr == 0) continue;

        strncpy(g_target_path, pathbuf, sizeof(g_target_path) - 1);
        g_base_addr = addr;
        g_target_loaded = true;
        break;
    }

    fclose(f);

    if (g_target_loaded && g_base_addr != 0 && strlen(g_target_path)) {
        printf("[Decryptor] Found executable: %s base=0x%lx\n", g_target_path, (unsigned long)g_base_addr);
        return true;
    }

    fprintf(stderr, "[Decryptor] find_executable_path failed\n");
    return false;
}

int Decryptor::dl_callback_wrapper(struct dl_phdr_info* info, size_t size, void* data) {
    return data ? static_cast<Decryptor*>(data)->dl_callback(info, size) : 0;
}

int Decryptor::dl_callback(struct dl_phdr_info* info, size_t size) const {
    (void)size;
    
    if (!info || !info->dlpi_name || strlen(info->dlpi_name) == 0) {
        return 0;
    }
    
    bool is_match = false;
    if (g_target_type == TYPE_SO) {
        is_match = strstr(info->dlpi_name, TARGET_NAME) != nullptr;
    } else {
        char base_path[PATH_MAX];
        strncpy(base_path, g_target_path, sizeof(base_path));
        char* base = basename(base_path);
        is_match = strstr(info->dlpi_name, base) != nullptr;
    }
    
    if (is_match && info->dlpi_addr != 0) {
        strncpy(g_target_path, info->dlpi_name, sizeof(g_target_path)-1);
        g_target_loaded = true;
        g_base_addr = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    
    return 0;
}

bool Decryptor::decrypt_so_section_impl() {
    if (!find_target_so_path() || g_base_addr == 0) return false;
    
    int fd = open(g_target_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[Decryptor] Open SO failed: %s\n", strerror(errno));
        return false;
    }
    
    struct stat st; 
    if (fstat(fd, &st) < 0) { 
        fprintf(stderr, "[Decryptor] Fstat SO failed: %s\n", strerror(errno));
        close(fd); 
        return false; 
    }
    
    uint8_t* so_file = (uint8_t*)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (so_file == MAP_FAILED) { 
        fprintf(stderr, "[Decryptor] Mmap SO failed: %s\n", strerror(errno));
        close(fd); 
        return false; 
    }
    
    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)so_file;
    if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) { 
        fprintf(stderr, "[Decryptor] Not ELF file\n");
        munmap(so_file, st.st_size); 
        close(fd); 
        return false; 
    }

    Elf64_Shdr* sec_hdr = (Elf64_Shdr*)(so_file + elf_hdr->e_shoff);
    const char* sec_names = (const char*)(so_file + sec_hdr[elf_hdr->e_shstrndx].sh_offset);
    
    Elf64_Shdr* encrypt_sec = nullptr; 
    uint64_t sec_vaddr = 0, sec_size = 0;
    
    // 打印所有段 + 定位加密段
    printf("[Decryptor] Start scanning ELF sections (total: %d)\n", elf_hdr->e_shnum);
    for(int i = 0; i < elf_hdr->e_shnum; i++) { 
        const char* sec_name = sec_names + sec_hdr[i].sh_name;
        if (strcmp(sec_name, ".encrypt_text") == 0) { 
            encrypt_sec = &sec_hdr[i]; 
            sec_vaddr = sec_hdr[i].sh_addr; 
            sec_size = sec_hdr[i].sh_size; 
            // 加密段详细信息打印
            printf("[Decryptor] ✅ Found encrypt section: .encrypt_text\n");
            printf("[Decryptor]   - Virtual Address (sh_addr): 0x%lx\n", (unsigned long)sec_vaddr);
            printf("[Decryptor]   - Section Size: 0x%lx (%lu bytes)\n", (unsigned long)sec_size, sec_size);
            printf("[Decryptor]   - File Offset (sh_offset): 0x%lx\n", (unsigned long)sec_hdr[i].sh_offset);
            printf("[Decryptor]   - Section Index: %d\n", i);
            break; 
        }
    }
    
    if (!encrypt_sec || sec_size == 0) { 
        fprintf(stderr, "[Decryptor] ❌ Cannot find .encrypt_text section!\n");
        munmap(so_file, st.st_size); 
        close(fd); 
        return false; 
    }
    
    munmap(so_file, st.st_size); 
    close(fd);

    const long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t sec_real_addr = g_base_addr + sec_vaddr;

    printf("[Decryptor] ELF type=%d sec_vaddr=0x%lx g_base=0x%lx sec_real=0x%lx size=0x%lx\n",
           elf_hdr->e_type, (unsigned long)sec_vaddr, (unsigned long)g_base_addr,
           (unsigned long)sec_real_addr, (unsigned long)sec_size);

    // 正确计算内存页范围，避免越界
    uintptr_t page_start = sec_real_addr & ~((uintptr_t)page_size - 1);
    uintptr_t sec_end = sec_real_addr + sec_size;
    uintptr_t page_end = (sec_end + page_size - 1) & ~((uintptr_t)page_size - 1);
    size_t page_len = page_end - page_start;
    
    if (!is_address_accessible(sec_real_addr, sec_size)) {
        fprintf(stderr, "[Decryptor] ❌ Encrypt section address 0x%lx is not accessible!\n", (unsigned long)sec_real_addr);
        return false;
    }

    // 设置内存权限为RWX
    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "[Decryptor] Failed to set RWX permissions at 0x%lx: %s\n", 
                (unsigned long)page_start, strerror(errno));
        fprintf(stderr, "[Decryptor] Hint: Try 'sudo sysctl -w vm.mmap_min_addr=0' or disable W^X\n");
        return false;
    }

    // 核心修改：替换为极简异或解密
    printf("[Decryptor] Start decrypting .encrypt_text section at 0x%lx (size: %lu bytes)\n", 
           (unsigned long)sec_real_addr, sec_size);
    DecryptTool::simpleXorDecrypt((uint8_t*)sec_real_addr, sec_size);
    flush_cache((uint8_t*)sec_real_addr, sec_size);
    MEM_BAR();

    // 恢复为RX权限
    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "[Decryptor] Failed to restore RX permissions at 0x%lx: %s\n", 
                (unsigned long)page_start, strerror(errno));
        return false;
    }

    printf("[Decryptor] ✅ Decrypted .encrypt_text section successfully!\n");
    return true;
}

bool Decryptor::decrypt_executable_section_impl() {
    if (!find_executable_path() || g_base_addr == 0) return false;
    
    int fd = open(g_target_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[Decryptor] Open executable failed: %s\n", strerror(errno));
        return false;
    }
    
    struct stat st; 
    if (fstat(fd, &st) < 0) { 
        fprintf(stderr, "[Decryptor] Fstat executable failed: %s\n", strerror(errno));
        close(fd); 
        return false; 
    }
    
    uint8_t* elf_file = (uint8_t*)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_file == MAP_FAILED) { 
        fprintf(stderr, "[Decryptor] Mmap executable failed: %s\n", strerror(errno));
        close(fd); 
        return false; 
    }
    
    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)elf_file;
    if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) { 
        fprintf(stderr, "[Decryptor] Not ELF executable\n");
        munmap(elf_file, st.st_size); 
        close(fd); 
        return false; 
    }

    Elf64_Shdr* sec_hdr = (Elf64_Shdr*)(elf_file + elf_hdr->e_shoff);
    const char* sec_names = (const char*)(elf_file + sec_hdr[elf_hdr->e_shstrndx].sh_offset);
    
    Elf64_Shdr* encrypt_sec = nullptr; 
    uint64_t sec_vaddr = 0;
    size_t sec_size = 0;
    
    // 打印可执行文件加密段信息
    printf("[Decryptor] Start scanning executable ELF sections (total: %d)\n", elf_hdr->e_shnum);
    for(int i = 0; i < elf_hdr->e_shnum; i++) { 
        const char* sec_name = sec_names + sec_hdr[i].sh_name;
        if (strcmp(sec_name, ".encrypt_text") == 0) { 
            encrypt_sec = &sec_hdr[i]; 
            sec_vaddr = sec_hdr[i].sh_addr; 
            sec_size = sec_hdr[i].sh_size; 
            printf("[Decryptor] ✅ Found encrypt section: .encrypt_text\n");
            printf("[Decryptor]   - Virtual Address (sh_addr): 0x%lx\n", (unsigned long)sec_vaddr);
            printf("[Decryptor]   - Section Size: 0x%lx (%lu bytes)\n", (unsigned long)sec_size, sec_size);
            printf("[Decryptor]   - File Offset (sh_offset): 0x%lx\n", (unsigned long)sec_hdr[i].sh_offset);
            printf("[Decryptor]   - Section Index: %d\n", i);
            break; 
        }
    }
    
    if (!encrypt_sec || sec_size == 0) { 
        fprintf(stderr, "[Decryptor] ❌ Cannot find .encrypt_text section in executable!\n");
        munmap(elf_file, st.st_size); 
        close(fd); 
        return false; 
    }
    
    munmap(elf_file, st.st_size); 
    close(fd);

    const long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t sec_real_addr = g_base_addr + sec_vaddr;
    
    // 正确计算内存页范围，避免越界
    uintptr_t page_start = sec_real_addr & ~((uintptr_t)page_size - 1);
    uintptr_t sec_end = sec_real_addr + sec_size;
    uintptr_t page_end = (sec_end + page_size - 1) & ~((uintptr_t)page_size - 1);
    size_t page_len = page_end - page_start;
    
    if (!is_address_accessible(sec_real_addr, sec_size)) {
        fprintf(stderr, "[Decryptor] ❌ Executable encrypt section address 0x%lx is not accessible!\n", (unsigned long)sec_real_addr);
        return false;
    }

    // 设置内存权限为RWX
    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "[Decryptor] Failed to set RWX permissions at 0x%lx: %s\n", 
                (unsigned long)page_start, strerror(errno));
        fprintf(stderr, "[Decryptor] Hint: Try 'sudo sysctl -w vm.mmap_min_addr=0' or disable W^X\n");
        return false;
    }

    // 核心修改：替换为极简异或解密
    printf("[Decryptor] Start decrypting executable .encrypt_text section at 0x%lx (size: %lu bytes)\n", 
           (unsigned long)sec_real_addr, sec_size);
    DecryptTool::simpleXorDecrypt((uint8_t*)sec_real_addr, sec_size);
    flush_cache((uint8_t*)sec_real_addr, sec_size);
    __sync_synchronize();
    MEM_BAR();

    // 恢复为RX权限
    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "[Decryptor] Failed to restore RX permissions at 0x%lx: %s\n", 
                (unsigned long)page_start, strerror(errno));
        return false;
    }

    printf("[Decryptor] ✅ Decrypted executable .encrypt_text section successfully!\n");
    return true;
}
