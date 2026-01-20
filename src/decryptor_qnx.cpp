/*#pragma GCC diagnostic ignored "-Wattributes"
#include "decryptor.h"
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <sys/elf.h>
#include <libgen.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>

// ✅ 与加密端完全一致的固定16位密钥，一字不差
const uint8_t DecryptTool::XOR_KEY[16] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
const size_t  DecryptTool::XOR_KEY_LEN = sizeof(DecryptTool::XOR_KEY)/sizeof(DecryptTool::XOR_KEY[0]);

// ✅ 纯净极简异或解密，加密解密通用，无任何printf日志
void DecryptTool::simple_xor_crypt(uint8_t* data, size_t len)
{
    if (!data || len == 0) return;
    for (size_t i = 0; i < len; ++i)
    {
        volatile uint8_t* p = &data[i];
        *p = *p ^ XOR_KEY[i % XOR_KEY_LEN];
    }
}

// ===================== Decryptor 静态成员初始化 =====================
Decryptor::TargetType Decryptor::g_target_type = Decryptor::TYPE_SO;
uintptr_t Decryptor::g_base_addr = 0;
char Decryptor::TARGET_NAME[PATH_MAX] = {0};
bool Decryptor::g_is_decrypted = false;
char Decryptor::g_target_path[PATH_MAX] = {0};
bool Decryptor::g_target_loaded = false;

// ✅ 单例实现
Decryptor& Decryptor::getInstance() {
    static Decryptor instance;
    return instance;
}

// ✅ 对外解密接口
bool Decryptor::decrypt() {
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
        DSB_SYNC();
        ISB_SYNC();
        MEM_BAR();
    } else {
        fprintf(stderr, "[Decryptor] Decrypt failed!\n");
    }
    return ret;
}

bool Decryptor::isDecrypted() { return g_is_decrypted; }

// ✅ 设置目标信息
void Decryptor::setTargetInfo(TargetType type, const char* name) {
    g_target_type = type;
    g_is_decrypted = false;
    g_target_loaded = false;
    memset(g_target_path, 0, sizeof(g_target_path));
    g_base_addr = 0;
    memset(TARGET_NAME, 0, sizeof(TARGET_NAME));
    if (type == TYPE_STATIC_A && name && strlen(name) >0) {
        strncpy(TARGET_NAME, name, sizeof(TARGET_NAME)-1);
    } else if(type == TYPE_SO && name && strlen(name) >0) {
        strncpy(TARGET_NAME, name, sizeof(TARGET_NAME)-1);
    }
    printf("[DEBUG] Set target: type=%d, name=%s\n", type, TARGET_NAME);
}

// ✅ 检查地址是否可访问
bool Decryptor::is_address_accessible(uintptr_t addr, size_t len) {
    const long qnx_page_size = sysconf(_SC_PAGESIZE);
    if (qnx_page_size <=0) return false;
    for (size_t i=0; i<len; i+=qnx_page_size) {
        volatile uint8_t* p = (volatile uint8_t*)(addr+i);
        uint8_t val = *p; (void)val;
    }
    return true;
}

// ✅ dl_iterate_phdr回调包装
int Decryptor::dl_callback_wrapper(const struct dl_phdr_info* info, size_t size, void* data) {
    return data ? static_cast<Decryptor*>(data)->dl_callback(info, size) : 0;
}

// ✅ 遍历ELF回调函数
int Decryptor::dl_callback(const struct dl_phdr_info* info, size_t size) const {
    (void)size;
    if (!info || !info->dlpi_name || strlen(info->dlpi_name) ==0) return 0;
    bool is_match = false;
    if (g_target_type == TYPE_SO) {
        is_match = strstr(info->dlpi_name, TARGET_NAME) != nullptr;
    } else {
        is_match = strcmp(info->dlpi_name, g_target_path) ==0 || strstr(info->dlpi_name, basename((char*)g_target_path)) != nullptr;
    }
    if (is_match && info->dlpi_addr !=0) {
        strncpy(g_target_path, info->dlpi_name, sizeof(g_target_path)-1);
        g_target_loaded = true;
        g_base_addr = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    return 0;
}

// ✅ 判断是否是目标SO
bool Decryptor::is_target_so(const char* so_path) const {
    return so_path && strlen(so_path) && strstr(so_path, TARGET_NAME) && strstr(so_path, ".so");
}

// ✅ 查找目标SO路径
bool Decryptor::find_target_so_path() {
    if (strlen(TARGET_NAME) ==0) return false;
    g_target_loaded = false; memset(g_target_path,0,sizeof(g_target_path)); g_base_addr=0;
    dl_iterate_phdr(dl_callback_wrapper, this);
    if (!g_target_loaded) {
        void* so_handle = dlopen(TARGET_NAME, RTLD_LOCAL | RTLD_NOLOAD);
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

// ✅ SO文件解密实现 (仅一份，无重复)
bool Decryptor::decrypt_so_section_impl() {
    if (!find_target_so_path() || g_base_addr ==0) return false;
    int fd = open(g_target_path, O_RDONLY | O_CLOEXEC);
    if (fd <0) return false;
    struct stat st; if (fstat(fd, &st) <0) { close(fd); return false; }
    uint8_t* so_file = (uint8_t*)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd,0);
    if (so_file == MAP_FAILED) { close(fd); return false; }
    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)((uintptr_t)so_file +7 & ~7);
    if (memcmp(elf_hdr->e_ident, ELFMAG,4) !=0) { munmap(so_file, st.st_size); close(fd); return false; }

    Elf64_Phdr* prog_hdr = (Elf64_Phdr*)(so_file + elf_hdr->e_phoff);
    uint64_t load_vaddr=0, load_offset=0; bool load_found=false;
    for(int i=0; i<elf_hdr->e_phnum; i++) { if (prog_hdr[i].p_type == PT_LOAD) { load_vaddr=prog_hdr[i].p_vaddr; load_offset=prog_hdr[i].p_offset; load_found=true; break; } }
    if (!load_found) { munmap(so_file, st.st_size); close(fd); return false; }

    Elf64_Shdr* sec_hdr = (Elf64_Shdr*)(so_file + elf_hdr->e_shoff);
    const char* sec_names = (const char*)(so_file + sec_hdr[elf_hdr->e_shstrndx].sh_offset);
    Elf64_Shdr* encrypt_sec=nullptr; uint64_t sec_vaddr=0, sec_size=0;
    for(int i=0; i<elf_hdr->e_shnum; i++) { if (strcmp(sec_names+sec_hdr[i].sh_name, ".encrypt_text")==0) { encrypt_sec=&sec_hdr[i]; sec_vaddr=sec_hdr[i].sh_addr; sec_size=sec_hdr[i].sh_size; break; } }
    if (!encrypt_sec || sec_size==0) { munmap(so_file, st.st_size); close(fd); return false; }
    munmap(so_file, st.st_size); close(fd);

    const long qnx_page_size = sysconf(_SC_PAGESIZE);
    uintptr_t sec_real_addr = g_base_addr + (sec_vaddr - load_vaddr);
    uintptr_t page_start = sec_real_addr & ~((uintptr_t)qnx_page_size -1);
    size_t page_len = ((sec_real_addr + sec_size - page_start) + qnx_page_size -1) & ~((uintptr_t)qnx_page_size -1);
    if (!is_address_accessible(sec_real_addr, sec_size)) return false;

    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) !=0) {
        DecryptTool::simple_xor_crypt((uint8_t*)sec_real_addr, sec_size);
        flush_arm64_cache((uint8_t*)sec_real_addr, sec_size);
        return true;
    }
    DecryptTool::simple_xor_crypt((uint8_t*)sec_real_addr, sec_size);
    flush_arm64_cache((uint8_t*)sec_real_addr, sec_size);
    DSB_SYNC(); ISB_SYNC(); MEM_BAR();
    mprotect((void*)page_start, page_len, PROT_READ | PROT_EXEC);
    return true;
}

// ✅ 查找可执行文件路径 (仅一份，无重复)
bool Decryptor::find_executable_path() {
    g_target_loaded = false; memset(g_target_path,0,sizeof(g_target_path)); g_base_addr=0;
    extern int main(int, char**); Dl_info dl_info;
    if (dladdr((void*)main, &dl_info) && dl_info.dli_fname) strncpy(g_target_path, dl_info.dli_fname, sizeof(g_target_path)-1);
    else if (strlen(TARGET_NAME) >0) strncpy(g_target_path, TARGET_NAME, sizeof(g_target_path)-1);
    else return false;
    dl_iterate_phdr(dl_callback_wrapper, this);
    if (!g_target_loaded || g_base_addr ==0) {
        void* self_handle = dlopen(NULL, RTLD_LOCAL);
        if (self_handle) { g_base_addr=(uintptr_t)self_handle; g_target_loaded=true; }
    }
    return g_target_loaded && strlen(g_target_path) && g_base_addr;
}

// ✅ 静态可执行文件解密实现 (仅一份，无重复)
bool Decryptor::decrypt_executable_section_impl() {
    if (!find_executable_path() || g_base_addr ==0) return false;
    int fd = open(g_target_path, O_RDONLY | O_CLOEXEC);
    if (fd <0) return false;
    struct stat st; if (fstat(fd, &st) <0) { close(fd); return false; }
    uint8_t* elf_file = (uint8_t*)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd,0);
    if (elf_file == MAP_FAILED) { close(fd); return false; }
    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)((uintptr_t)elf_file +7 & ~7);
    if (memcmp(elf_hdr->e_ident, ELFMAG,4) !=0) { munmap(elf_file, st.st_size); close(fd); return false; }

    Elf64_Phdr* prog_hdr = (Elf64_Phdr*)(elf_file + elf_hdr->e_phoff);
    uint64_t load_vaddr=0, load_offset=0; bool load_found=false;
    for(int i=0; i<elf_hdr->e_phnum; i++) { if (prog_hdr[i].p_type == PT_LOAD && (prog_hdr[i].p_flags & (PF_R|PF_X))) { load_vaddr=prog_hdr[i].p_vaddr; load_offset=prog_hdr[i].p_offset; load_found=true; break; } }
    if (!load_found) { munmap(elf_file, st.st_size); close(fd); return false; }

    Elf64_Shdr* sec_hdr = (Elf64_Shdr*)(elf_file + elf_hdr->e_shoff);
    const char* sec_names = (const char*)(elf_file + sec_hdr[elf_hdr->e_shstrndx].sh_offset);
    Elf64_Shdr* encrypt_sec=nullptr; uint64_t sec_vaddr=0, sec_size=0;
    for(int i=0; i<elf_hdr->e_shnum; i++) { if (strcmp(sec_names+sec_hdr[i].sh_name, ".encrypt_text")==0) { encrypt_sec=&sec_hdr[i]; sec_vaddr=sec_hdr[i].sh_addr; sec_size=sec_hdr[i].sh_size; break; } }
    if (!encrypt_sec || sec_size==0) { munmap(elf_file, st.st_size); close(fd); return false; }
    munmap(elf_file, st.st_size); close(fd);

    const long qnx_page_size = sysconf(_SC_PAGESIZE);
    uintptr_t sec_real_addr = g_base_addr + (sec_vaddr - load_vaddr);
    uintptr_t page_start = sec_real_addr & ~((uintptr_t)qnx_page_size -1);
    size_t page_len = ((sec_real_addr + sec_size - page_start) + qnx_page_size -1) & ~((uintptr_t)qnx_page_size -1);
    if (!is_address_accessible(sec_real_addr, sec_size)) return false;

    if (mprotect((void*)page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) !=0) {
        DecryptTool::simple_xor_crypt((uint8_t*)sec_real_addr, sec_size);
        flush_arm64_cache((uint8_t*)sec_real_addr, sec_size);
        return true;
    }
    DecryptTool::simple_xor_crypt((uint8_t*)sec_real_addr, sec_size);
    flush_arm64_cache((uint8_t*)sec_real_addr, sec_size);
    DSB_SYNC();
    ISB_SYNC();
    MEM_BAR();
    mprotect((void*)page_start, page_len, PROT_READ | PROT_EXEC);

    return true;
}
*/