#define _CRT_SECURE_NO_WARNINGS
#include "fix.h"
#include "elf.h"

static const char *g_str = "..dynsym..dynstr..hash..gnu.hash..rel.dyn..rel.plt..plt.."
                           "text..ARM.exidx..fini_array..init_array..dynamic.."
                           "got..data..bss..shstrtab..rela.dyn..rela.plt\0";
static const char *g_strtabcontent =
    "\0.dynsym\0.dynstr\0.hash\0.gnu.hash\0.rel.dyn\0.rel.plt\0.plt\0.text\0.ARM.exidx\0."
    "fini_array\0.init_array\0.dynamic\0.got\0.data\0.bss\0.shstrtab\0.rela."
    "dyn\0.rela.plt\0";

static uint32_t _get_off_in_shstrtab(const char *name)
{
    return (uint32_t)(strstr(g_str, name) - g_str);
}

template <typename ElfHeaderType>
static void _get_elf_header(ElfHeaderType *pehdr, const char *buffer)
{
    int header_len = sizeof(ElfHeaderType);
    memcpy(pehdr, (void *)buffer, header_len);
}

static long _get_file_len(FILE *p)
{
    fseek(p, 0, SEEK_END);
    long fsize = ftell(p);
    rewind(p);
    return fsize;
}



template <typename Elf_Shdr_Type, typename Elf_Addr_Type, typename Elf_Rel_Type,
          bool isElf32>
static void _fix_relative_rebase(char *buffer, size_t bufSize,
                                 uint64_t imageBase, Elf_Shdr_Type *g_shdr)
{
    Elf_Addr_Type addr = g_shdr[RELDYN].sh_addr;
    size_t sz = g_shdr[RELDYN].sh_size;
    size_t n = sz / sizeof(Elf_Rel_Type);
    Elf_Rel_Type *rel = (Elf_Rel_Type *)(buffer + addr);
    const char *border = buffer + bufSize;
    for (size_t i = 0; i < n; ++i, ++rel)
    {
        int type = 0;
        if (isElf32)
        {
            type = ELF32_R_TYPE(rel->r_info);
        }
        else
        {
            type = ELF64_R_TYPE(rel->r_info);
        }
        if (type == R_ARM_RELATIVE || type == R_AARCH64_RELATIVE)
        {
            // 被Releative修正的地址需要减回装载地址才可以得出原本的Releative偏移
            Elf_Addr_Type off = rel->r_offset;
            unsigned *offIntBuf = (unsigned *)(buffer + off);
            if (border < (const char *)offIntBuf)
            {
                uint64_t tmp = off;
#ifdef __aarch64__
                printf("relocation off %lx invalid, out of border...\n", tmp);
#else
                printf("relocation off %llx invalid, out of border...\n", tmp);
#endif
                continue;
            }
            unsigned addrNow = *offIntBuf;
            addrNow -= imageBase;
            (*offIntBuf) = addrNow;
        }
    }
}

template <typename Elf_Phdr_Type, typename Elf_Addr_Type>
uint32_t _get_mem_flag(Elf_Phdr_Type *phdr, size_t phNum, size_t memAddr)
{
    for (int i = 0; i < phNum; i++)
    {
        Elf_Addr_Type begin = phdr[i].p_vaddr;
        Elf_Addr_Type end = begin + phdr[i].p_memsz;
        if (memAddr > begin && memAddr < end)
        {
            return phdr[i].p_flags;
        }
    }
    return 0;
}

template <typename Elf_Rel_Type, bool isElf32>
static void _fix_rel_bias(Elf_Rel_Type *relDyn, size_t relCount, size_t bias)
{
    for (int i = 0; i < relCount; i++)
    {
        unsigned type = 0;
        unsigned sym = 0;
        if (isElf32)
        {
            type = ELF32_R_TYPE(relDyn[i].r_info);
            sym = ELF32_R_SYM(relDyn[i].r_info);
        }
        else
        {
            type = ELF64_R_TYPE(relDyn[i].r_info);
            sym = ELF64_R_SYM(relDyn[i].r_info);
        }
        // 这两种重定位地址都是相对于loadAddr的，所以要修正
        if (type == R_ARM_JUMP_SLOT || type == R_ARM_RELATIVE ||
            type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_RELATIVE)
        {
            if (relDyn[i].r_offset > 0)
            {
                relDyn[i].r_offset -= bias;
            }
        }
    }
}

template <typename Elf_Sym_Type>
static void _fix_dynsym_bias(Elf_Sym_Type *dysym, size_t count, size_t bias)
{
    for (int i = 0; i < count; ++i)
    {
        if (dysym[i].st_value > 0)
        {
            dysym[i].st_value -= bias;
        }
    }
}
static uint64_t paddup(uint64_t input, uint64_t align)
{
    uint64_t pad = ~(align - 1);
    return input % align ? (input + align) & pad : input;
}

template <typename Elf_Ehdr_Type, typename Elf_Shdr_Type,
          typename Elf_Phdr_Type, typename Elf_Word_Type,
          typename Elf_Addr_Type, typename Elf_Sym_Type, typename Elf_Dyn_Type,
          typename Elf_Rel_Type, bool isElf32>
static void _regen_section_header(const Elf_Ehdr_Type *pehdr,
                                  char *buffer, size_t len,
                                  Elf_Shdr_Type g_shdr[SHDRS])
{
    Elf_Phdr_Type lastLoad = {0};
    Elf_Phdr_Type *phdr = (Elf_Phdr_Type *)(buffer + pehdr->e_phoff);
    int ph_num = pehdr->e_phnum;
    int dyn_size = 0, dyn_off = 0;

    // 所有相对于module base的地址都要减去这个地址
    // 第一个PT_LOAD段的虚拟地址（p_vaddr）被视为ELF文件的基地址
    size_t bias = 0;
    for (int i = 0; i < ph_num; i++)
    {
        if (phdr[i].p_type == PT_LOAD) // see linker get_elf_exec_load_bias
        {
            bias = phdr[i].p_vaddr;
            printf("[INFO] Founded First PT_LOAD Segment, bias(p_vaddr)=%lx\n", bias);
            break;
        }
    }

    Elf_Word_Type maxLoad = 0;
    for (int i = 0; i < ph_num; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
            maxLoad = phdr[i].p_vaddr + phdr[i].p_memsz - bias; // 取得最后一个load，获得整个so加载大小
    }
    printf("[INFO] maxLoad=%lx\n", maxLoad);

    if (maxLoad > len)
    {
        // 加载的范围大于整个dump下来的so，有问题，先警告
#ifdef __aarch64__
        printf("[WARNING] Load size [%u] is bigger than so size [%zu], dump may be incomplete!\n", maxLoad, len);
#else
        printf("[WARNING] Load size [%u] is bigger than so size [%u], dump may be incomplete!\n", maxLoad, len);
#endif
        // TODO:should we fix it???
    }

    int loadIndex = 0;
    int align = sizeof(Elf_Addr_Type);
    // backup all phdr info
    Elf_Phdr_Type *phdrBackup = (Elf_Phdr_Type *)malloc(ph_num * sizeof(Elf_Phdr_Type));
    memcpy(phdrBackup, phdr, ph_num * sizeof(Elf_Phdr_Type));
    int lastLoadIndex = -1;

    for (int i = 0; i < ph_num; i++)
    {
        phdr[i].p_vaddr -= bias;
        phdr[i].p_paddr = phdr[i].p_vaddr;
        phdr[i].p_offset = phdr[i].p_vaddr; // 段在文件中的偏移修正，因为从内存dump出来的文件偏移就是在内存的偏移
        phdr[i].p_filesz = phdr[i].p_memsz;
        Elf_Word_Type p_type = phdr[i].p_type;
        if (phdr[i].p_type == PT_LOAD)
        {
            loadIndex++;
            if (phdr[i].p_vaddr >= 0)
            {
                lastLoad = phdr[i]; // 一般来说.data就在最后一个PT_LOAD段
                lastLoadIndex = i;
            }
        }
        else if (p_type == PT_DYNAMIC)
        {
            printf("[INFO] Found PT_DYNAMIC Segment, p_vaddr=%lx\n", phdr[i].p_vaddr);
            // 动态表，动态表包括很多项，找到动态表位置可以恢复大部分结构,这个是恢复的突破口
            g_shdr[DYNAMIC].sh_name = _get_off_in_shstrtab(".dynamic");
            g_shdr[DYNAMIC].sh_type = SHT_DYNAMIC;
            g_shdr[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
            g_shdr[DYNAMIC].sh_addr = phdr[i].p_vaddr;
            g_shdr[DYNAMIC].sh_offset = phdr[i].p_vaddr;
            g_shdr[DYNAMIC].sh_size = phdr[i].p_memsz;
            g_shdr[DYNAMIC].sh_info = 0;
            g_shdr[DYNAMIC].sh_link = DYNSTR;
            if (isElf32)
            {
                g_shdr[DYNAMIC].sh_addralign = align;
                g_shdr[DYNAMIC].sh_entsize = 8;
            }
            else
            {
                g_shdr[DYNAMIC].sh_addralign = align;
                g_shdr[DYNAMIC].sh_entsize = 16;
            }
            dyn_size = phdr[i].p_memsz;
            dyn_off = phdr[i].p_vaddr;
        }

        else if (phdr[i].p_type == PT_LOPROC || phdr[i].p_type == PT_LOPROC + 1)
        {
            printf("[INFO] Found PT_LOPROC Segment, p_vaddr=%lx\n", phdr[i].p_vaddr);
            g_shdr[ARMEXIDX].sh_name = _get_off_in_shstrtab(".ARM.exidx");
            g_shdr[ARMEXIDX].sh_type = SHT_LOPROC;
            g_shdr[ARMEXIDX].sh_flags = SHF_ALLOC;
            g_shdr[ARMEXIDX].sh_addr = phdr[i].p_vaddr;
            g_shdr[ARMEXIDX].sh_offset = phdr[i].p_vaddr;
            g_shdr[ARMEXIDX].sh_size = phdr[i].p_memsz;
            g_shdr[ARMEXIDX].sh_link = 7;
            g_shdr[ARMEXIDX].sh_info = 0;
            g_shdr[ARMEXIDX].sh_addralign = align;
            g_shdr[ARMEXIDX].sh_entsize = 8;
        }
    }

    Elf_Dyn_Type *dyn = (Elf_Dyn_Type *)(buffer + dyn_off);
    int n = dyn_size / sizeof(Elf_Dyn_Type);
    printf("[INFO] .dynamic section entry num %d\n", n);

    Elf_Word_Type __global_offset_table = 0;
    int nDynSyms = 0;
    for (int i = 0; i < n; i++)
    {
        printf("[INFO] Processing .dynamic entry %d\n", i);
        int tag = dyn[i].d_tag;
        switch (tag)
        {
            case DT_SYMTAB:
                printf("[INFO] Found DT_SYMTAB, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[DYNSYM].sh_name = _get_off_in_shstrtab(".dynsym");
                g_shdr[DYNSYM].sh_type = SHT_DYNSYM;
                g_shdr[DYNSYM].sh_flags = SHF_ALLOC;
                g_shdr[DYNSYM].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[DYNSYM].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[DYNSYM].sh_link = 2;
                g_shdr[DYNSYM].sh_info = 1;
                g_shdr[DYNSYM].sh_addralign = align;
                break;
            case DT_SYMENT:
                printf("[INFO] Found DT_SYMENT, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                g_shdr[DYNSYM].sh_entsize = dyn[i].d_un.d_ptr;
                break;
            case DT_STRTAB:
                printf("[INFO] Found DT_STRTAB, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[DYNSTR].sh_name = _get_off_in_shstrtab(".dynstr");
                g_shdr[DYNSTR].sh_type = SHT_STRTAB;
                g_shdr[DYNSTR].sh_flags = SHF_ALLOC;
                g_shdr[DYNSTR].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[DYNSTR].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[DYNSTR].sh_addralign = 1;
                g_shdr[DYNSTR].sh_entsize = 0;
                break;
            case DT_STRSZ:
                printf("[INFO] Found DT_STRSZ, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[DYNSTR].sh_size = dyn[i].d_un.d_val;
                break;
            case DT_HASH:
            {
                printf("[INFO] Found DT_HASH, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                int nbucket = 0, nchain = 0;
                g_shdr[HASH].sh_name = _get_off_in_shstrtab(".hash");
                g_shdr[HASH].sh_type = SHT_HASH;
                g_shdr[HASH].sh_flags = SHF_ALLOC;
                g_shdr[HASH].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[HASH].sh_offset = dyn[i].d_un.d_ptr;
                memcpy(&nbucket, buffer + g_shdr[HASH].sh_offset, 4);
                memcpy(&nchain, buffer + g_shdr[HASH].sh_offset + 4, 4);
                g_shdr[HASH].sh_size = (nbucket + nchain + 2) * sizeof(int);
                g_shdr[HASH].sh_link = DYNSYM;
                g_shdr[HASH].sh_info = 0;
                g_shdr[HASH].sh_addralign = align;
                g_shdr[HASH].sh_entsize = 4;
                // linker源码，DT_HASH实际上是通过hashtable在加速动态符号的查找，所以hashtable的大小就是动态符号表的大小
                nDynSyms = nchain;
                break;
            }
            case DT_GNU_HASH:
            {
                printf("[INFO] Found DT_GNU_HASH, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[HASH].sh_name = _get_off_in_shstrtab(".gnu.hash");
                g_shdr[HASH].sh_type = SHT_GNU_HASH;
                g_shdr[HASH].sh_flags = SHF_ALLOC;
                g_shdr[HASH].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[HASH].sh_offset = dyn[i].d_un.d_ptr;
                
                uint32_t *gnu_hash_section = (uint32_t *)(buffer + g_shdr[HASH].sh_offset);
                uint32_t nbuckets = gnu_hash_section[0];
                uint32_t symoffset = gnu_hash_section[1];
                uint32_t bloom_size = gnu_hash_section[2];
                // uint32_t bloom_shift = gnu_hash_section[3]; // 这个用不到
                
                size_t bloom_filter_offset = sizeof(uint32_t) * 4;
                size_t bloom_filter_size = bloom_size * sizeof(Elf64_Addr); // 64 位系统
                
                size_t buckets_offset = bloom_filter_offset + bloom_filter_size;
                size_t buckets_size = nbuckets * 4;
                
                size_t chains_offset = buckets_offset + buckets_size;
                
                // Chains 数组的大小未知，需要通过遍历确定
                uint32_t *buckets = (uint32_t *)((uint8_t *)gnu_hash_section + buckets_offset);
                uint32_t *chains = (uint32_t *)((uint8_t *)gnu_hash_section + chains_offset);

                size_t max_chain_index = 0;

                // todo:统计hash_num时遇到hash重复算不算同一项？
                int hash_num = 0;
                for (uint32_t i = 0; i < nbuckets; i++) 
                {
                    uint32_t bucket = buckets[i];
                    if (bucket < symoffset) 
                        continue; // 非法的 bucket，跳过
                    if (bucket == 0) 
                        continue; // 空的 bucket，跳过
                    uint32_t chain_index = bucket - symoffset;
                    do 
                    {
                        printf("    curr hash %x -> symtab index=%d\n", chains[chain_index], chain_index + symoffset);
                        hash_num++;   
                    } while ((chains[chain_index++] &1) == 0);
                }

                size_t chains_size = (hash_num) * sizeof(uint32_t);

                size_t gnu_hash_size = 16       // 头部
                        + bloom_filter_size // Bloom 过滤器
                        + buckets_size      // Buckets 数组
                        + chains_size;      // Chains 数组
                
                printf("    Got hash_num %d\n", hash_num);

                g_shdr[HASH].sh_size = gnu_hash_size;
                g_shdr[HASH].sh_link = DYNSYM;
                g_shdr[HASH].sh_info = 0;
                g_shdr[HASH].sh_addralign = align;
                g_shdr[HASH].sh_entsize = 0;

                nDynSyms = hash_num + symoffset;
                break;
            }
            case DT_REL:
            case DT_RELA:
            {
                printf("[INFO] Found DT_REL or DT_RELA, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[RELDYN].sh_flags = SHF_ALLOC;
                g_shdr[RELDYN].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[RELDYN].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[RELDYN].sh_link = DYNSYM;
                g_shdr[RELDYN].sh_info = 0;
                g_shdr[RELDYN].sh_addralign = align;
                if (tag == DT_REL)
                {
                    g_shdr[RELDYN].sh_name = _get_off_in_shstrtab(".rel.dyn");
                    g_shdr[RELDYN].sh_type = SHT_REL;
                }
                else
                {
                    g_shdr[RELDYN].sh_name = _get_off_in_shstrtab(".rela.dyn");
                    g_shdr[RELDYN].sh_type = SHT_RELA;
                }
                break;
            }
            case DT_RELSZ:
            case DT_RELASZ:
                printf("[INFO] Found DT_RELSZ or DT_RELASZ, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[RELDYN].sh_size = dyn[i].d_un.d_val;
                break;
            case DT_RELENT:
            case DT_RELAENT:
                printf("[INFO] Found DT_RELENT or DT_RELAENT, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[RELPLT].sh_entsize = dyn[i].d_un.d_val;
                g_shdr[RELDYN].sh_entsize = dyn[i].d_un.d_val;
                break;
            case DT_JMPREL:
                printf("[INFO] Found DT_JMPREL, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[RELPLT].sh_flags = SHF_ALLOC;
                g_shdr[RELPLT].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[RELPLT].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[RELPLT].sh_link = DYNSYM;
                g_shdr[RELPLT].sh_info = PLT;
                g_shdr[RELPLT].sh_addralign = align;
                if (isElf32)
                {
                    g_shdr[RELPLT].sh_name = _get_off_in_shstrtab(".rel.plt");
                    g_shdr[RELPLT].sh_type = SHT_REL;
                }
                else
                {
                    g_shdr[RELPLT].sh_name = _get_off_in_shstrtab(".rela.plt");
                    g_shdr[RELPLT].sh_type = SHT_RELA;
                }
                break;
            case DT_PLTRELSZ:
                printf("[INFO] Found DT_PLTRELSZ, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[RELPLT].sh_size = dyn[i].d_un.d_val;
                break;
            case DT_FINI_ARRAY:
                printf("[INFO] Found DT_FINI_ARRAY, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[FINIARRAY].sh_name = _get_off_in_shstrtab(".fini_array");
                g_shdr[FINIARRAY].sh_type = 15;
                g_shdr[FINIARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
                g_shdr[FINIARRAY].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[FINIARRAY].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[FINIARRAY].sh_addralign = align;
                g_shdr[FINIARRAY].sh_entsize = 0;
                break;
            case DT_FINI_ARRAYSZ:
                printf("[INFO] Found DT_FINI_ARRAYSZ, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[FINIARRAY].sh_size = dyn[i].d_un.d_val;
                break;
            case DT_INIT_ARRAY:// 函数地址也需要减掉base
                printf("[INFO] Found DT_INIT_ARRAY, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                g_shdr[INITARRAY].sh_name = _get_off_in_shstrtab(".init_array");
                g_shdr[INITARRAY].sh_type = 14;
                g_shdr[INITARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
                g_shdr[INITARRAY].sh_offset = dyn[i].d_un.d_ptr;
                g_shdr[INITARRAY].sh_addr = dyn[i].d_un.d_ptr;
                g_shdr[INITARRAY].sh_addralign = align;
                g_shdr[INITARRAY].sh_entsize = 0;
                break;
            case DT_INIT_ARRAYSZ:
                printf("[INFO] Found DT_INIT_ARRAYSZ, d_ptr=%lx\n", dyn[i].d_un.d_val);
                g_shdr[INITARRAY].sh_size = dyn[i].d_un.d_val;
                break;
            case DT_PLTGOT:
                printf("[INFO] Found DT_PLTGOT, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                dyn[i].d_un.d_ptr -= bias;
                __global_offset_table = dyn[i].d_un.d_ptr;
                g_shdr[GOT].sh_name = _get_off_in_shstrtab(".got");
                g_shdr[GOT].sh_type = SHT_PROGBITS;
                g_shdr[GOT].sh_flags = SHF_WRITE | SHF_ALLOC;
                // TODO:这里基于假设.got一定在.dynamic段之后，并不可靠，王者荣耀libGameCore.so就是例外
                // g_shdr[GOT].sh_addr = g_shdr[DYNAMIC].sh_addr + g_shdr[DYNAMIC].sh_size;
                // g_shdr[GOT].sh_offset = g_shdr[GOT].sh_addr;
                // 这里优化用我的优化，找到rel.dyn里第一个R_AARCH64_GLOB_DAT重定位项，然后取其地址作为.got开始的地址，这个部分要靠后一些完成
                g_shdr[GOT].sh_addralign = align;
                break;
            case DT_INIT:
            {
                printf("[INFO] Found DT_INIT, d_ptr=%lx\n", dyn[i].d_un.d_ptr);
                // 找到init段代码，但是无法知道有多长，只好做一个警告，提醒使用者init段存在，脱壳代码可能存在这里
                uint64_t tmp = dyn[i].d_un.d_ptr;
    #ifdef __aarch64__
                printf("[WARNING] .init exists at 0x%016lx\n", tmp);
    #else
                printf("[WARNING] .init exists at 0x%016llx\n", tmp);
    #endif
                break;
            }
            case DT_TEXTREL:
                // 地址相关的so，警告，暂时不做处理
                printf("[WARNING] DT_TEXTREL found, so is address dependent.\n");
                break;
            }
    }

    size_t relpltCount = g_shdr[RELPLT].sh_size / g_shdr[RELPLT].sh_entsize;
    size_t reldynCount = g_shdr[RELDYN].sh_size / g_shdr[RELDYN].sh_entsize;
    printf("[INFO] .rel.plt Count=%ld\n", relpltCount);
    printf("[INFO] .rel.dyn Count=%ld\n", reldynCount);

    Elf_Rel_Type *relDyn = (Elf_Rel_Type *)(buffer + g_shdr[RELDYN].sh_addr);
    _fix_rel_bias<Elf_Rel_Type, isElf32>(relDyn, reldynCount, bias);

    Elf_Rel_Type *relPlt = (Elf_Rel_Type *)(buffer + g_shdr[RELPLT].sh_addr);
    _fix_rel_bias<Elf_Rel_Type, isElf32>(relPlt, relpltCount, bias);

    // calculate .got entry num
    // 通过统计 .rela.plt 中的 R_xx_JUMP_SLOT 重定位项数，统计 .rela.dyn 中的 R_xx_GLOB_DAT 重定位项数，然后加上3个保留项，你可以得到GOT中的总项数。
    int gotEntryCount = 0;
    Elf_Word_Type firstOfGOT = 0xffffffff;
    Elf_Word_Type szGotEntry = 4;
    if (!isElf32)
        szGotEntry = 8;
    int foundedIndyn = 0;

    // 先是.rel.dyn
    for (size_t i = 0; i < reldynCount; i++) 
    {
        if (isElf32)
        {
            Elf32_Word type = ELF32_R_TYPE(relDyn[i].r_info);
            Elf32_Word sym = ELF32_R_SYM(relDyn[i].r_info);
            if (type == R_ARM_GLOB_DAT) 
            {
                if (relDyn[i].r_offset < firstOfGOT)
                    firstOfGOT = relDyn[i].r_offset;
                gotEntryCount++;
                printf("[INFO] Found R_ARM_GLOB_DAT sym %d\n", sym);
            }
        }
        else
        {
            Elf64_Word type = ELF64_R_TYPE(relDyn[i].r_info);
            Elf64_Word sym = ELF64_R_SYM(relDyn[i].r_info);
            if (type == R_AARCH64_GLOB_DAT) 
            {
                if (relDyn[i].r_offset < firstOfGOT)
                    firstOfGOT = relDyn[i].r_offset;
                gotEntryCount++;
                printf("[INFO] Found R_AARCH64_GLOB_DAT sym %d\n", sym);
            }
        }
    }
    if (firstOfGOT != 0xffffffff)
    {
        foundedIndyn = 1;
    }

    for (size_t i = 0; i < relpltCount; i++) 
    {
        if (isElf32)
        {
            Elf32_Word type = ELF32_R_TYPE(relPlt[i].r_info);
            Elf32_Word sym = ELF32_R_SYM(relPlt[i].r_info);
            if (type == R_ARM_JUMP_SLOT) 
            {
                if (!foundedIndyn && relPlt[i].r_offset < firstOfGOT)
                {
                    firstOfGOT = relPlt[i].r_offset;
                    
                }
                gotEntryCount++;
                printf("[INFO] Found R_ARM_JUMP_SLOT sym %d\n", sym);
            }
        }
        else
        {
            Elf64_Word type = ELF64_R_TYPE(relPlt[i].r_info);
            Elf64_Word sym = ELF64_R_SYM(relPlt[i].r_info);
            if (type == R_AARCH64_JUMP_SLOT) 
            {
                if (!foundedIndyn && relPlt[i].r_offset < firstOfGOT)
                {
                    firstOfGOT = relPlt[i].r_offset;
                    firstOfGOT -= szGotEntry * 3;
                }
                gotEntryCount++;
                printf("[INFO] Found R_AARCH64_JUMP_SLOT sym %d\n", sym);
            }
        }
    }
    if (!foundedIndyn)
    {
        firstOfGOT -= szGotEntry * 3; // 如果是在rel.plt找到的，则减去3个保留项
    }

    printf("[INFO] Found GOT start position is %lx\n", firstOfGOT);

    if (firstOfGOT != 0xffffffff)
    {
        g_shdr[GOT].sh_addr = g_shdr[GOT].sh_offset = firstOfGOT;
    }
    else // cnm
    {
        g_shdr[GOT].sh_addr = g_shdr[DYNAMIC].sh_addr + g_shdr[DYNAMIC].sh_size;
        g_shdr[GOT].sh_offset = g_shdr[GOT].sh_addr;
    }

    gotEntryCount += 3;
    printf("[INFO] Got gotEntryCount=%d\n", gotEntryCount);

    if (__global_offset_table)
    {
        printf("[INFO] Start building .GOT\n");
        Elf_Word_Type gotBase = g_shdr[GOT].sh_addr;
        Elf_Word_Type gotEnd =  __global_offset_table + szGotEntry * gotEntryCount;

        //.got的结尾就是.data的开始，根据经验，data的地址总是与0x1000对齐。以此来修正地址
        Elf_Word_Type gotEndTry = gotEnd & ~0x0FFF;
        if (__global_offset_table < gotEndTry)
        {
            gotEnd = gotEndTry;
        }
        printf("[INFO] gotBase = %x gotEnd = %x\n", gotBase, gotEnd);

        // .data是有可能不存在的！当然这也是极少数情况。不存在就直接不填充这个section
        if (loadIndex == 3)
        {
            printf("[INFO] loadIndex is 3, guess it is .data\n");
            g_shdr[DATA].sh_name = _get_off_in_shstrtab(".data");
            g_shdr[DATA].sh_type = SHT_PROGBITS;
            g_shdr[DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
            g_shdr[DATA].sh_addr = lastLoad.p_vaddr; //paddup(gotEnd, 0x1000);
            g_shdr[DATA].sh_offset = g_shdr[DATA].sh_addr;
            g_shdr[DATA].sh_size = phdrBackup[lastLoadIndex].p_filesz; // 这里要用修复前的p_filesz
            g_shdr[DATA].sh_addralign = align;
            printf("[INFO] Data start %lx size %d\n", g_shdr[DATA].sh_addr, g_shdr[DATA].sh_size);

            printf("[INFO] Fix data size to original filesz %d\n", phdrBackup[lastLoadIndex].p_filesz);
            phdr[lastLoadIndex].p_filesz = phdrBackup[lastLoadIndex].p_filesz;

            // 这里还要修.bss，覆盖成0，主要是区分一下是不是data
            g_shdr[BSS].sh_name = _get_off_in_shstrtab(".bss");
            g_shdr[BSS].sh_type = SHT_NOBITS;
            g_shdr[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
            g_shdr[BSS].sh_addr = lastLoad.p_vaddr + phdrBackup[lastLoadIndex].p_filesz;
            g_shdr[BSS].sh_offset = g_shdr[BSS].sh_addr;
            g_shdr[BSS].sh_size = lastLoad.p_memsz - phdrBackup[lastLoadIndex].p_filesz;
            g_shdr[BSS].sh_addralign = align;
            
            printf("[INFO] BSS start %lx size %d\n", g_shdr[BSS].sh_addr, g_shdr[BSS].sh_size);
        }
        else
        {
            printf("[WARNING] warning loadIndex is not 3, don't fix .data\n");
        }
        
        if (gotEnd > gotBase)
        {
            g_shdr[GOT].sh_size = gotEnd - gotBase;
        }
        else
        {
            //.got紧接着.dynamic的假设不成立
            // 虽然算不准got段的真正的地址，但是可以用__global_offset_table的地址充当.got段的地址，__global_offset_table以上的地址全部为
            // 数据段的修正地址，对分析关系不大。
            printf("[WARNING] .got is not after .dynamic, using __global_offset_table as .got base\n");
            g_shdr[GOT].sh_addr = g_shdr[GOT].sh_offset = __global_offset_table;
            g_shdr[GOT].sh_size = gotEnd - __global_offset_table;
        }
    }
    const char *symbase = buffer + g_shdr[DYNSYM].sh_addr;

    // 如果之前没有HASH表，无法确定符号表大小，只能靠猜测来获取符号表大小
    if (nDynSyms == 0)
    {
        printf("[WARNING] DT_HASH not found,try to detect dynsym size...\n");
        const char *strbase = buffer + g_shdr[DYNSTR].sh_addr;
        const char *strend = strbase + g_shdr[DYNSTR].sh_size;
        unsigned symCount = 0;
        Elf_Sym_Type *sym = (Elf_Sym_Type *)symbase;
        while (1)
        {
            // 符号在符号表里面的偏移，不用考虑文件与内存加载之间bias
            size_t off = sym->st_name;
            const char *symName = strbase + off;
            size_t symOff = sym->st_value;
            // printf("symName=%p strbase=%p strend=%p\n", symName, strbase, strend);
            if ((size_t)symName < (size_t)strbase ||
                (size_t)symName > (size_t)strend)
            {
                // 动态表的符号偏移不在动态字符串表之内，说明非法，已经没有合法的动态符号了。
                //  printf("break 1 symName=%s strbase");
                break;
            }
            symCount++;
            sym++;
        }
        nDynSyms = symCount;
    }

    printf("[INFO] Now we guess nDynSyms is %d\n", nDynSyms);

    // 处理一下特殊情况，对.dynsym的符号类型进行修正
    Elf_Sym_Type *sym = (Elf_Sym_Type *)symbase;
    for (int i = 0; i < nDynSyms; i++)
    {
        // 发现某些so如饿了么libdeadpool通过将符号表里面的type设置成错误的值，从而使ida分析出错
        // 这里如果发现值是非法的，强制指定为FUNC类型，让ida分析
        unsigned char info = sym->st_info;
        unsigned int type = ELF_ST_TYPE(info);
        if (type > STT_FILE) // not a valid symbol type, fix it!
        {
            unsigned char c = (unsigned char)(info & 0xF0);
            unsigned newType = STT_OBJECT;
            if (sym->st_value == 0)
            {
                printf("[INFO] Sym %d st_value==0 is external symbol\n", i);
                // 当符号值为零说明是个外部符号，此时类型判断不准，给一个通常的就可
                newType = STT_FUNC;
            }
            else
            {
                // 内存符号可以通过内存读写属性来判断是什么符号
                uint32_t flag = _get_mem_flag<Elf_Phdr_Type, Elf_Addr_Type>(
                    phdr, ph_num, sym->st_value);
                if (flag & PF_X)
                {
                    printf("[INFO] Sym %d has execute permission, guessing it is a function\n", i);
                    newType = STT_FUNC;
                }
            }
            sym->st_info = (unsigned char)(c | newType);
        }
        sym++;
    }

    
    g_shdr[DYNSYM].sh_size = nDynSyms * sizeof(Elf_Sym_Type);

    // 处理.plt段，其实可有可无
    unsigned pltAlign = 4;
    if (!isElf32)
    {
        pltAlign = 16;
    }
    g_shdr[PLT].sh_name = _get_off_in_shstrtab(".plt");
    g_shdr[PLT].sh_type = SHT_PROGBITS;
    g_shdr[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    Elf_Addr_Type addr = g_shdr[RELPLT].sh_addr + g_shdr[RELPLT].sh_size;

    g_shdr[PLT].sh_addr = paddup(addr, pltAlign);
    g_shdr[PLT].sh_offset = g_shdr[PLT].sh_addr;
    // 20=padding 12=每个plt的指令大小
    Elf_Word_Type szPltEntry = 12;
    if (!isElf32)
    {
        szPltEntry = 16;
    }
    g_shdr[PLT].sh_size = paddup(20 + szPltEntry * relpltCount, pltAlign);
    g_shdr[PLT].sh_addralign = pltAlign;

    if (g_shdr[ARMEXIDX].sh_addr != 0)
    {
        // text段的确定依赖ARMEXIDX的决定，ARMEXIDX没有的话，干脆不要text段了，因为text对ida分析没什么作用，ida对第一个LOAD的分析已经涵盖了text段的作用
        g_shdr[TEXT].sh_name = _get_off_in_shstrtab(".text");
        g_shdr[TEXT].sh_type = SHT_PROGBITS;
        g_shdr[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        g_shdr[TEXT].sh_addr = g_shdr[PLT].sh_addr + g_shdr[PLT].sh_size;
        g_shdr[TEXT].sh_offset = g_shdr[TEXT].sh_addr;
        g_shdr[TEXT].sh_size = g_shdr[ARMEXIDX].sh_addr - g_shdr[TEXT].sh_addr;
    }

    g_shdr[STRTAB].sh_name = _get_off_in_shstrtab(".shstrtab");
    g_shdr[STRTAB].sh_type = SHT_STRTAB;
    g_shdr[STRTAB].sh_flags = SHT_NULL;
    g_shdr[STRTAB].sh_addr = 0; // 写文件的时候修正
    g_shdr[STRTAB].sh_size = (uint32_t)strlen(g_str) + 1;
    g_shdr[STRTAB].sh_addralign = 1;

    Elf_Sym_Type *dynsym = (Elf_Sym_Type *)(buffer + g_shdr[DYNSYM].sh_addr);
    _fix_dynsym_bias<Elf_Sym_Type>(dynsym, nDynSyms, bias);

}

static bool is_elf32(const char *soPath)
{
    FILE *f = fopen(soPath, "rb");
    fseek(f, 0x4, SEEK_SET);
    char buf[10] = {0};
    fread(buf, 1, 1, f);
    fclose(f);
    return buf[0] == 0x1;
}

template <typename Elf_Ehdr_Type, typename Elf_Shdr_Type,
          typename Elf_Phdr_Type, typename Elf_Word_Type,
          typename Elf_Addr_Type, typename Elf_Sym_Type, typename Elf_Dyn_Type,
          typename Elf_Rel_Type, bool isElf32>
static void _fix_elf(char *buffer, size_t flen, FILE *fw, uint64_t ptrbase)
{
    Elf_Shdr_Type g_shdr[SHDRS] = {0};
    Elf_Ehdr_Type ehdr = {0};
    _get_elf_header<Elf_Ehdr_Type>(&ehdr, buffer);

    _regen_section_header<Elf_Ehdr_Type, Elf_Shdr_Type, Elf_Phdr_Type,
                          Elf_Word_Type, Elf_Addr_Type, Elf_Sym_Type,
                          Elf_Dyn_Type, Elf_Rel_Type, isElf32>(&ehdr, buffer,
                                                               flen, g_shdr);

    _fix_relative_rebase<Elf_Shdr_Type, Elf_Addr_Type, Elf_Rel_Type, isElf32>(
        buffer, flen, ptrbase, g_shdr);

    size_t shstrtabsz = strlen(g_str) + 1;
    ehdr.e_entry = ptrbase;
    ehdr.e_shnum = SHDRS;
    // 倒数第一个为段名字符串段
    ehdr.e_shstrndx = SHDRS - 1;
    ehdr.e_shentsize = sizeof(Elf_Shdr_Type);

    // 段表头紧接住段表最后一个成员--字符串段之后
    ehdr.e_shoff = (Elf_Addr_Type)(flen + shstrtabsz);

    // 就在原来文件最后加上段名字符串段
    g_shdr[STRTAB].sh_offset = flen;
    size_t szEhdr = sizeof(Elf_Ehdr_Type);
    // Elf头
    fwrite(&ehdr, szEhdr, 1, fw);
    // 除了Elf头之外的原文件内容
    fwrite(buffer + szEhdr, flen - szEhdr, 1, fw);
    // 补上段名字符串段
    fwrite(g_strtabcontent, shstrtabsz, 1, fw);
    // 补上段表头
    fwrite(&g_shdr, sizeof(g_shdr), 1, fw);
}


int fix_so(const char *openPath, const char *outPutPath, uint64_t ptrbase)
{
    FILE *fr = NULL, *fw = NULL;

    fr = fopen(openPath, "rb");

    if (fr == NULL)
    {
        printf("Open failed: \n");
        return -3;
    }
    bool isElf32 = is_elf32(openPath);
    printf("isElf32=%d\n", isElf32);
    char head[4] = {0};
    fread(head, 1, 4, fr);
    if (head[0] != 0x7f || head[1] != 'E' || head[2] != 'L' || head[3] != 'F')
    {
        printf("error header is not .ELF!!!\n");
        fclose(fr);
        return -5;
    }
    fseek(fr, 0, SEEK_SET);

    size_t flen = _get_file_len(fr);

    char *buffer = (char *)malloc(flen);
    if (buffer == NULL)
    {
        printf("Malloc error\n");
        fclose(fr);
        return -1;
    }

    unsigned long result = fread(buffer, 1, flen, fr);
    if (result != flen)
    {
        printf("Reading %s error\n", openPath);
        fclose(fr);
        free(buffer);
        return -2;
    }
    fw = fopen(outPutPath, "wb");
    if (fw == NULL)
    {
        printf("Open failed: %s\n", outPutPath);
        fclose(fr);
        free(buffer);
        return -4;
    }

    if (isElf32)
    {
        _fix_elf<Elf32_Ehdr, Elf32_Shdr, Elf32_Phdr, Elf32_Word, Elf32_Addr,
                 Elf32_Sym, Elf32_Dyn, Elf32_Rel, true>(buffer, flen, fw, ptrbase);
    }
    else
    {
        _fix_elf<Elf64_Ehdr, Elf64_Shdr, Elf64_Phdr, Elf64_Word, Elf64_Addr,
                 Elf64_Sym, Elf64_Dyn, Elf64_Rela, false>(buffer, flen, fw,
                                                          ptrbase);
    }

    printf("[INFO] Fixed so has been written to %s\n", outPutPath);
    if (fw != NULL)
        fclose(fw);
    if (fr != NULL)
        fclose(fr);
    free(buffer);
    return 0;
}
