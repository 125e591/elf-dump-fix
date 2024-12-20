//
// Created by 麦耀 on 2018/6/30.
//
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int dumpMemory(int pid, uint64_t begin, uint64_t end, const char *outPath)
{
    char bufMaps[256] = "/proc/self/maps";
    char bufMemPath[256] = "/proc/self/mem";

    if (getuid() != 0)
    {
        printf("warning, program running as user: %d, please run this program by "
               "root!!!\n",
               getuid());
    }

#ifdef __aarch64__
    printf("trying to dump %d from %016lx to %016lx\n", pid, begin, end);
#else
    printf("trying to dump %d from %016llx to %016llx\n", pid, begin, end);
#endif

    if (pid != 0)
    {
        sprintf(bufMaps, "/proc/%d/maps", pid);
        sprintf(bufMemPath, "/proc/%d/mem", pid);
    }

    int fMem = open(bufMemPath, O_RDONLY);
    if (!fMem)
    {
        // open mem error, maybe permition deny.
        printf("open %s error, reason %s\n", bufMemPath, strerror(errno));
        return -1;
    }

    size_t sz = (size_t)(end - begin);
    unsigned char *mem = (unsigned char *)malloc(sz);
    if (!mem)
    {
        close(fMem);
        return -2;
    }
    memset(mem, 0, sz);

    off64_t r = lseek64(fMem, begin, SEEK_SET);
    if (r < 0)
    {
        printf("fseek error return %d\n", (int)r);
    }

#ifdef __aarch64__
    printf("trying to read %s fp:%d, off=%016lx, sz=%zu\n", bufMemPath, fMem,
           begin, sz);
#else
    printf("trying to read %s fp:%d, off=%016llx, sz=%d\n", bufMemPath, fMem,
           begin, sz);
#endif
    ssize_t szRead = read(fMem, mem, sz);
    if (szRead < 0)
    {
        const char *reason = strerror(errno);
        printf("read error return %d lasterr=[%s]", (int)szRead, reason);
        return -1;
    }

    printf("read return %d\n", (int)szRead);

    size_t left = sz - szRead;
    if (left > 0)
    {
        printf("dump %d left\n", (unsigned)left);
        for (size_t i = 0; i < left; ++i)
        {
            unsigned char byte = 0;
            ssize_t szB = read(fMem, &byte, 1);
            if (szB < 1)
            {
                lseek64(fMem, 1, SEEK_CUR);
                continue;
            }
            mem[szRead + i] = byte;
        }
    }
    int fOut = open(outPath, O_WRONLY | O_CREAT, 0666);
    if (fOut < 0)
    {
        printf("open %s error:%s\n", outPath, strerror(errno));
    }
    ssize_t szW = write(fOut, mem, sz);
    printf("%d writed\n", (unsigned)szW);
    close(fOut);

    free(mem);
    close(fMem);
    return 0;
}
