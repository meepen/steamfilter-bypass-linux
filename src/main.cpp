
#include <string.h>
#include <stdio.h>
#include <fstream>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

struct memory
{
  unsigned long start;
  unsigned long end;
  unsigned long len;
};

bool GetMemory(memory *mem, const char *pid, const char *name, int skip)
{

    char path[512];

    snprintf(path, 512, "/proc/%s/maps", pid);

    std::ifstream f;
    f.open(path);
    if(!f.is_open()) return false;

    while(!f.eof())
    {
      char line[2048];

      f.getline(line, 2048);

      size_t len = strlen(line);
      if(len < strlen(name)) continue;

      if(strcmp(((const char *)line) + len - strlen(name), name) == 0 && skip-- == 0)
      {

        sscanf(line, "%08lx-%08lx", &mem->start, &mem->end);
        mem->len - mem->end - mem->start;
        f.close();
        return true;

      }

    }
    f.close();

    return false;

}


bool readmem(FILE *f, long address, void *buf, size_t size)
{
    if(!f) return false;
    long before = ftell(f);
    
    fseek(f, address, SEEK_SET);
    
    bool ret = size == fread(buf, size, 1, f);
    
    fseek(f, before, SEEK_SET);
    
    return ret;
}

bool writemem(FILE *f, long address, void *buf, size_t size)
{
    if(!f) return false;
    
    long before = ftell(f);
    
    fseek(f, address, SEEK_SET);
    
    bool ret = size == fwrite(buf, size, 1, f);
    
    fseek(f, before, SEEK_SET);
    
    return ret;
}

int main(int argc, char *argv[])
{


  if(argc != 2) { printf("Not correct argumento\n"); return 1; }
  const char *sig = "\x55"
  "\x57"
  "\x56"
  "\x53"
  "\x83\xEC?"
  "\xE8????"
  "\x81?????"
  "\x8B???"
  "\x8D?????"
  "\x8D?????"
  "\xEB?"
  "\x83\xC6\x04";

  pid_t pid;

  sscanf(argv[1], "%d", &pid);
  
  
  char temp[256];
  snprintf(temp, 256, "/proc/%i/mem", pid);
  FILE *f = fopen(temp, "rb+");

  char mem[1];

  const char *now = sig;

  memory mems;
  int skip = 0;

  while(GetMemory(&mems, argv[1], "friendsui.so",skip))
  {

    printf("%08lX - %08lX\n", mems.start, mems.end);

    for(long i = mems.start; i < mems.end; i++)
    {

      if(!readmem(f, i, (void *)mem, 1))
      {
        printf("END!! :(: %08lX\n", i);
        break;
      }

      if(*now == '?' || *now == mem[0])
      {
        now++;
        if(!*now) // end of sig
        {
          long write = i - strlen(sig) + 1;

          if(!writemem(f, write, (void *)"\xB8\x01\x00\x00\x00\xC3", 6))
          {
            printf("NO WRITE!!\n");
          }
          printf("Found!!! %08lX\n", i);
          break;
        }
      }
      else
        now = sig;
    }
    skip++;
  }
  fclose(f);
  printf("Done!\n");


  return 0;
}
