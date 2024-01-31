//#include "stdint.h"
typedef unsigned long         size_t;
typedef unsigned int          uint32_t;
typedef unsigned long long    uint64_t;
typedef unsigned char         uint8_t;
typedef unsigned short int    uint16_t;
//##########################################################
enum color {
    BLACK = 0,
    BRIGHT = 7
};

enum size {
    COLS = 80,
    ROWS = 25
};

uint16_t *const video = (uint16_t*)0xB8000;

void putc(uint8_t x, uint8_t y, enum color fg, enum color bg, char c) {
    video[y * COLS + x] = (bg << 12) | (fg << 8) | c;
}

void puts(uint8_t x, uint8_t y, enum color fg, enum color bg, const char *s) {
    for (; *s; s++, x++)
        putc(x, y, fg, bg, *s);
}

void print_number(uint8_t x,uint8_t y,size_t  num){
  char buffer[20];
  char res[20];
  int i=0;
  while(num>0){
    buffer[i++]='0'+num%10;
    num/=10;
  }
  buffer[i]='\0';
  int j,len=i;
  for(j=0;j<len;++j){
    res[j]=buffer[len-j-1];
  }
  res[j]='\0';
  puts(x,y,BRIGHT,BLACK,res);
}
void clear(enum color bg) {
    uint8_t x, y;
    for (y = 0; y < ROWS; y++)
        for (x = 0; x < COLS; x++)
            putc(x, y, bg, bg, ' ');
}
//##########################################################
static inline void fence() { __asm__ volatile ("mfence"); }

static inline void maccess(void *p){
  __asm__ volatile("movl (%0) ,%%eax" : : "c"(p):"eax");
}

static inline void flush(void *p){
  __asm__ volatile("clflush 0(%0)" : : "r"(p) : "eax");
}

uint64_t rdtsc(){
  uint64_t a=0;
  __asm__ volatile("mfence");
  __asm__ volatile("rdtsc":"=A"(a));
  __asm__ volatile("mfence");
  return a;
}

//###########################################################
int __attribute__((noreturn)) main() {
    size_t reload_time = 0;
    size_t flush_reload_time = 0;
    size_t i, count = 1000000;
    size_t dummy[16];
    size_t *ptr = dummy + 8;
    uint64_t start = 0, end = 0;
    
    maccess(ptr);
    for (i = 0; i < count; i++) {
        start = rdtsc();
        maccess(ptr);
        end = rdtsc();
        reload_time += (end - start);
    }
    for (i = 0; i < count; i++) {
        flush(ptr);
	start = rdtsc();
        maccess(ptr);
        end = rdtsc();
        flush_reload_time += (end - start);
    }
    reload_time /= count;
    flush_reload_time /= count; 
    size_t CACHE_MISS_THRESHOLD = (flush_reload_time + reload_time * 2) / 3;
    //printf("time1 is %ld,time2 is %ld,diff is %ld",reload_time,flush_reload_time,CACHE_MISS_THRESHOLD);
    clear(BLACK);
    print_number(0,0,reload_time);
    print_number(0,5,flush_reload_time);
    print_number(0,10,CACHE_MISS_THRESHOLD);
    while(1);
}
//######################################################################
/*int __attribute__((noreturn)) main() {
    size_t detect_data=444;
    size_t number_of_measurements=1000;
    size_t hit=measure_hits(&detect_data,number_of_measurements);
    //size_t miss=measure_misses(&detect_data,number_of_measurements);
    //size_t threshold=miss-hit;
    clear(BLACK);
    print_number(0,0,hit);
    //print_number(0,0,miss);
    //print_number(0,10,threshold);
    while (1);
}*/
