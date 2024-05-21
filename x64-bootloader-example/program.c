//#include "print.h"
//#include "memory.h"

//TODO: the vidchar get/set's are not working u skid
//TODO: printnl() does not scroll
//TODO: colors are messed up for a moment when scrolling

//void print_memmap();
//void test_prints();
//void test_memory();
//#include "stdint.h"
typedef unsigned long         size_t;
typedef unsigned int          uint32_t;
typedef unsigned long long    uint64_t;
typedef unsigned char         uint8_t;
typedef unsigned short int    uint16_t;
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

void printBits(uint64_t number,int y) {
    char bits[64];
    // 循环遍历64位无符号整数的每一位
    for (int i = 63; i >= 0; i--) {
        // 使用位操作提取每一位
        uint64_t bit = (number >> i) & 1;
        
        if (bit == 0) {
             bits[63-i]='0';
        }else{
             bits[63-i]='1';
        }
    }
    puts(0,y,BRIGHT,BLACK,bits);
}

void print_number(uint8_t x,uint8_t y,uint64_t  num){
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
uint64_t rdmsr(uint32_t msr)
{
	uint32_t a, d;

	__asm__ __volatile__("rdmsr" : "=a"(a), "=d"(d) : "c"(msr) : "memory");
	return a | ((uint64_t) d << 32);
}
void wrmsr(uint32_t msr, uint64_t value)
{
	uint32_t a = value;
	uint32_t d = value >> 32;
	__asm__ __volatile__("wrmsr" :: "a"(a), "d"(d), "c"(msr) : "memory");
}

void main() {
      clear(BLACK);
      uint64_t res1=rdmsr(0x199);
      puts(0,0,BRIGHT,BLACK,"hello!,run add!");
//      wrmsr(0x199,0x800);
//      uint64_t res2=rdmsr(0x199);
//      print_number(0,5,res1);
      printBits(res1,5);
      int a=0;
      while(1){
      	a+=1;
	a-=1;
      }
//      printBits(res2,10);
//    printstr("hello world\n");
}






