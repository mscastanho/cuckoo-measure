#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include "cuckoo_filter.h"

/*This should be configurable instead os static*/
#define SLOT_TIME 125000000ULL /* 1.25ms in ns*/
#define SEC_IN_NS 1000000000ULL

const char *basename = "filter";
const char* usage = "%s <number-of-filters> <path-to-files>\n";

typedef struct tracker_t {
    int last_seen;
    long sum;
    int count;
} tracker_t;

typedef struct ip_5tuple_t {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
} __attribute__((packed)) ip5tuple_t;

int main(int argc, char **argv){
    int nfilters = 0;
    int i;
    char filename[64];
    char *filesdir;
    cuckoo_filter_t *cf;
    tracker_t tracker = {0,0,0};
    ip5tuple_t flow = {0x0a00010a,0x0a00000a,0x0000,0x0000,0x01};
    CUCKOO_FILTER_RETURN ret;
    
    switch(argc){
        case 3:
            nfilters = atoi(argv[1]);
            if(!nfilters){
                printf("Failed to parse number of filters. Maybe 0?\n");
                exit(1);
            }

            /* Remove possible extra bar in path */
            int sz = strlen(argv[2]);
            if(argv[2][sz-1] == '/')
                argv[2][sz-1] = '\0';

            filesdir = argv[2];
            break;
        default:
            printf(usage,argv[0]);
            break;
    }

    for(i = 0 ; i < nfilters ; i++){
        sprintf(filename,"%s/%s_%d.cuckoo",filesdir,basename,i);
        // printf("Processing %s\n",filename);
        ret = cuckoo_filter_load(&cf,filename);

        if(ret != CUCKOO_FILTER_OK){
            printf("Failed to load filter from file\n");
            exit(1);
        }

        // cuckoo_filter_hexdump(cf);

        /* Do actual processing */
        if(cuckoo_filter_contains(cf,(void*) &flow,sizeof(flow)) == CUCKOO_FILTER_OK){
            printf("%d\n",i);
            tracker.sum += (i-tracker.last_seen)*SLOT_TIME;
            tracker.count++;
            tracker.last_seen = i;
        }

        cuckoo_filter_free(&cf);
    }

    printf("\n\n");

    if(tracker.count){
        printf("Count: %d\n",tracker.count);
        printf("Average inter arrival time: %f s\n",(((double)tracker.sum)/tracker.count)/SEC_IN_NS);
    }else{
        printf("No packets captured corresponding to that flow\n");
    }
    return 0;
}