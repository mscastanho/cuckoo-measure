#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include "cuckoo_filter.h"

/*This should be configurable instead of static*/

const char* usage = "%s <number-of-filters> <window-length-ms> <number-of-slots> <path-to-files>\n";

typedef struct tracker_t {
    int last_seen;
    double sum;
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
    int nfilters = 0, nslots = 0;
    int i;
    char filename[64];
    char *filesdir;
    double window_time;
    double slot_time;
    cuckoo_filter_t *cf;
    tracker_t tracker = {0,0,0};
    ip5tuple_t flow = {0x0a000001,0x0a000002,0x0000,0x0000,0x11};
    CUCKOO_FILTER_RETURN ret;
    
    switch(argc){
        case 5:
            nfilters = atoi(argv[1]);
            if(!nfilters){
                printf("Failed to parse number of filters. Maybe 0?\n");
                exit(1);
            }

            window_time = atof(argv[2]);
            if(!window_time){
                printf("Failed to parse window length. Maybe 0?\n");
                exit(1);
            }

            nslots = atoi(argv[3]);
            if(!nslots){
                printf("Failed to parse number of slots. Maybe 0?\n");
                exit(1);
            }

            /* Remove possible extra bar in path */
            int sz = strlen(argv[4]);
            if(argv[4][sz-1] == '/')
                argv[4][sz-1] = '\0';

            filesdir = argv[4];
            break;
        default:
            printf(usage,argv[0]);
            exit(1);
            break;
    }

    slot_time = window_time/nslots; // in ms
    printf("Window:\t%f ms\n",window_time);
    printf("Slot:\t%f ms\n",slot_time);

    for(i = 0 ; i < nfilters ; i++){
        sprintf(filename,"%s/%d.ck",filesdir,i);
        //printf("Processing %s\n",filename);
        ret = cuckoo_filter_load(&cf,filename);
        //cuckoo_filter_hexdump(cf);

        if(ret != CUCKOO_FILTER_OK){
            printf("Failed to load filter from file\n");
            exit(1);
        }

        // cuckoo_filter_hexdump(cf);

        /* Do actual processing */
        if(cuckoo_filter_contains(cf,(void*) &flow,sizeof(flow)) == CUCKOO_FILTER_OK){
            //printf("%d\n",i);

            // Increasing sum only makes sense if we have seen it at least twice
            if(tracker.count > 0)
                tracker.sum += (i-tracker.last_seen)*slot_time;
            
            tracker.count++;
            tracker.last_seen = i;
            printf("Seen on slot %d\n",i);
        }

        cuckoo_filter_free(&cf);
    }

    printf("\n\n");

    if(tracker.count){
        printf("Count: %d\n",tracker.count);
        printf("Sum: %f\n",tracker.sum);
        if(tracker.count == 1)
            printf("Not enough data to calculate inter arrival time\n");
        else   
            printf("Average inter arrival time: %f ms\n",tracker.sum/tracker.count);
    }else{
        printf("No packets captured corresponding to that flow\n");
    }
    return 0;
}