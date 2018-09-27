#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cuckoofilter.h"

#define MAX_RANGE   20000
#define MAX_INSERT  13000
#define MAX_RUNS    1

/* To compile run:
        gcc test_cuckoofilter.c -o testcf -L ./ -lbpfmap
*/
int main(){
    printf("Testing CuckooFilter\n");

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_CFILTER,
        .key_size = sizeof(int),
        .value_size = 0, // Unused
        .max_entries = MAX_RANGE,
        .map_flags = 0,
    };

    struct bpf_map *map = cfilter_map_alloc(&attr);

    if (map == NULL) {
        printf("Invalid parameters for creating the map\n");
        return EXIT_FAILURE;
    }

    printf("Map created successfully\n");

    int i,j,cnt,*res,r,ret;
    time_t t;
    int added[MAX_RANGE];

    srand((unsigned) time(&t));
    memset(added,0,sizeof(added));

    /* Insert MAX_INSERT random elements in the filter */
    cnt = 0;
    while(cnt < MAX_INSERT){
        r = rand() % MAX_RANGE;

        if(!added[r]){ 
            // printf("%d ",r);
            // fflush(stdout);
            ret = cfilter_map_update_elem(map,&r,0,0);
            if(ret != 0) printf("failed!\n");
            added[r] = 1;
            cnt += 1;
        }
    }

    /* Test false-positive rate*/
    int fpos, tpos, fneg, tneg, nlookups;

    for(i = 0 ; i < MAX_RUNS ; i++){
        fpos = tpos = fneg = tneg = nlookups = 0;

        for(j = 0 ; j < MAX_RANGE ; j++){
            res = cfilter_map_lookup_elem(map,&j);
            nlookups++;

            if(*res == 0){
                if(added[j])
                    tpos++;
                else
                    fpos++;
            }else{
                if(added[j])
                    fneg++;
                else
                    tneg++;
            }

            // if(added[j]){ 
            //     if(*res == 0) // True positive
            //         tpos += 1;
            //     else // False negative, should never happen
            //         fneg += 1; 
            // }else{
            //     if(*res == 0) // False positive
            //         fpos += 1; 
            //     else // True negative
            //         tneg += 1;
            // }
        }

        printf("================================================\n");
        printf("\t\t   Results\n");
        printf("================================================\n");
        printf("Type\t\t\tExpected\tObtained\n");
        printf("False negatives\t\t%d\t\t%d\n",0,fneg);
        printf("False positives\t\t%d\t\t%d\n",(int)(0.001*MAX_INSERT),fpos);
        printf("True negatives\t\t%d\t\t%d\n",MAX_RANGE-MAX_INSERT,tneg);
        printf("True positives\t\t%d\t\t%d\n\n",MAX_INSERT,tpos);
        printf("================================================\n");
    }
}