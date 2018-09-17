#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "libcuckoofilter/include/cuckoo_filter.h"
#include "bpfmap.h"
#include "cuckoofilter.h"

struct bpf_cfilter {
    struct bpf_map map;
    cuckoo_filter_t *cfilter;
};

struct bpf_map *cfilter_map_alloc(union bpf_attr *attr){
    struct bpf_cfilter *cf;
    CUCKOO_FILTER_RETURN ret;

    // if (attr->map_flags & ~BPF_F_NO_PREALLOC) {
    //   /* reserved bits should not be used */
    //   errno = EINVAL;
    //   return NULL;
    // }

    cf = calloc(1, sizeof(struct bpf_cfilter));
    if(!cf){
        errno = ENOMEM;
        return NULL;
    }
    
    /* mandatory map attributes */
    cf->map.map_type = attr->map_type;
    cf->map.key_size = attr->key_size;
    cf->map.value_size = attr->value_size;
    cf->map.max_entries = attr->max_entries;
    cf->map.map_flags = attr->map_flags;

    /* TODO: Check attributes passed to function*/
    /* TODO: Allow configuration of filter, bucket and fingerprint sizes */

    ret = cuckoo_filter_new(&cf->cfilter,MAX_ELEMS,MAX_KICKS,(uint32_t) (time(NULL) & 0xffffffff));
    if( ret != CUCKOO_FILTER_OK ){
        free(cf);
        errno = EINVAL;
        return NULL;
    }

    return &cf->map;
}

void cfilter_map_free(struct bpf_map *map){

}

void *cfilter_map_lookup_elem(struct bpf_map *map, void *key){

}

int cfilter_map_get_next_key(struct bpf_map *map, void *key, void *next_key){}
int cfilter_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags){}
int cfilter_map_delete_elem(struct bpf_map *map, void *key){}