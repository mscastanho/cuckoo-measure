#ifndef __EBPF_CUCKOOFILTER_H
#define __EBPF_CUCKOOFILTER_H

#include "bpfmap.h"

#define MAX_KICKS 500

struct bpf_map *cfilter_map_alloc(union bpf_attr *attr);
void cfilter_map_free(struct bpf_map *map);
void *cfilter_map_lookup_elem(struct bpf_map *map, void *key);
int cfilter_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int cfilter_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int cfilter_map_delete_elem(struct bpf_map *map, void *key);
void cfilter_map_save(struct bpf_map *map);

#endif /* __EBPF_CUCKOOFILTER_H */