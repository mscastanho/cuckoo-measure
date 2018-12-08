#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/* This file has been partially exported from  
 * https://github.com/qmonnet/tbpoc-bpf/blob/master/bpf_api.h
 */

#include <stdint.h>

#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <asm/byteorder.h>

/** Misc macros. */

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#ifndef htons
# define htons(X)		__constant_htons((X))
#endif

#ifndef ntohs
# define ntohs(X)		__constant_ntohs((X))
#endif

#ifndef htonl
# define htonl(X)		__constant_htonl((X))
#endif

#ifndef ntohl
# define ntohl(X)		__constant_ntohl((X))
#endif

#ifndef __inline__
# define __inline__		__attribute__((always_inline))
#endif

/** Section helper macros. */

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_xdp_entry
# define __section_xdp_entry						\
	__section(ELF_SECTION_PROG)
#endif

#ifndef __section_cls_entry
# define __section_cls_entry						\
	__section(ELF_SECTION_CLASSIFIER)
#endif

#ifndef __section_act_entry
# define __section_act_entry						\
	__section(ELF_SECTION_ACTION)
#endif

#ifndef __section_lwt_entry
# define __section_lwt_entry						\
	__section(ELF_SECTION_PROG)
#endif

#ifndef __section_license
# define __section_license						\
	__section(ELF_SECTION_LICENSE)
#endif

#ifndef __section_maps
# define __section_maps							\
	__section(ELF_SECTION_MAPS)
#endif


/** LLVM built-ins, mem*() routines work for constant size */

#ifndef lock_xadd
# define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#ifndef memset
# define memset(s, c, n)	__builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
# define memcpy(d, s, n)	__builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
# define memmove(d, s, n)	__builtin_memmove((d), (s), (n))
#endif


#endif /* __BPF_HELPERS__ */