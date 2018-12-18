all: process

OUTNAME=process
process:
	gcc -I ../bpfmap/libcuckoofilter/include/ ../bpfmap/libcuckoofilter/src/cuckoo_filter.c process-cuckoo.c -o $(OUTNAME)

clean:
	rm $(OUTNAME)