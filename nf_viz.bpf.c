#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4


char _license[] SEC("license") = "GPL";

SEC("netfilter")
int nf_viz(struct bpf_nf_ctx *ctx)
{
    return NF_ACCEPT; 
}