#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <linux/netfilter.h>
#include <unistd.h>

#define BPF_NF_VIZ_OBJ "nf_viz.bpf.o"
#define BPF_PROGNAME "nf_viz"

#define RC_LOAD_BPF_FAILED          10
#define RC_FIND_PROG_FAILED         11
#define RC_ATTACH_NF_HOOK_FAILED    12

#define CLEANUP_LINK(link) \
    do { if (link) bpf_link__destroy(link); } while(0)

#define CLEANUP_OBJ(obj) \
    do { if (obj) bpf_object__close(obj); } while(0)

#define PRINT_EXIT_STATUS(err) \
    do { \
        if (err != 0) { \
            fprintf(stderr, "Error occurred: %d\n", err); \
        } else { \
            printf("Exiting cleanly.\n"); \
        } \
    } while(0)

static volatile bool exiting = false;

static void handle_signal(int sig) {
    exiting = true;
}

static struct bpf_link* attach_nf_hook(struct bpf_program *prog, 
                                        int hooknum, 
                                        const char *hook_name,
                                        int pf,
                                        int priority) {
    LIBBPF_OPTS(bpf_netfilter_opts, opts,
        .pf = pf,
        .hooknum = hooknum,
        .priority = priority,
    );

    struct bpf_link *link = bpf_program__attach_netfilter(prog, &opts);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach to %s hook\n", hook_name);
        return NULL;
    }
    printf("✓ Attached to %s hook\n", hook_name);
    return link;
}

int main(int argc, char *argv[]) {

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link_input = NULL, *link_output = NULL;
    int err = 0;

    libbpf_set_print(NULL);

    printf("Loading BPF program...\n");

    obj = bpf_object__open_file(BPF_NF_VIZ_OBJ, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", BPF_NF_VIZ_OBJ);
        return 1;
    }

    printf("BPF object file opened successfully\n");

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        err = RC_LOAD_BPF_FAILED;
        goto cleanup;
    }

    printf("BPF program loaded successfully\n");
    
    prog = bpf_object__find_program_by_name(obj, "nf_viz");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program: %s\n", BPF_PROGNAME);
        err = RC_FIND_PROG_FAILED;
        goto cleanup;
    }

    printf("BPF program found successfully\n");

    link_input = attach_nf_hook(prog, NF_INET_LOCAL_IN, "INPUT", NFPROTO_IPV4, -128);
    if (!link_input) {
        err = RC_ATTACH_NF_HOOK_FAILED;
        goto cleanup;
    }

    link_output = attach_nf_hook(prog, NF_INET_LOCAL_OUT, "OUTPUT", NFPROTO_IPV4, -128);
    if (!link_output) {
        err = RC_ATTACH_NF_HOOK_FAILED;
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\nPress Ctrl+C to exit...\n");

    while (!exiting) {
        sleep(1);
    }
    
cleanup:
    CLEANUP_LINK(link_input);
    CLEANUP_LINK(link_output);
    CLEANUP_OBJ(obj);

    PRINT_EXIT_STATUS(err);

    return err;
}