/* Ensure TASK_COMM_LEN is defined for BPF programs */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(kprobe_execve)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    /* Single concise log: uid, pid, comm */
    bpf_printk("execve: uid=%u pid=%u comm=%s\n", uid, pid, comm);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";