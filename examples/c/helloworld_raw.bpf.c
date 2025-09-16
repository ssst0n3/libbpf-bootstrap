// helloworld-raw.bpf.c 

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 在 x86_64 架构下，execve 的系统调用号是 59
// 为了可移植性，最好包含 unistd.h 头文件来获取 __NR_execve 宏
// 这通常由编译器或构建系统在编译时通过 -I 选项提供内核头文件路径
#if defined(__x86_64__)
#define __NR_execve 59
#elif defined(__aarch64__)
#define __NR_execve 221
#else
#warning "Architecture not supported, using a fallback syscall number for execve."
#define __NR_execve 59 // 默认为 x86_64
#endif


SEC("raw_tracepoint/sys_enter")
int bpf_prog(struct bpf_raw_tracepoint_args *ctx) {
  // bpf_raw_tracepoint_args 的第二个成员是系统调用号
  // 具体可以查看 bpf_tracing.h 中的定义： unsigned long long args[2];
  // 对于 sys_enter, args[1] 是 syscall ID
  unsigned long syscall_id = ctx->args[1];

  // 判断是否是 execve 系统调用
  if (syscall_id != __NR_execve) {
    return 0; // 如果不是，直接返回
  }

  // 如果是 execve，则打印信息
  char msg[] = "Hello, World! (execve detected)";
  bpf_printk("invoke bpf_prog: %s\n", msg);
  
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";