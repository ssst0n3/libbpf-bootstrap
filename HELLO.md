```
$ docker build -t test .
```

```
$ docker run -ti --cap-add CAP_SYS_ADMIN -v /sys/kernel/tracing:/sys/kernel/tracing test bash
root@7bf678a14aa3:/src/examples/c# ./helloworld
libbpf: loading object 'helloworld_bpf' from buffer
libbpf: elf: section(2) .symtab, size 168, link 1, flags 0, type=2
libbpf: elf: section(3) tracepoint/syscalls/sys_enter_execve, size 120, link 0, flags 6, type=1
libbpf: sec 'tracepoint/syscalls/sys_enter_execve': found program 'bpf_prog' at insn offset 0 (0 bytes), code size 15 insns (120 bytes)
libbpf: elf: section(4) .rodata.str1.1, size 14, link 0, flags 32, type=1
libbpf: elf: section(5) .rodata, size 21, link 0, flags 2, type=1
libbpf: elf: section(6) license, size 13, link 0, flags 3, type=1
libbpf: license of helloworld_bpf is Dual BSD/GPL
libbpf: elf: section(7) .reltracepoint/syscalls/sys_enter_execve, size 16, link 2, flags 40, type=9
libbpf: elf: section(8) .BTF, size 524, link 0, flags 0, type=1
libbpf: elf: section(9) .BTF.ext, size 128, link 0, flags 0, type=1
libbpf: looking for externs among 7 symbols...
libbpf: collected 0 externs total
libbpf: map '.rodata.str1.1' (global data): at sec_idx 4, offset 0, flags 80.
libbpf: map 0 is ".rodata.str1.1"
libbpf: map 'hellowor.rodata' (global data): at sec_idx 5, offset 0, flags 80.
libbpf: map 1 is "hellowor.rodata"
libbpf: sec '.reltracepoint/syscalls/sys_enter_execve': collecting relocation for section(3) 'tracepoint/syscalls/sys_enter_execve'
libbpf: sec '.reltracepoint/syscalls/sys_enter_execve': relo #0: insn #9 against '.rodata'
libbpf: prog 'bpf_prog': found data map 1 (hellowor.rodata, sec 5, off 0) for insn 9
libbpf: object 'helloworld_bpf': failed (-22) to create BPF token from '/sys/fs/bpf', skipping optional step...
libbpf: map '.rodata.str1.1': created successfully, fd=3
libbpf: map 'hellowor.rodata': created successfully, fd=4
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
...
```

```
$ docker run -ti --cap-add CAP_SYS_ADMIN test bash                                 
root@ae679eed6b49:/src/examples/c# ./helloworld_raw 
libbpf: loading object 'helloworld_raw_bpf' from buffer
libbpf: elf: section(2) .symtab, size 192, link 1, flags 0, type=2
libbpf: elf: section(3) raw_tracepoint/sys_enter, size 176, link 0, flags 6, type=1
libbpf: sec 'raw_tracepoint/sys_enter': found program 'bpf_prog' at insn offset 0 (0 bytes), code size 22 insns (176 bytes)
libbpf: elf: section(4) .rodata.str1.1, size 32, link 0, flags 32, type=1
libbpf: elf: section(5) .rodata, size 21, link 0, flags 2, type=1
libbpf: elf: section(6) license, size 13, link 0, flags 3, type=1
libbpf: license of helloworld_raw_bpf is Dual BSD/GPL
libbpf: elf: section(7) .relraw_tracepoint/sys_enter, size 16, link 2, flags 40, type=9
libbpf: elf: section(8) .BTF, size 706, link 0, flags 0, type=1
libbpf: elf: section(9) .BTF.ext, size 144, link 0, flags 0, type=1
libbpf: looking for externs among 8 symbols...
libbpf: collected 0 externs total
libbpf: map '.rodata.str1.1' (global data): at sec_idx 4, offset 0, flags 80.
libbpf: map 0 is ".rodata.str1.1"
libbpf: map 'hellowor.rodata' (global data): at sec_idx 5, offset 0, flags 80.
libbpf: map 1 is "hellowor.rodata"
libbpf: sec '.relraw_tracepoint/sys_enter': collecting relocation for section(3) 'raw_tracepoint/sys_enter'
libbpf: sec '.relraw_tracepoint/sys_enter': relo #0: insn #16 against '.rodata'
libbpf: prog 'bpf_prog': found data map 1 (hellowor.rodata, sec 5, off 0) for insn 16
libbpf: object 'helloworld_raw_': failed (-22) to create BPF token from '/sys/fs/bpf', skipping optional step...
libbpf: map '.rodata.str1.1': created successfully, fd=3
libbpf: map 'hellowor.rodata': created successfully, fd=4
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
...
```

```
$ docker run -ti --cap-add CAP_SYS_ADMIN test ./helloworld_kprobe
libbpf: loading object 'helloworld_kprobe_bpf' from buffer
libbpf: elf: section(2) .symtab, size 168, link 1, flags 0, type=2
libbpf: elf: section(3) kprobe/__x64_sys_execve, size 176, link 0, flags 6, type=1
libbpf: sec 'kprobe/__x64_sys_execve': found program 'kprobe_execve' at insn offset 0 (0 bytes), code size 22 insns (176 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of helloworld_kprobe_bpf is Dual BSD/GPL
libbpf: elf: section(5) .rodata, size 31, link 0, flags 2, type=1
libbpf: elf: section(6) .relkprobe/__x64_sys_execve, size 16, link 2, flags 40, type=9
libbpf: elf: section(7) .BTF, size 1123, link 0, flags 0, type=1
libbpf: elf: section(8) .BTF.ext, size 192, link 0, flags 0, type=1
libbpf: looking for externs among 7 symbols...
libbpf: collected 0 externs total
libbpf: map 'hellowor.rodata' (global data): at sec_idx 5, offset 0, flags 80.
libbpf: map 0 is "hellowor.rodata"
libbpf: sec '.relkprobe/__x64_sys_execve': collecting relocation for section(3) 'kprobe/__x64_sys_execve'
libbpf: sec '.relkprobe/__x64_sys_execve': relo #0: insn #13 against '.rodata'
libbpf: prog 'kprobe_execve': found data map 0 (hellowor.rodata, sec 5, off 0) for insn 13
libbpf: object 'helloworld_kpro': failed (-22) to create BPF token from '/sys/fs/bpf', skipping optional step...
libbpf: map 'hellowor.rodata': created successfully, fd=3
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
...
```