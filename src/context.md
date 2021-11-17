# bcc 中的程序参数

## bpf\_prog 结构体

每一个 ebpf 程序，都是通过 struct bpf\_prog 表示出来的，可以看到，这就是对 bpf 程序的描述，包括了下面关键的信息
1. 是否 jit
2. bpf 程序的类，如 PROG\_SOCKET\_FILTER，PROG\_TYPE\_XDP
3. 希望 attach 的类型，如 kprobe, uprobe, tracepoint
4. bpf 程序的指令集
```c
// include/linux/filter.h

struct bpf_prog {
	u16			pages;		/* Number of allocated pages */
	u16			jited:1,	/* Is our filter JIT'ed? */
				jit_requested:1,/* archs need to JIT the prog */
				gpl_compatible:1, /* Is filter GPL compatible? */
				cb_access:1,	/* Is control block accessed? */
				dst_needed:1,	/* Do we need dst entry? */
				blinded:1,	/* Was blinded */
				is_func:1,	/* program is a bpf function */
				kprobe_override:1, /* Do we override a kprobe? */
				has_callchain_buf:1, /* callchain buffer allocated? */
				enforce_expected_attach_type:1, /* Enforce expected_attach_type checking at attach time */
				call_get_stack:1; /* Do we call bpf_get_stack() or bpf_get_stackid() */
	enum bpf_prog_type	type;		/* Type of BPF program */
	enum bpf_attach_type	expected_attach_type; /* For some prog types */
	u32			len;		/* Number of filter blocks */
	u32			jited_len;	/* Size of jited insns in bytes */
	u8			tag[BPF_TAG_SIZE];
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	/* Instructions for interpreter */
	struct sock_filter	insns[0];
	struct bpf_insn		insnsi[];
};

```

通过 `BPF_PROG_RUN` 宏，来执行一个 BPF 程序  
这个宏需要传入一个 ctx 参数，这个参数，在不同场景下是不同的，比如对于 xdp 程序来说，就是一个 `xdp_buff`，对于 socket 程序来说，就是一个 `sk_buff` 结构  
在不同的上下文环境中，可以拿到不同类型的参数

```c
// include/linux/filter.h
#define BPF_PROG_RUN(prog, ctx)						\
	__BPF_PROG_RUN(prog, ctx, bpf_dispatcher_nop_func)

```

bpf 程序中使用的 bpf map 类型，使用了下面的 `struct bpf_map` 来表示，一般来说，用户需要定义的字段就是 `bpf_map_type`，以及 `key_size`，`value_size`，还有 `max_entries`，其余的内核会为我们处理妥当
```c
struct bpf_map {
	/* The first two cachelines with read-mostly members of which some
	 * are also accessed in fast-path (e.g. ops, max_entries).
	 */
	const struct bpf_map_ops *ops ____cacheline_aligned;
	struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	int spin_lock_off; /* >=0 valid offset, <0 error */
	u32 id;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	struct btf *btf;
	struct bpf_map_memory memory;
	char name[BPF_OBJ_NAME_LEN];
	u32 btf_vmlinux_value_type_id;
	bool bypass_spec_v1;
	bool frozen; /* write-once; write-protected by freeze_mutex */
	/* 22 bytes hole */

	/* The 3rd and 4th cacheline with misc members to avoid false sharing
	 * particularly with refcounting.
	 */
	atomic64_t refcnt ____cacheline_aligned;
	atomic64_t usercnt;
	struct work_struct work;
	struct mutex freeze_mutex;
	u64 writecnt; /* writable mmap cnt; protected by freeze_mutex */
};
```
