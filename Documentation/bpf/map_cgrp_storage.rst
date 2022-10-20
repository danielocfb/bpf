.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Meta Platforms, Inc. and affiliates.

===========================
BPF_MAP_TYPE_CGRP_STORAGE
===========================

The ``BPF_MAP_TYPE_CGRP_STORAGE`` map type represents a local fix-sized
storage for cgroups. It is only available with ``CONFIG_CGROUP_BPF``.
The programs are made available by the same Kconfig. The
data for a particular cgroup can be retrieved by looking up the map
with that cgroup.

This document describes the usage and semantics of the
``BPF_MAP_TYPE_CGRP_STORAGE`` map type.

Usage
=====

The map key must be ``sizeof(int)`` representing a cgroup fd.
To access the storage in a program, use ``bpf_cgrp_storage_get``::

    void *bpf_cgrp_storage_get(struct bpf_map *map, struct cgroup *cgroup, void *value, u64 flags)

``flags`` could be 0 or ``BPF_LOCAL_STORAGE_GET_F_CREATE`` which indicates that
a new local storage will be created if one does not exist.

The local storage can be removed with ``bpf_cgrp_storage_delete``::

    long bpf_cgrp_storage_delete(struct bpf_map *map, struct cgruop *cgroup)

The map is available to all program types.

Examples
========

An bpf-program example with BPF_MAP_TYPE_CGRP_STORAGE::

    #include <vmlinux.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>

    struct {
            __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, long);
    } cgrp_storage SEC(".maps");

    SEC("tp_btf/sys_enter")
    int BPF_PROG(on_enter, struct pt_regs *regs, long id)
    {
            struct task_struct *task = bpf_get_current_task_btf();
            long *ptr;

            ptr = bpf_cgrp_storage_get(&cgrp_storage, task->cgroups->dfl_cgrp, 0,
                                       BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (ptr)
                __sync_fetch_and_add(ptr, 1);

            return 0;
    }

Userspace accessing map declared above::

    #include <linux/bpf.h>
    #include <linux/libbpf.h>

    __u32 map_lookup(struct bpf_map *map, int cgrp_fd)
    {
            __u32 *value;
            value = bpf_map_lookup_elem(bpf_map__fd(map), &cgrp_fd);
            if (value)
                return *value;
            return 0;
    }

Difference Between BPF_MAP_TYPE_CGRP_STORAGE and BPF_MAP_TYPE_CGROUP_STORAGE
============================================================================

The main difference between ``BPF_MAP_TYPE_CGRP_STORAGE`` and ``BPF_MAP_TYPE_CGROUP_STORAGE``
is that ``BPF_MAP_TYPE_CGRP_STORAGE`` can be used by all program types while
``BPF_MAP_TYPE_CGROUP_STORAGE`` is available only to cgroup program types.

There are some other differences as well.

(1). ``BPF_MAP_TYPE_CGRP_STORAGE`` supports local storage for more than one
     cgroups while ``BPF_MAP_TYPE_CGROUP_STORAGE`` only support one, the one attached
     by the bpf program.

(2). ``BPF_MAP_TYPE_CGROUP_STORAGE`` allocates local storage at attach time so
     ``bpf_get_local_storage()`` always returns non-null local storage.
     ``BPF_MAP_TYPE_CGRP_STORAGE`` allocates local storage at runtime so
     it is possible that ``bpf_cgrp_storage_get()`` may return null local storage.
     To avoid such null local storage issue, user space can do
     ``bpf_map_update_elem()`` to pre-allocate local storage.

(3). ``BPF_MAP_TYPE_CGRP_STORAGE`` supports de-allocating local storage by bpf program
     while ``BPF_MAP_TYPE_CGROUP_STORAGE`` only de-allocates storage during
     prog detach time.

So overall, ``BPF_MAP_TYPE_CGRP_STORAGE`` supports all ``BPF_MAP_TYPE_CGROUP_STORAGE``
functionality and beyond. It is recommended to use ``BPF_MAP_TYPE_CGRP_STORAGE``
instead of ``BPF_MAP_TYPE_CGROUP_STORAGE``.
