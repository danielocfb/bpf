.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

===================
BPF_MAP_TYPE_CPUMAP
===================

.. note::
   - ``BPF_MAP_TYPE_CPUMAP`` was introduced in kernel version 4.15

``BPF_MAP_TYPE_CPUMAP`` is primarily used as a backend map for the XDP BPF
helpers ``bpf_redirect_map()`` and ``XDP_REDIRECT`` action. This map type redirects raw
XDP frames to another CPU.

A CPUMAP is a scalability and isolation mechanism that allows the steering of packets
to dedicated CPUs for processing. An example use-case for this map type is software
based Receive Side Scaling (RSS).

The CPUMAP represents the CPUs in the system indexed as the map-key, and the
map-value is the config setting (per CPUMAP entry). Each CPUMAP entry has a dedicated
kernel thread bound to the given CPU to represent the remote CPU execution unit.

Starting from Linux kernel version 5.9 the CPUMAP can run a second XDP program
on the remote CPU. This allows an XDP program to split its processing across
multiple CPUs. For example, a scenario where the initial CPU (that sees/receives
the packets) needs to do minimal packet processing and the remote CPU (to which
the packet is directed) can afford to spend more cycles processing the frame. The
initial CPU is where the XDP redirect program is executed. The remote CPU
receives raw``xdp_frame`` objects.

Usage
=====

.. c:function::
   long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)

 CPU entries can be added or updated using the ``bpf_map_update_elem()``
 helper. This helper replaces existing elements atomically. The ``value`` parameter
 can be ``struct bpf_cpumap_val``.

 .. note::
    The maps can only be updated from user space and not from a BPF program.

 .. code-block:: c

    struct bpf_cpumap_val {
        __u32 qsize;  /* queue size to remote target CPU */
        union {
            int   fd; /* prog fd on map write */
            __u32 id; /* prog id on map read */
        } bpf_prog;
    };

.. c:function::
   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

 CPU entries can be retrieved using the ``bpf_map_lookup_elem()``
 helper.

.. c:function::
   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

 CPU entries can be deleted using the ``bpf_map_delete_elem()``
 helper. This helper will return 0 on success, or negative error in case of
 failure.

.. c:function::
     long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)

 Redirect the packet to the endpoint referenced by ``map`` at index ``key``.
 For ``BPF_MAP_TYPE_CPUMAP`` this map contains references to CPUs.

 The lower two bits of *flags* are used as the return code if the map lookup
 fails. This is so that the return value can be one of the XDP program return
 codes up to ``XDP_TX``, as chosen by the caller.

Examples
========
Kernel
------

The following code snippet shows how to declare a BPF_MAP_TYPE_CPUMAP called
cpu_map and how to redirect packets to a remote CPU using a round robin scheme.

.. code-block:: c

   struct {
        __uint(type, BPF_MAP_TYPE_CPUMAP);
        __type(key, u32);
        __type(value, struct bpf_cpumap_val);
        __uint(max_entries, 12);
    } cpu_map SEC(".maps");

    struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, u32);
        __uint(max_entries, 12);
    } cpus_available SEC(".maps");

    struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, u32);
        __uint(max_entries, 1);
       } cpus_iterator SEC(".maps");

    SEC("xdp")
    int  xdp_redir_cpu_round_robin(struct xdp_md *ctx)
    {
        u32 key = 0;
        u32 cpu_dest = 0;
        u32 *cpu_selected, *cpu_iterator;
        u32 cpu_idx;

        cpu_iterator = bpf_map_lookup_elem(&cpus_iterator, &key);
        if (!cpu_iterator)
            return XDP_ABORTED;
        cpu_idx = *cpu_iterator;

        *cpu_iterator += 1;
        if (*cpu_iterator == bpf_num_possible_cpus())
            *cpu_iterator = 0;

        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;

        if (cpu_dest >= bpf_num_possible_cpus())
            return XDP_ABORTED;

        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    }

References
===========

- https://elixir.bootlin.com/linux/v6.0.1/source/kernel/bpf/cpumap.c
- https://developers.redhat.com/blog/2021/05/13/receive-side-scaling-rss-with-ebpf-and-cpumap#redirecting_into_a_cpumap
