// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates.*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <test_progs.h>
#include "cgrp_local_storage.skel.h"
#include "cgrp_ls_recursion.skel.h"

static void test_sys_enter_exit(int cgroup_fd)
{
	struct cgrp_local_storage *skel;
	long val1 = 1, val2 = 0;
	int err;

	skel = cgrp_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* populate a value in cgrp_storage_2 */
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.cgrp_storage_2), &cgroup_fd, &val1, BPF_ANY);
	if (!ASSERT_OK(err, "map_update_elem"))
		goto out;

	/* check value */
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.cgrp_storage_2), &cgroup_fd, &val2);
	if (!ASSERT_OK(err, "map_lookup_elem"))
		goto out;
	if (!ASSERT_EQ(val2, 1, "map_lookup_elem, invalid val"))
		goto out;

	/* delete value */
	err = bpf_map_delete_elem(bpf_map__fd(skel->maps.cgrp_storage_2), &cgroup_fd);
	if (!ASSERT_OK(err, "map_delete_elem"))
		goto out;

	skel->bss->target_pid = syscall(SYS_gettid);

	err = cgrp_local_storage__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	syscall(SYS_gettid);
	syscall(SYS_gettid);

	skel->bss->target_pid = 0;

	/* 3x syscalls: 1x attach and 2x gettid */
	ASSERT_EQ(skel->bss->enter_cnt, 3, "enter_cnt");
	ASSERT_EQ(skel->bss->exit_cnt, 3, "exit_cnt");
	ASSERT_EQ(skel->bss->mismatch_cnt, 0, "mismatch_cnt");
out:
	cgrp_local_storage__destroy(skel);
}

static void test_recursion(int cgroup_fd)
{
	struct cgrp_ls_recursion *skel;
	int err;

	skel = cgrp_ls_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = cgrp_ls_recursion__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* trigger sys_enter, make sure it does not cause deadlock */
	syscall(SYS_gettid);

out:
	cgrp_ls_recursion__destroy(skel);
}

void test_cgrp_local_storage(void)
{
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/cgrp_local_storage");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup /cgrp_local_storage"))
		return;

	if (test__start_subtest("sys_enter_exit"))
		test_sys_enter_exit(cgroup_fd);
	if (test__start_subtest("recursion"))
		test_recursion(cgroup_fd);

	close(cgroup_fd);
}
