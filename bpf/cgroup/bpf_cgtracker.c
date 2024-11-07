// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_helpers.h"
#include "bpf_cgroup.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64); /* cgroup id */
	__type(value, __u64); /* tracker cgroup id */
} tg_cgtracker_map SEC(".maps");

/* new kernel cgroup definition */
struct cgroup___new {
	int level;
	struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

/* old kernel cgroup definition */
struct cgroup___old {
	int level;
	u64 ancestor_ids[];
} __attribute__((preserve_access_index));

FUNC_INLINE __u64 get_cgroup_ancestor_id(struct cgroup *cgrp, int level)
{
	struct cgroup___new *cgrp_new = (struct cgroup___new *)cgrp;

	if (bpf_core_field_exists(cgrp_new->ancestors)) {
		return BPF_CORE_READ(cgrp_new, ancestors[level], kn, id);
	} else {
		struct cgroup___old *cgrp_old;

		cgrp_old = (struct cgroup___old *)cgrp;
		return BPF_CORE_READ(cgrp_old, ancestor_ids[level]);
	}
}

__attribute__((section(("raw_tracepoint/cgroup_mkdir")), used)) int
tg_cgtracker_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	int level;
	struct cgroup *cgrp;
	__u64 cgid, cgid_parent, *cgid_tracker;

	cgrp = (struct cgroup *)ctx->args[0];
	cgid = get_cgroup_id(cgrp);
	if (cgid == 0)
		return 0;
	level = get_cgroup_level(cgrp);
	if (level <= 0)
		return 0;
	cgid_parent = get_cgroup_ancestor_id(cgrp, level - 1);
	if (cgid_parent == 0)
		return 0;
	cgid_tracker = map_lookup_elem(&tg_cgtracker_map, &cgid_parent);
	if (cgid_tracker)
		map_update_elem(&tg_cgtracker_map, &cgid, cgid_tracker, BPF_ANY);

	return 0;
}

__attribute__((section(("raw_tracepoint/cgroup_release")), used)) int
tg_cgtracker_cgroup_release(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cgrp;
	__u64 cgid;

	cgrp = (struct cgroup *)ctx->args[0];
	cgid = get_cgroup_id(cgrp);
	if (cgid == 0)
		return 0;
	map_delete_elem(&tg_cgtracker_map, &cgid);

	return 0;
}
