# Cgroup Tracking

Tetragon associates processes to workloads via their cgroup. We use this to do pod association,
i.e., attach pod information in every event. Cgroup tracking allows to track processes not only _of_
a given cgroup but _under_  a given cgroup. Effectively, this means that even if a container creates
a cgroup hierachy and has processes running under its cgroup root, pod association still works.

There are two ways Tetragon implements pod association:

1. cgroup name: bpf program passes the cgroup name to user-space to find the corresponding container
   and then the pod. This approach utilizes the fact that runtime systems name the cgroup based on
   the container id. This is the default.

2. cgroup id: bpf program passes the cgroup id to user-space which maintains a mapping between
   cgroup id and container id. This is enabled using --enable-cgidmap and uses the cri socket to
   maintain the mapping. This is a more reliable approach.

Under approach (2), we can implement cgroup tracking.

This is done by using a `cgtracker_map` where cgroups are mapped to their tracker cgroup id.

When a container starts or we discover a new container:
 - we get its cgroup path (`cg_path`), and cgroup id (`cgid`)
 - and an entry `cgid` -> `cgid` in the `cgtracker_map`
 - for all paths p under cgPath:
    add an entry to `cgtracker_map`: getCgroupIDFromPath(p) -> `cgid`

When a cgroup is created:
 - if `cgid` is the new cgroup id, and `cgid_parent` is its parent
   if `cgid_parent` in `cgtracker_map`:
        add `cgid` -> `cgtracker_map[cgid]` entry to the `cgtracker_map`

When a cgroup is deleted:
    delete `cgtracker_map[cgid]`

TODO:
 -remove old cgroup code


Other notes:
 - We have an issue because the process data are only computed during exec. If things change, then
   we do not update the process information.
