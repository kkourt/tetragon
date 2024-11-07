// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func MkdirProg() *program.Program {
	return program.Builder(
		objFilename,
		"cgroup/cgroup_mkdir",
		"raw_tracepoint/cgroup_mkdir",
		"tg_cgtracker_cgroup_mkdir",
		"raw_tracepoint",
	)
}

func ReleaseProg() *program.Program {
	return program.Builder(
		objFilename,
		"cgroup/cgroup_release",
		"raw_tracepoint/cgroup_release",
		"tg_cgtracker_cgroup_release",
		"raw_tracepoint",
	)
}
