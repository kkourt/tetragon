// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/cgidarg"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "cgtracker",
		Short:        "manage cgtracker map (only for debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		dumpCmd(),
		addCommand(),
	)

	return ret
}

func dumpCmd() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, cgtracker.MapName)
	ret := &cobra.Command{
		Use:   "dump",
		Short: "dump cgtracker map state",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			m, err := cgtracker.OpenMap(mapFname)
			if err != nil {
				log.Fatal(err)
			}
			defer m.Close()

			vals, err := m.Dump()
			if err != nil {
				log.Fatal(err)
			}
			for tracker, tracked := range vals {
				fmt.Printf("%d: %v\n", tracker, tracked)
			}
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "cgtracker map filename")
	return ret
}

func addCommand() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, cgtracker.MapName)
	ret := &cobra.Command{
		Use:   "add cg_tracked cg_tracker",
		Short: "add cgtracker entry",
		Args:  cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			tracked, err := cgidarg.Parse(args[0])
			if err != nil {
				log.Fatal(err)
			}
			tracker, err := cgidarg.Parse(args[1])
			if err != nil {
				log.Fatal(err)
			}
			m, err := cgtracker.OpenMap(mapFname)
			if err != nil {
				log.Fatal(err)
			}
			defer m.Close()

			err = m.Add(tracked, tracker)
			if err != nil {
				log.Fatal(err)
			}

		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "cgtracker map filename")
	return ret
}
