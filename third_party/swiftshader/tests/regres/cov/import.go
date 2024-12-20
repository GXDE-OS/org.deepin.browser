// Copyright 2020 The SwiftShader Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cov

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"../cause"
	"../llvm"
)

// Location describes a single line-column position in a source file.
type Location struct {
	Line, Column int
}

func (l Location) String() string {
	return fmt.Sprintf("%v:%v", l.Line, l.Column)
}

// Compare returns -1 if l comes before o, 1 if l comes after o, otherwise 0.
func (l Location) Compare(o Location) int {
	switch {
	case l.Line < o.Line:
		return -1
	case l.Line > o.Line:
		return 1
	}
	return 0
}

// Before returns true if l comes before o.
func (l Location) Before(o Location) bool { return l.Compare(o) == -1 }

// Span describes a start and end interval in a source file.
type Span struct {
	Start, End Location
}

func (s Span) String() string {
	return fmt.Sprintf("%v-%v", s.Start, s.End)
}

// Compare returns -1 if l comes before o, 1 if l comes after o, otherwise 0.
func (s Span) Compare(o Span) int {
	switch {
	case s.Start.Before(o.Start):
		return -1
	case o.Start.Before(s.Start):
		return 1
	case s.End.Before(o.End):
		return -1
	case o.End.Before(s.End):
		return 1
	}
	return 0
}

// Before returns true if span s comes before o.
func (s Span) Before(o Span) bool { return s.Compare(o) == -1 }

// File describes the coverage spans in a single source file.
type File struct {
	Path  string
	Spans []Span
}

// Coverage describes the coverage spans for all the source files for a single
// process invocation.
type Coverage struct {
	Files []File
}

// Env holds the enviroment settings for performing coverage processing.
type Env struct {
	LLVM     llvm.Toolchain
	RootDir  string // path to SwiftShader git root directory
	ExePath  string // path to the executable binary
	TurboCov string // path to turbo-cov (optional)
}

// AppendRuntimeEnv returns the environment variables env with the
// LLVM_PROFILE_FILE environment variable appended.
func AppendRuntimeEnv(env []string, coverageFile string) []string {
	return append(env, "LLVM_PROFILE_FILE="+coverageFile)
}

// Import uses the llvm-profdata and llvm-cov tools to import the coverage
// information from a .profraw file.
func (e Env) Import(profrawPath string) (*Coverage, error) {
	profdata := profrawPath + ".profdata"

	if err := exec.Command(e.LLVM.Profdata(), "merge", "-sparse", profrawPath, "-output", profdata).Run(); err != nil {
		return nil, cause.Wrap(err, "llvm-profdata errored")
	}
	defer os.Remove(profdata)

	if e.TurboCov == "" {
		args := []string{
			"export",
			e.ExePath,
			"-instr-profile=" + profdata,
			"-format=text",
		}
		if e.LLVM.Version.GreaterEqual(llvm.Version{Major: 9}) {
			// LLVM 9 has new flags that omit stuff we don't care about.
			args = append(args,
				"-skip-expansions",
				"-skip-functions",
			)
		}

		data, err := exec.Command(e.LLVM.Cov(), args...).Output()
		if err != nil {
			return nil, cause.Wrap(err, "llvm-cov errored: %v", string(err.(*exec.ExitError).Stderr))
		}
		cov, err := e.parseCov(data)
		if err != nil {
			return nil, cause.Wrap(err, "Couldn't parse coverage json data")
		}
		return cov, nil
	}

	data, err := exec.Command(e.TurboCov, e.ExePath, profdata).Output()
	if err != nil {
		return nil, cause.Wrap(err, "turbo-cov errored: %v", string(err.(*exec.ExitError).Stderr))
	}
	cov, err := e.parseTurboCov(data)
	if err != nil {
		return nil, cause.Wrap(err, "Couldn't process turbo-cov output")
	}
	return cov, nil
}

// https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
// https://stackoverflow.com/a/56792192
func (e Env) parseCov(raw []byte) (*Coverage, error) {
	// line int, col int, count int64, hasCount bool, isRegionEntry bool
	type segment []interface{}

	type file struct {
		// expansions ignored
		Name     string    `json:"filename"`
		Segments []segment `json:"segments"`
		// summary ignored
	}

	type data struct {
		Files []file `json:"files"`
	}

	root := struct {
		Data []data `json:"data"`
	}{}
	err := json.NewDecoder(bytes.NewReader(raw)).Decode(&root)
	if err != nil {
		return nil, err
	}

	c := &Coverage{Files: make([]File, 0, len(root.Data[0].Files))}
	for _, f := range root.Data[0].Files {
		relpath, err := filepath.Rel(e.RootDir, f.Name)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(relpath, "..") {
			continue
		}
		file := File{Path: relpath}
		for sIdx := 0; sIdx+1 < len(f.Segments); sIdx++ {
			start := Location{(int)(f.Segments[sIdx][0].(float64)), (int)(f.Segments[sIdx][1].(float64))}
			end := Location{(int)(f.Segments[sIdx+1][0].(float64)), (int)(f.Segments[sIdx+1][1].(float64))}
			covered := f.Segments[sIdx][2].(float64) != 0
			if covered {
				if c := len(file.Spans); c > 0 && file.Spans[c-1].End == start {
					file.Spans[c-1].End = end
				} else {
					file.Spans = append(file.Spans, Span{start, end})
				}
			}
		}
		if len(file.Spans) > 0 {
			c.Files = append(c.Files, file)
		}
	}

	return c, nil
}

func (e Env) parseTurboCov(data []byte) (*Coverage, error) {
	u32 := func() uint32 {
		out := binary.LittleEndian.Uint32(data)
		data = data[4:]
		return out
	}
	u8 := func() uint8 {
		out := data[0]
		data = data[1:]
		return out
	}
	str := func() string {
		len := u32()
		out := data[:len]
		data = data[len:]
		return string(out)
	}

	numFiles := u32()
	c := &Coverage{Files: make([]File, 0, numFiles)}
	for i := 0; i < int(numFiles); i++ {
		path := str()
		relpath, err := filepath.Rel(e.RootDir, path)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(relpath, "..") {
			continue
		}

		file := File{Path: relpath}

		type segment struct {
			location Location
			count    int
			covered  bool
		}

		numSegements := u32()
		segments := make([]segment, numSegements)
		for j := range segments {
			segment := &segments[j]
			segment.location.Line = int(u32())
			segment.location.Column = int(u32())
			segment.count = int(u32())
			segment.covered = u8() != 0
		}

		for sIdx := 0; sIdx+1 < len(segments); sIdx++ {
			start := segments[sIdx].location
			end := segments[sIdx+1].location
			if segments[sIdx].count > 0 {
				if c := len(file.Spans); c > 0 && file.Spans[c-1].End == start {
					file.Spans[c-1].End = end
				} else {
					file.Spans = append(file.Spans, Span{start, end})
				}
			}
		}

		if len(file.Spans) > 0 {
			c.Files = append(c.Files, file)
		}
	}

	return c, nil
}

// Path is a tree node path formed from a list of strings
type Path []string
