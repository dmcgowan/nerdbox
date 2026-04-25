/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package task

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/nerdbox/internal/shim/sandbox"
	"github.com/containerd/nerdbox/internal/shim/task/bundle"
)

func applyOpts(opts []sandbox.Opt) sandbox.Options {
	var o sandbox.Options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func TestBlockMountsProvider(t *testing.T) {
	const id = "cid"

	testcases := []struct {
		name           string
		mounts         []specs.Mount
		wantDisks      []sandbox.Disk
		wantSpecMounts []specs.Mount
		wantVmMounts   []mount.Mount
	}{
		{
			name:           "no mounts",
			mounts:         nil,
			wantDisks:      nil,
			wantSpecMounts: nil,
			wantVmMounts:   nil,
		},
		{
			name: "no ext4 mounts",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantDisks: nil,
			wantSpecMounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantVmMounts: nil,
		},
		{
			name: "single ext4 mount read-write",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data"},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: 0},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
			},
		},
		{
			name: "single ext4 mount read-only",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data", Options: []string{"ro"}},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: sandbox.DiskFlagReadonly},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind", "ro"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda", Options: []string{"ro"}},
			},
		},
		{
			name: "multiple ext4 mounts",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/vol1.img", Destination: "/data"},
				{Type: "ext4", Source: "/vol/vol2.img", Destination: "/logs", Options: []string{"ro"}},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/vol1.img", Flags: 0},
				{BlockID: "disk-98-cid", MountPath: "/vol/vol2.img", Flags: sandbox.DiskFlagReadonly},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
				{Type: "bind", Source: "/mnt/sdb", Destination: "/logs", Options: []string{"rbind", "ro"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
				{Type: "ext4", Source: "/dev/vdb", Target: "/mnt/sdb", Options: []string{"ro"}},
			},
		},
		{
			name: "mixed mount types",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: 0},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Spec: specs.Spec{Mounts: tc.mounts},
			}

			da := newDiskAllocator()
			bm := &blockMounter{}
			err := bm.FromBundle(context.Background(), b, id, &da)
			assert.NoError(t, err)

			opts := applyOpts(bm.SandboxOpts())
			assert.Equal(t, tc.wantDisks, opts.Disks)
			assert.Equal(t, tc.wantSpecMounts, b.Spec.Mounts)
			assert.Equal(t, tc.wantVmMounts, bm.VmMounts())
		})
	}
}

// TestTransformMountsErofsToVirtiofs covers the new EROFS handling:
// each erofs layer is hard-linked into <blobsDir>/<id>/<index>.erofs,
// guest mount specs reference the file under blobshare.MountPath, no
// virtio-block device is allocated for EROFS, and the blob share is
// added once via WithFSDAX.
func TestTransformMountsErofsToVirtiofs(t *testing.T) {
	const id = "ctr-erofs"

	tmp := t.TempDir()
	src0 := filepath.Join(tmp, "layer0.erofs")
	src1 := filepath.Join(tmp, "layer1.erofs")
	if err := os.WriteFile(src0, []byte("layer0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src1, []byte("layer1"), 0o644); err != nil {
		t.Fatal(err)
	}

	blobsDir := filepath.Join(tmp, "vm", "blobs")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	mounts := []*types.Mount{
		{Type: "ext4", Source: filepath.Join(tmp, "rw.ext4"), Options: []string{"rw", "loop"}},
		{Type: "erofs", Source: src0, Options: []string{"ro", "loop"}},
		{Type: "erofs", Source: src1, Options: []string{"ro", "loop"}},
	}

	da := newDiskAllocator()
	out, sbOpts, err := transformMounts(context.Background(), id, mounts, blobsDir, &da)
	assert.NoError(t, err)

	// EROFS no longer takes a virtio-block letter; only ext4 should.
	assert.Equal(t, byte('b'), da.next, "ext4 should consume vda; EROFS should not allocate a letter")

	// Guest mount specs: ext4 stays virtio-block; erofs become file
	// sources under the blob share's mount path.
	assert.Len(t, out, 3)
	assert.Equal(t, "ext4", out[0].Type)
	assert.Equal(t, "/dev/vda", out[0].Source)
	assert.Equal(t, "erofs", out[1].Type)
	assert.Equal(t, "/run/nerdbox/blobs/"+id+"/0.erofs", out[1].Source)
	assert.Equal(t, "erofs", out[2].Type)
	assert.Equal(t, "/run/nerdbox/blobs/"+id+"/1.erofs", out[2].Source)

	// The shim should hard-link each blob into <blobsDir>/<id>/.
	stagedDir := filepath.Join(blobsDir, id)
	for i, src := range []string{src0, src1} {
		dst := filepath.Join(stagedDir, fmt.Sprintf("%d.erofs", i))
		dstInfo, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("staged blob %d not found: %v", i, err)
		}
		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		// Same inode means hard link (no copy).
		assert.True(t, os.SameFile(srcInfo, dstInfo), "blob %d should be hard-linked, not copied", i)
	}

	// Sandbox opts should include the disk for ext4 + the blob share.
	o := applyOpts(sbOpts)
	assert.Len(t, o.Disks, 1, "only ext4 should produce a disk")
	assert.Len(t, o.Filesystems, 1, "blob share should be added once")
	assert.Equal(t, "nerdbox-blobs", o.Filesystems[0].Tag)
	assert.Equal(t, blobsDir, o.Filesystems[0].MountPath)
	assert.True(t, o.Filesystems[0].Readonly)
	assert.Greater(t, o.Filesystems[0].DAXWindow, uint64(0))
}

// TestStageBlobHardLink verifies stageBlob hard-links rather than
// copies when source and destination are on the same filesystem.
func TestStageBlobHardLink(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := stageBlob(src, dst); err != nil {
		t.Fatal(err)
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, os.SameFile(srcInfo, dstInfo), "stageBlob should produce a hard link on the same fs")

	// Idempotent: a second call leaves the file in place.
	if err := stageBlob(src, dst); err != nil {
		t.Fatal(err)
	}
	dstInfo2, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, os.SameFile(dstInfo, dstInfo2))
}

func TestBindMountsProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	testfile := filepath.Join(tmpDir, "testfile.txt")
	f, err := os.Create(testfile)
	assert.NoError(t, err)
	f.Close()

	// Create a test directory
	testdirData := filepath.Join(tmpDir, "testdir", "data")
	assert.NoError(t, os.MkdirAll(testdirData, 0755))
	testdirConfig := filepath.Join(tmpDir, "testdir", "config")
	assert.NoError(t, os.MkdirAll(testdirConfig, 0755))

	testcases := []struct {
		name            string
		mounts          []specs.Mount
		wantMounts      []bindMount
		wantSpecSources []string // expected sources in the OCI spec after transformation
		wantVmMounts    []mount.Mount
	}{
		{
			name:            "no mounts",
			mounts:          nil,
			wantMounts:      nil,
			wantSpecSources: nil,
			wantVmMounts:    nil,
		},
		{
			name: "no bind mounts",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantMounts:      nil,
			wantSpecSources: []string{"tmpfs", "proc"},
			wantVmMounts:    nil,
		},
		{
			name: "single bind mount",
			mounts: []specs.Mount{
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
			},
			wantSpecSources: []string{"/mnt/bind-8c5eaa445dd84f17"},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
			},
		},
		{
			name: "multiple bind mounts",
			mounts: []specs.Mount{
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
				{Type: "bind", Source: testdirConfig, Destination: "/container/config"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
				{
					tag:      "bind-529984c9ac58b7ec",
					hostSrc:  testdirConfig,
					vmTarget: "/mnt/bind-529984c9ac58b7ec",
				},
			},
			wantSpecSources: []string{
				"/mnt/bind-8c5eaa445dd84f17",
				"/mnt/bind-529984c9ac58b7ec",
			},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
				{Type: "virtiofs", Source: "bind-529984c9ac58b7ec", Target: "/mnt/bind-529984c9ac58b7ec"},
			},
		},
		{
			name: "mixed mount types",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
			},
			wantSpecSources: []string{
				"tmpfs",
				"/mnt/bind-8c5eaa445dd84f17",
				"proc",
			},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
			},
		},
		{
			name: "single file bind mount",
			mounts: []specs.Mount{
				{Type: "bind", Source: testfile, Destination: "/container/testfile"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-6dace5108a719565",
					hostSrc:  tmpDir,
					vmTarget: "/mnt/bind-6dace5108a719565",
				},
			},
			wantSpecSources: []string{"/mnt/bind-6dace5108a719565/testfile.txt"},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-6dace5108a719565", Target: "/mnt/bind-6dace5108a719565"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Spec: specs.Spec{
					Mounts: tc.mounts,
				},
			}

			bm := &bindMounter{}
			err := bm.FromBundle(context.Background(), b)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantMounts, bm.mounts)

			// Verify that the spec sources were transformed
			for i, wantSource := range tc.wantSpecSources {
				assert.Equal(t, wantSource, b.Spec.Mounts[i].Source)
			}

			// Verify the VM mounts passed via MountAll RPC
			assert.Equal(t, tc.wantVmMounts, bm.VmMounts())
		})
	}
}
