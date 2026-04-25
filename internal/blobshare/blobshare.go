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

// Package blobshare defines the convention for the read-only virtio-fs
// share that the host shim uses to expose EROFS layer files to the
// guest. The host adds a single virtio-fs share at VM startup; vminitd
// mounts it at MountPath, and per-container EROFS files are reached as
// MountPath/<container-id>/<index>.erofs.
package blobshare

const (
	// Tag is the virtio-fs tag the host uses for the blob share.
	Tag = "nerdbox-blobs"

	// MountPath is the in-guest path where vminitd mounts the share.
	MountPath = "/run/nerdbox/blobs"

	// DefaultDAXWindow is the DAX SHM window size to use for the share
	// (1 GiB). Tunable; cloud-hypervisor defaults to 8 GiB. Smaller
	// windows mean more DAX setup/teardown when the working set
	// exceeds the window; the host page cache itself is not bounded
	// by this.
	DefaultDAXWindow uint64 = 1 << 30
)
