package cryptd

import (
	encconfig "github.com/containerd/containerd/pkg/encryption/config"
	"github.com/containerd/typeurl"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func init() {
	typeurl.Register(&ProcessorPayload{}, "com.ibm.research.v1.ProcessorPayload")
}

type ProcessorPayload struct {
	DecryptConfig encconfig.DecryptConfig `json:"decrypt_config"`
	Descriptor    ocispec.Descriptor      `json:"descriptor"`
}
