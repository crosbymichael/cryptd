package cryptd

import (
	"context"

	"github.com/containerd/containerd/diff"
	encconfig "github.com/containerd/containerd/pkg/encryption/config"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// WithDecryptedImageUnpack sets the decryption keys for the client
func WithDecryptedImageUnpack(config encconfig.DecryptConfig) RemoteOpt {
	return func(_ *Client, c *RemoteContext) error {
		c.Unpack = true
		c.UnpackOpts = append(c.UnpackOpts, func(_ context.Context, desc ocispec.Descriptor, c *diff.ApplyConfig) error {
			if c.ProcessorPayloads == nil {
				c.ProcessorPayloads = make(map[string]*types.Any)
			}
			p := &ProcessorPayload{
				Descriptor:    desc,
				DecryptConfig: config,
			}
			any, err := typeurl.MarshalAny(p)
			if err != nil {
				return errors.Wrapf(err, "failed to marshal payload")
			}

			c.ProcessorPayloads["io.containerd.layertool.tar"] = any
			c.ProcessorPayloads["io.containerd.layertool.tar.gzip"] = any
			return nil
		})
		return nil
	}
}
