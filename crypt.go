package cryptd

import (
	"context"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	imgenc "github.com/containerd/containerd/images/encryption"
	encconfig "github.com/containerd/containerd/pkg/encryption/config"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func New(client *containerd.Client) *CryptoClient {
	return CryptoClient{
		client: client,
	}
}

type CryptoClient struct {
	client *containerd.Client
}

type CryptOpt func(ctx context.Context, c *CryptOptConfig)

type CryptOptConfig struct {
	Platforms []string
	Layers    []int32
}

func WithPlatforms(platforms []string) CryptOpt {
	return func(ctx context.Context, c *CryptOptConfig) {
		c.Platforms = platforms
	}
}

func WithLayers(layers []int32) CryptOpt {
	return func(ctx context.Context, c *CryptOptConfig) {
		c.Layers = layers
	}
}

func (c *CryptoClient) EncryptImage(ctx context.Context, image containerd.Image, name string, config *encconfig.CryptoConfig, opts ...CryptOpt) (containerd.Image, error) {
	var optConfig CryptOptConfig
	for _, o := range opts {
		o(ctx, &optConfig)
	}

	pl, err := parsePlatformArray(optConfig.Platforms)
	if err != nil {
		return nil, err
	}

	lf, err := c.createLayerFilter(ctx, image.Target(), optConfig.Layers, pl)
	if err != nil {
		return nil, err
	}

	ctx, done, err := c.client.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	desc, modified, err := imgenc.EncryptImage(ctx, image.ContentStore(), image.Target(), config, lf)
	if err != nil {
		return nil, err
	}
	if !modified {
		return image, nil
	}

	newImage := images.Image{
		Name:   name,
		Target: desc,
		Labels: image.Labels(),
	}

	s := c.client.ImageService()
	i, err := s.Create(ctx, newImage)
	if err != nil {
		return nil, err
	}
	return containerd.NewImage(c.client, i)
}

func (c *CryptoClient) DecryptImage(ctx context.Context, image containerd.Image, name string, config *encconfig.CryptoConfig, opts ...CryptOpt) (containerd.Image, error) {
	var optConfig CryptOptConfig
	for _, o := range opts {
		o(ctx, &optConfig)
	}

	pl, err := parsePlatformArray(optConfig.Platforms)
	if err != nil {
		return nil, err
	}

	lf, err := c.createLayerFilter(ctx, image.Target(), optConfig.Layers, pl)
	if err != nil {
		return nil, err
	}

	ctx, done, err := c.client.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	desc, modified, err := imgenc.DecryptImage(ctx, image.ContentStore(), image.Target(), config, lf)
	if err != nil {
		return nil, err
	}
	if !modified {
		return image, nil
	}

	newImage := images.Image{
		Name:   name,
		Target: desc,
		Labels: image.Labels(),
	}

	s := c.client.ImageService()
	i, err := s.Create(ctx, newImage)
	if err != nil {
		return nil, err
	}
	return containerd.NewImage(c.client, i)
}

func (c *CryptoClient) createLayerFilter(ctx context.Context, desc ocispec.Descriptor, layers []int32, platformList []ocispec.Platform) (imgenc.LayerFilter, error) {
	alldescs, err := images.GetImageLayerDescriptors(ctx, client.ContentStore(), desc)
	if err != nil {
		return nil, err
	}

	_, descs := filterLayerDescriptors(alldescs, layers, platformList)

	lf := func(d ocispec.Descriptor) bool {
		for _, desc := range descs {
			if desc.Digest.String() == d.Digest.String() {
				return true
			}
		}
		return false
	}
	return lf, nil
}
