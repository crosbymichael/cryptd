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

package main

import (
	gocontext "context"

	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/pkg/encryption"
	encconfig "github.com/containerd/containerd/pkg/encryption/config"
	encutils "github.com/containerd/containerd/pkg/encryption/utils"
	"github.com/containerd/containerd/platforms"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// LayerInfo holds information about an image layer
type LayerInfo struct {
	// The Number of this layer in the sequence; starting at 0
	Index      uint32
	Descriptor ocispec.Descriptor
}

// isUserSelectedLayer checks whether a layer is user-selected given its number
// A layer can be described with its (positive) index number or its negative number.
// The latter is counted relative to the topmost one (-1), the former relative to
// the bottommost one (0).
func isUserSelectedLayer(layerIndex, layersTotal int32, layers []int32) bool {
	if len(layers) == 0 {
		// convenience for the user; none given means 'all'
		return true
	}
	negNumber := layerIndex - layersTotal

	for _, l := range layers {
		if l == negNumber || l == layerIndex {
			return true
		}
	}
	return false
}

// isUserSelectedPlatform determines whether the platform matches one in
// the array of user-provided platforms
func isUserSelectedPlatform(platform *ocispec.Platform, platformList []ocispec.Platform) bool {
	if len(platformList) == 0 {
		// convenience for the user; none given means 'all'
		return true
	}
	matcher := platforms.NewMatcher(*platform)

	for _, platform := range platformList {
		if matcher.Match(platform) {
			return true
		}
	}
	return false
}

// processRecipientKeys sorts the array of recipients by type. Recipients may be either
// x509 certificates, public keys, or PGP public keys identified by email address or name
func processRecipientKeys(recipients []string) ([][]byte, [][]byte, [][]byte, error) {
	var (
		gpgRecipients [][]byte
		pubkeys       [][]byte
		x509s         [][]byte
	)
	for _, recipient := range recipients {

		idx := strings.Index(recipient, ":")
		if idx < 0 {
			return nil, nil, nil, errors.New("Invalid recipient format")
		}

		protocol := recipient[:idx]
		value := recipient[idx+1:]

		switch protocol {
		case "pgp":
			gpgRecipients = append(gpgRecipients, []byte(value))
		case "jwe":
			tmp, err := ioutil.ReadFile(value)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Unable to read file")
			}
			if !encutils.IsPublicKey(tmp) {
				return nil, nil, nil, errors.New("File provided is not a public key")
			}
			pubkeys = append(pubkeys, tmp)

		case "pkcs7":
			tmp, err := ioutil.ReadFile(value)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Unable to read file")
			}
			if !encutils.IsCertificate(tmp) {
				return nil, nil, nil, errors.New("File provided is not an x509 cert")
			}
			x509s = append(x509s, tmp)

		default:
			return nil, nil, nil, errors.New("Provided protocol not recognized")
		}
	}
	return gpgRecipients, pubkeys, x509s, nil
}

// Process a password that may be in any of the following formats:
// - file=<passwordfile>
// - pass=<password>
// - fd=<filedescriptor>
// - <password>
func processPwdString(pwdString string) ([]byte, error) {
	if strings.HasPrefix(pwdString, "file=") {
		return ioutil.ReadFile(pwdString[5:])
	} else if strings.HasPrefix(pwdString, "pass=") {
		return []byte(pwdString[5:]), nil
	} else if strings.HasPrefix(pwdString, "fd=") {
		fdStr := pwdString[3:]
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse file descriptor %s", fdStr)
		}
		f := os.NewFile(uintptr(fd), "pwdfile")
		if f == nil {
			return nil, fmt.Errorf("%s is not a valid file descriptor", fdStr)
		}
		defer f.Close()
		pwd := make([]byte, 64)
		n, err := f.Read(pwd)
		if err != nil {
			return nil, errors.Wrapf(err, "could not read from file descriptor")
		}
		return pwd[:n], nil
	}
	return []byte(pwdString), nil
}

// processPrivateKeyFiles sorts the different types of private key files; private key files may either be
// private keys or GPG private key ring files. The private key files may include the password for the
// private key and take any of the following forms:
// - <filename>
// - <filename>:file=<passwordfile>
// - <filename>:pass=<password>
// - <filename>:fd=<filedescriptor>
// - <filename>:<password>
func processPrivateKeyFiles(keyFilesAndPwds []string) ([][]byte, [][]byte, [][]byte, [][]byte, error) {
	var (
		gpgSecretKeyRingFiles [][]byte
		gpgSecretKeyPasswords [][]byte
		privkeys              [][]byte
		privkeysPasswords     [][]byte
		err                   error
	)
	// keys needed for decryption in case of adding a recipient
	for _, keyfileAndPwd := range keyFilesAndPwds {
		var password []byte

		parts := strings.Split(keyfileAndPwd, ":")
		if len(parts) == 2 {
			password, err = processPwdString(parts[1])
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}

		keyfile := parts[0]
		tmp, err := ioutil.ReadFile(keyfile)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		isPrivKey, err := encutils.IsPrivateKey(tmp, password)
		if encutils.IsPasswordError(err) {
			return nil, nil, nil, nil, err
		}
		if isPrivKey {
			privkeys = append(privkeys, tmp)
			privkeysPasswords = append(privkeysPasswords, password)
		} else if encutils.IsGPGPrivateKeyRing(tmp) {
			gpgSecretKeyRingFiles = append(gpgSecretKeyRingFiles, tmp)
			gpgSecretKeyPasswords = append(gpgSecretKeyPasswords, password)
		} else {
			return nil, nil, nil, nil, fmt.Errorf("unidentified private key in file %s (password=%s)", keyfile, string(password))
		}
	}
	return gpgSecretKeyRingFiles, gpgSecretKeyPasswords, privkeys, privkeysPasswords, nil
}

func createGPGClient(context *cli.Context) (encryption.GPGClient, error) {
	return encryption.NewGPGClient(context.String("gpg-version"), context.String("gpg-homedir"))
}

func getGPGPrivateKeys(context *cli.Context, gpgSecretKeyRingFiles [][]byte, descs []ocispec.Descriptor, mustFindKey bool) (gpgPrivKeys [][]byte, gpgPrivKeysPwds [][]byte, err error) {
	gpgClient, err := createGPGClient(context)
	if err != nil {
		return nil, nil, err
	}

	var gpgVault encryption.GPGVault
	if len(gpgSecretKeyRingFiles) > 0 {
		gpgVault = encryption.NewGPGVault()
		err = gpgVault.AddSecretKeyRingDataArray(gpgSecretKeyRingFiles)
		if err != nil {
			return nil, nil, err
		}
	}
	return encryption.GPGGetPrivateKey(descs, gpgClient, gpgVault, mustFindKey)
}

func getImageLayerInfos(client *containerd.Client, ctx gocontext.Context, name string, layers []int32, platformList []string) ([]LayerInfo, []ocispec.Descriptor, error) {
	s := client.ImageService()

	image, err := s.Get(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	pl, err := parsePlatformArray(platformList)
	if err != nil {
		return nil, nil, err
	}

	alldescs, err := images.GetImageLayerDescriptors(ctx, client.ContentStore(), image.Target)
	if err != nil {
		return nil, nil, err
	}

	lis, descs := filterLayerDescriptors(alldescs, layers, pl)
	return lis, descs, nil
}

func countLayers(descs []ocispec.Descriptor, platform *ocispec.Platform) int32 {
	c := int32(0)

	for _, desc := range descs {
		if desc.Platform == platform {
			c = c + 1
		}
	}

	return c
}

func filterLayerDescriptors(alldescs []ocispec.Descriptor, layers []int32, pl []ocispec.Platform) ([]LayerInfo, []ocispec.Descriptor) {
	var (
		layerInfos  []LayerInfo
		descs       []ocispec.Descriptor
		curplat     *ocispec.Platform
		layerIndex  int32
		layersTotal int32
	)

	for _, desc := range alldescs {
		if curplat != desc.Platform {
			curplat = desc.Platform
			layerIndex = 0
			layersTotal = countLayers(alldescs, desc.Platform)
		} else {
			layerIndex = layerIndex + 1
		}

		if isUserSelectedLayer(layerIndex, layersTotal, layers) && isUserSelectedPlatform(curplat, pl) {
			li := LayerInfo{
				Index:      uint32(layerIndex),
				Descriptor: desc,
			}
			descs = append(descs, desc)
			layerInfos = append(layerInfos, li)
		}
	}
	return layerInfos, descs
}

// CreateDecryptCryptoConfig creates the CryptoConfig object that contains the necessary
// information to perform decryption from command line options and possibly
// LayerInfos describing the image and helping us to query for the PGP decryption keys
func CreateDecryptCryptoConfig(context *cli.Context, descs []ocispec.Descriptor) (encconfig.CryptoConfig, error) {
	ccs := []encconfig.CryptoConfig{}

	// x509 cert is needed for PKCS7 decryption
	_, _, x509s, err := processRecipientKeys(context.StringSlice("dec-recipient"))
	if err != nil {
		return encconfig.CryptoConfig{}, err
	}

	gpgSecretKeyRingFiles, gpgSecretKeyPasswords, privKeys, privKeysPasswords, err := processPrivateKeyFiles(context.StringSlice("key"))
	if err != nil {
		return encconfig.CryptoConfig{}, err
	}

	_, err = createGPGClient(context)
	gpgInstalled := err == nil
	if gpgInstalled {
		if len(gpgSecretKeyRingFiles) == 0 && len(privKeys) == 0 && descs != nil {
			// Get pgp private keys from keyring only if no private key was passed
			gpgPrivKeys, gpgPrivKeyPasswords, err := getGPGPrivateKeys(context, gpgSecretKeyRingFiles, descs, true)
			if err != nil {
				return encconfig.CryptoConfig{}, err
			}

			gpgCc, err := encconfig.DecryptWithGpgPrivKeys(gpgPrivKeys, gpgPrivKeyPasswords)
			if err != nil {
				return encconfig.CryptoConfig{}, err
			}
			ccs = append(ccs, gpgCc)

		} else if len(gpgSecretKeyRingFiles) > 0 {
			gpgCc, err := encconfig.DecryptWithGpgPrivKeys(gpgSecretKeyRingFiles, gpgSecretKeyPasswords)
			if err != nil {
				return encconfig.CryptoConfig{}, err
			}
			ccs = append(ccs, gpgCc)

		}
	}

	x509sCc, err := encconfig.DecryptWithX509s(x509s)
	if err != nil {
		return encconfig.CryptoConfig{}, err
	}
	ccs = append(ccs, x509sCc)

	privKeysCc, err := encconfig.DecryptWithPrivKeys(privKeys, privKeysPasswords)
	if err != nil {
		return encconfig.CryptoConfig{}, err
	}
	ccs = append(ccs, privKeysCc)

	return encconfig.CombineCryptoConfigs(ccs), nil
}

// parsePlatformArray parses an array of specifiers and converts them into an array of specs.Platform
func parsePlatformArray(specifiers []string) ([]ocispec.Platform, error) {
	var speclist []ocispec.Platform

	for _, specifier := range specifiers {
		spec, err := platforms.Parse(specifier)
		if err != nil {
			return []ocispec.Platform{}, err
		}
		speclist = append(speclist, spec)
	}
	return speclist, nil
}
