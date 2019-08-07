package main

import (
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/defaults"
	"github.com/crosbymichael/cryptd"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var encryptCommand = cli.Command{
	Name: "encrypt",
	Flags: append([]cli.Flag{
		cli.StringFlag{
			Name:  "recipient",
			Usage: "Recipient of the image is the person who can decrypt it in the form specified above (i.e. jwe:/path/to/key)",
		},
		cli.IntSliceFlag{
			Name:  "layer",
			Usage: "The layer to encrypt; this must be either the layer number or a negative number starting with -1 for topmost layer",
		},
		cli.StringSliceFlag{
			Name:  "platform",
			Usage: "For which platform to encrypt; by default encrytion is done for all platforms",
		},
	},
		ImageDecryptionFlags...),
	Action: func(clix *cli.Context) error {
		local := context.Args().First()
		if local == "" {
			return errors.New("please provide the name of an image to encrypt")
		}

		newName := context.Args().Get(1)
		if newName != "" {
			fmt.Printf("Encrypting %s to %s\n", local, newName)
		}
		ctx := context.Background()
		ctdClient, err := containerd.New(defaults.DefaultAddress)
		if err != nil {
			return err
		}

		image, err := ctdClient.GetImage(ctx, local)
		if err != nil {
			return err
		}

		recipients := context.StringSlice("recipient")
		if len(recipients) == 0 {
			return errors.New("no recipients given -- nothing to do")
		}
		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		gpgRecipients, pubKeys, x509s, err := processRecipientKeys(recipients)
		if err != nil {
			return err
		}

		encryptCcs := []encconfig.CryptoConfig{}
		_, err = createGPGClient(context)
		gpgInstalled := err == nil

		if len(gpgRecipients) > 0 && gpgInstalled {
			gpgClient, err := createGPGClient(context)
			if err != nil {
				return err
			}

			gpgPubRingFile, err := gpgClient.ReadGPGPubRingFile()
			if err != nil {
				return err
			}

			gpgCc, err := encconfig.EncryptWithGpg(gpgRecipients, gpgPubRingFile)
			if err != nil {
				return err
			}
			encryptCcs = append(encryptCcs, gpgCc)

		}

		// Create Encryption Crypto Config
		pkcs7Cc, err := encconfig.EncryptWithPkcs7(x509s)
		if err != nil {
			return err
		}
		encryptCcs = append(encryptCcs, pkcs7Cc)

		jweCc, err := encconfig.EncryptWithJwe(pubKeys)
		if err != nil {
			return err
		}
		encryptCcs = append(encryptCcs, jweCc)

		cc := encconfig.CombineCryptoConfigs(encryptCcs)

		_, descs, err := getImageLayerInfos(ctdClient, ctx, local, layers32, context.StringSlice("platform"))
		if err != nil {
			return err
		}

		// Create Decryption CryptoConfig for use in adding recipients to
		// existing image if decryptable.
		decryptCc, err := CreateDecryptCryptoConfig(context, descs)
		if err != nil {
			return err
		}
		cc.EncryptConfig.AttachDecryptConfig(decryptCc.DecryptConfig)

		client := cryptd.New(ctdClient)
		_, err = client.EncryptImage(ctx, image, newName, cc, cryptd.WithPlatforms(clix.StringSlice("platform")), cryptd.WithLayers(layers32))
		return err

	},
}
