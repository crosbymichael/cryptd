package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "cryptd"
	app.Version = "1"
	app.Usage = "containerd crypto tools"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output in the logs",
		},
	}
	app.Before = func(clix *cli.Context) error {
		if clix.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	app.Commands = []cli.Command{
		encryptCommand,
		decryptCommand,
		streamCommand,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ImageDecryptionFlags are cli flags needed when decrypting an image
var ImageDecryptionFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "gpg-homedir",
		Usage: "The GPG homedir to use; by default gpg uses ~/.gnupg",
	}, cli.StringFlag{
		Name:  "gpg-version",
		Usage: "The GPG version (\"v1\" or \"v2\"), default will make an educated guess",
	}, cli.StringSliceFlag{
		Name:  "key",
		Usage: "A secret key's filename and an optional password separated by colon; this option may be provided multiple times",
	}, cli.StringSliceFlag{
		Name:  "dec-recipient",
		Usage: "Recipient of the image; used only for PKCS7 and must be an x509 certificate",
	},
}
