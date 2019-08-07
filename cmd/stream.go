package main

import (
	"io"
	"os"
	"syscall"

	"github.com/containerd/containerd/cmd/ctr-layertool/commands/utils"
	"github.com/containerd/containerd/pkg/encryption"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var streamCommand = cli.Command{
	Name: "stream",
	Action: func(clix *cli.Context) error {
		var (
			layerInFd  = syscall.Stdin
			layerOutFd = syscall.Stdout
		)

		decryptData, err := utils.ReadDecryptData()
		if err != nil {
			return errors.Wrapf(err, "could not read config data")
		}

		layerOutFile := os.NewFile(uintptr(layerOutFd), "layerOutFd")
		if layerOutFile == nil {
			return errors.Errorf("layer output file descriptor %d is invalid", layerOutFd)
		}
		defer layerOutFile.Close()

		layerInFile := os.NewFile(uintptr(layerInFd), "layerInFd")
		if layerInFile == nil {
			return errors.Errorf("layer input file descriptor %d is invalid", layerInFd)
		}
		defer layerInFile.Close()

		ltd, err := utils.UnmarshalLayerToolDecryptData(decryptData)
		if err != nil {
			return err
		}

		_, plainLayerReader, _, err := encryption.DecryptLayer(&ltd.DecryptConfig, layerInFile, ltd.Descriptor, false)
		if err != nil {
			return errors.Wrapf(err, "call to DecryptLayer failed")
		}

		for {
			_, err := io.CopyN(layerOutFile, plainLayerReader, 10*1024)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "could not copy data")
			}
		}
		return nil
	},
}
