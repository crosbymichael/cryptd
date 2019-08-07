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
	"github.com/containerd/typeurl"
	"github.com/crosbymichael/cryptd"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
)

// UnmarshalLayerToolDecryptData unmarshals a byte array to LayerToolDecryptData
func UnmarshalLayerToolDecryptData(decryptData []byte) (*cryptd.ProcessorPayload, error) {
	var pb types.Any

	if err := proto.Unmarshal(decryptData, &pb); err != nil {
		return nil, errors.Wrapf(err, "could not proto.Unmarshal() decrypt data")
	}
	v, err := typeurl.UnmarshalAny(&pb)
	if err != nil {
		return nil, errors.Wrapf(err, "could not UnmarshalAny() the decrypt data")
	}

	data, ok := v.(*cryptd.ProcessorPayload)
	if !ok {
		return nil, errors.Errorf("received an unknown data type '%s'", pb.TypeUrl)
	}
	return data, nil
}
