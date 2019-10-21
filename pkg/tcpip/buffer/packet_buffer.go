// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buffer

// A PacketBuffer contains all the data of a network packet.
type PacketBuffer struct {
	// Data holds the payload of the packet. For inbound packets, it also holds
	// all the headers, which are consumed as the packet moves up the stack.
	Data VectorisedView

	// Unparsed hold the same information as Data. For inbound packets, it is

	// Headers holds the link, network, and transport headers of outbound
	// packets.
	Headers Prependable

	// All of the below are slices within Data.
	LinkHeader      View
	NetworkHeader   View
	TransportHeader View
	Payload         View
}
