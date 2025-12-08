// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tdx

import _ "embed"

var (

	//go:embed test/corim/unsignedCorimTdxPlatformComidTdxModule.cbor
	unsignedCorimTdxPlatformModule []byte

	//go:embed test/corim/unsignedCorimTdxTdComidTdxTd.cbor
	unsignedCorimTdxTd []byte
)
