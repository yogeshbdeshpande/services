// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"errors"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/scheme/common"
)

// EndorsementHandler implements the IEndorsementHandler interface for SEVSNP scheme
type EndorsementHandler struct{}

// Init initializes the endorsement handler instance. no-op for SEVSNP
func (o EndorsementHandler) Init(params handler.EndorsementHandlerParams) error {
	return nil // no-op
}

// Close closes the endorsement handler instance. no-op for SEVSNP
func (o EndorsementHandler) Close() error {
	return nil // no-op
}

// GetName returns the name of the endorsement handler
func (o EndorsementHandler) GetName() string {
	return SchemeName
}

// GetAttestationScheme returns the scheme name
func (o EndorsementHandler) GetAttestationScheme() string {
	return SchemeName
}

// GetSupportedMediaTypes returns the media types supported for SEVSNP endorsements
func (o EndorsementHandler) GetSupportedMediaTypes() []string {
	return EndorsementMediaTypes
}

// Decode decodes the supplied endorsement as an unsigned CoRIM
func (o EndorsementHandler) Decode(data []byte, mediaType string, caCertPool []byte) (*handler.EndorsementHandlerResponse, error) {
	// Provide support for UnsignedCoRIM first
	extractor := &Extractor{}

	// Default to unsigned CoRIM decoder
	return common.UnsignedCorimDecoder(data, extractor)
}

func (o EndorsementHandler) CoservRepackage(coservQuery string, resultSet []string) ([]byte, error) {
	return nil, errors.New("TDX CoservRepackage not implemented")
}
