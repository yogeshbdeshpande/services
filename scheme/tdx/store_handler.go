// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/veraison/corim/comid"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

var (
	ErrMissingMeasurement          = errors.New("measurement not found")
	ErrARKDecodeFailure            = errors.New("failed to decode ARK")
	ErrUnsupportedMultipleEvidence = errors.New("unable to process multiple evidence in a single request")
)

// StoreHandler implements the IStoreHandler interface handler for SEVSNP scheme
type StoreHandler struct{}

// GetName returns the name of this StoreHandler instance
func (s StoreHandler) GetName() string {
	return fmt.Sprintf("%s-store-handler", SchemeName)
}

// GetAttestationScheme returns the attestation scheme
func (s StoreHandler) GetAttestationScheme() string {
	return SchemeName
}

// GetSupportedMediaTypes returns the supported media types; no-op for SEVSNP
func (s StoreHandler) GetSupportedMediaTypes() []string {
	return nil
}

// getRefValKey helper to compute RefVal key from CoMID value triple
func getRefValKey(rv comid.ValueTriple, tenantID string) (string, error) {
	var classID []byte
	env := rv.Environment
	if err := env.Valid(); err != nil {
		return "", fmt.Errorf("invalid environment %w", err)
	}
	if env.Class != nil {
		return "", errors.New("invalid class parameter")

	}
	if err := env.Class.Valid(); err != nil {
		return "", fmt.Errorf("invalid class %w", err)
	}
	classID = env.Class.ClassID.Bytes()

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   hex.EncodeToString(classID),
	}

	return u.String(), nil
}

// SynthKeysFromRefValue constructs TDX reference value of the form
// "TDX://<tenantID>/<classID>". The classID
// is unique to an tagrte environment and, as such, is
// the best candidate to use as the key.
func (s StoreHandler) SynthKeysFromRefValue(
	tenantID string,
	refValue *handler.Endorsement,
) ([]string, error) {
	var rv comid.ValueTriple

	err := json.Unmarshal(refValue.Attributes, &rv)
	if err != nil {
		return nil, err
	}

	refValKey, err := getRefValKey(rv, tenantID)
	if err != nil {
		return nil, err
	}

	return []string{refValKey}, nil
}

// SynthKeysFromTrustAnchor constructs the TDX Trust Anchor key. The
// key format is "TDX://<keyname>". For example, "TDX://Intel-RootKey"
//
// Intel's Root Key (IRK) is the only Trust Anchor for TDX.
//
// The attester supplies all the keys in the certificate chain
// for verification. During verification, the scheme must ensure that
// the IRK in the Evidence matches the provisioned Trust Anchor.
func (s StoreHandler) SynthKeysFromTrustAnchor(_ string, ta *handler.Endorsement) ([]string, error) {
	var avk comid.KeyTriple

	err := json.Unmarshal(ta.Attributes, &avk)
	if err != nil {
		return nil, err
	}

	ark := avk.VerifKeys[0]

	keyBlock, _ := pem.Decode([]byte(ark.String()))
	if keyBlock == nil || keyBlock.Type != "CERTIFICATE" {
		return nil, ErrARKDecodeFailure
	}

	cert, err := x509.ParseCertificate(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	u := url.URL{
		Scheme: SchemeName,
		Path:   cert.Issuer.CommonName,
	}

	return []string{u.String()}, nil
}

// GetTrustAnchorIDs gets the TA ID from evidence
//
// "auxblob" in the TSM report contains a certificate
// table. Extract ARK from it and construct the TA key.
func (s StoreHandler) GetTrustAnchorIDs(token *proto.AttestationToken) ([]string, error) {
	var (
		name string = "abcd"
	)

	u := url.URL{
		Scheme: SchemeName,
		Path:   name,
	}

	return []string{u.String()}, nil
}

// GetRefValueIDs gets the refval keys from the claims set. Looks up
// RefValue Triples associated with TDX CoMID and extracts the Keys
//
// Reference value key for TDX is of the form
// "TDX://<tenantID>/<classID>", for each target envionment
// For TDX there are three target environments
// 1.TDX Seam Module 2. TDX Quoting Enclave 3. TD VM
func (s StoreHandler) GetRefValueIDs(
	tenantID string,
	_ []string,
	claims map[string]interface{},
) ([]string, error) {
	var rvKeys []string

	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	extractedComid, err := comidFromJson(claimsJson)
	if err != nil {
		return nil, err
	}
	rvs := extractedComid.Triples.ReferenceValues

	if len(extractedComid.Triples.ReferenceValues.Values) > 3 {
		return nil, ErrUnsupportedMultipleEvidence
	}

	for _, rv := range rvs.Values {
		refValKey, err := getRefValKey(rv, tenantID)
		if err != nil {
			return nil, fmt.Errorf("getRefValKeyError %w", err)
		}
		rvKeys = append(rvKeys, refValKey)
	}

	if err != nil {
		return nil, err
	}

	return rvKeys, nil
}

func (s StoreHandler) SynthCoservQueryKeys(tenantID string, query string) ([]string, error) {
	return []string{"TODO"}, nil
}
