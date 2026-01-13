// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ear"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/log"
	"github.com/veraison/services/proto"
)

var (
	ErrNoARK                 = errors.New("missing ARK certificate in evidence")
	ErrNoASK                 = errors.New("missing ASK certificate in evidence")
	ErrNoVEK                 = errors.New("evidence must supply VLEK or VCEK")
	ErrNoVCEK                = errors.New("VCEK is missing")
	ErrNoVLEK                = errors.New("VLEK is missing")
	ErrTAMismatch            = errors.New("evidence Trust Anchor (ARK) doesn't match the provisioned one")
	ErrNoProvisionedTA       = errors.New("missing provisioned Trust Anchor")
	ErrNoProvisionedRV       = errors.New("reference value unavailable for attester")
	ErrBadSigningKey         = errors.New("bad signing key in attestation report")
	ErrMismatchedReportedTCB = errors.New("reported TCB in evidence doesn't match reference")
	ErrReferenceMissingSVN   = errors.New("reference doesn't have SVN")
	ErrEvidenceMissingSVN    = errors.New("evidence doesn't have SVN")
)

const (
	ReportSigningKeyVcek = 0
	ReportSigningKeyVlek = 1
)

// EvidenceHandler implements the IEvidenceHandler interface for TDX
type EvidenceHandler struct {
}

// GetName returns the name of this evidence handler instance
func (o EvidenceHandler) GetName() string {
	return "tdx-evidence-handler"
}

// GetAttestationScheme returns the attestation scheme
func (o EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

// GetSupportedMediaTypes returns the supported media types for the TDX scheme
func (o EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func transformEvidenceToCorim(token *proto.AttestationToken) (*corim.UnsignedCorim, error) {
	tsm, err := parseAttestationToken(token)
	if err != nil {
		return nil, err
	}

	reportProto, err := abi.QuoteToProto(tsm.OutBlob)
	if err != nil {
		return nil, err
	}

	evComid, err := reportToCoMID(reportProto)
	if err != nil {
		return nil, err
	}

	err = evComid.Valid()
	if err != nil {
		return nil, err
	}

	evCorim := corim.UnsignedCorim{}
	evCorim.SetProfile(EndorsementMediaType)
	evCorim.AddComid(evComid)

	return &evCorim, nil

}

// ExtractClaims converts evidence in tsm-report format to our
// "internal representation", which is in CoRIM format.
func (o EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	_ []string,
) (map[string]interface{}, error) {
	var claimsSet map[string]interface{}

	evCorim, err := transformEvidenceToCorim(token)
	if err != nil {
		return nil, err
	}

	evJson, err := evCorim.ToJSON()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(evJson, &claimsSet)
	if err != nil {
		return nil, err
	}

	return claimsSet, nil
}

func extractProvisionedTA(trustAnchors []string) (*comid.CryptoKey, error) {
	var (
		taEndorsement *handler.Endorsement
		avk           comid.KeyTriple
	)

	for i, t := range trustAnchors {
		var endorsement handler.Endorsement

		if err := json.Unmarshal([]byte(t), &endorsement); err != nil {
			return nil, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		if endorsement.Type == handler.EndorsementType_VERIFICATION_KEY {
			taEndorsement = &endorsement
			break
		}
	}

	if taEndorsement == nil {
		return nil, handler.BadEvidence(ErrNoProvisionedTA)
	}

	err := json.Unmarshal(taEndorsement.Attributes, &avk)
	if err != nil {
		return nil, err
	}

	// The StoreHandler takes care of ensuring that only one TA is
	// supplied, we don't have to re-check it here.
	provisionedArk := avk.VerifKeys[0]

	return provisionedArk, nil
}

func validateCertificateChain(certChain any) error {

	return nil
}

func validateTA(certChain any, provisionedArk *comid.CryptoKey) error {

	return nil
}

func validateReportIntegrity(tsm *tokens.TSMReport, certChain any) error {

	return nil
}

func validateSessionNonce(tsm *tokens.TSMReport, sessionNonce []byte) error {
	var evNonce []byte
	reportProto, err := abi.QuoteToProto(tsm.OutBlob)
	if err != nil {
		return err
	}
	reportV4 := reportProto.(*pb.QuoteV4)
	rep, err := getQEReportFromQuote(reportV4)
	if err != nil {
		return err
	}
	evNonce = rep.GetReportData()
	if !bytes.Equal(evNonce, sessionNonce) {
		return handler.BadEvidence(fmt.Errorf("nonce in the evidence doesn't match the session nonce. evidence: 0x%x vs session: 0x%x", evNonce, sessionNonce))
	}

	return nil
}

// ValidateEvidenceIntegrity confirms the integrity of evidence by doing the following:
//   - verifies that the TA in the evidence matches the provisioned TA
//   - confirms the integrity of the certificate chain
//   - validates the integrity of evidence by checking its signature
func (o EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchors []string,
	_ []string,
) error {
	// TO DO We need correct Options, else the RawTdxQuote API will Fail
	var opts validate.Options
	var opt verify.Options

	// First Obtain Bytes of TDX Quote in Raw Format, Check if we need any Tag Removal etc.
	// Get Quote from the Attestation Token
	rawQuote := token.Data
	// Check if its a Valid Quite-V4 ..?
	err := validate.RawTdxQuote(rawQuote, &opts)
	if err != nil {
		return fmt.Errorf("invalid RawTDXQuote: %w", err)
	}
	// I assume the Root CA Certificate will be avaialable in the Trust Anchor
	if err := verify.TdxQuote(rawQuote, &opt); err != nil {
		return fmt.Errorf("could not verify the signature on the quote: %w", err)
	}
	return nil
}

// refvalToComidTriple converts extracted reference values, in Endorsement Strings to
// to CoMID value triples one per each Target Environment
func refvalToComidTriples(endorsementsStrings []string) (*comid.ValueTriples, error) {
	var (
		refValEndorsement *handler.Endorsement
		rv                comid.ValueTriple
	)
	refVals := comid.NewValueTriples()

	for i, e := range endorsementsStrings {
		var endorsement handler.Endorsement

		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return nil, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		if endorsement.Type == handler.EndorsementType_REFERENCE_VALUE {
			refValEndorsement = &endorsement
			err := json.Unmarshal(refValEndorsement.Attributes, &rv)
			if err != nil {
				return nil, err
			}
			// Great we have extracted a Single RefVal Triple, lets add it to the list
			refVals.Add(&rv)
		}
	}

	if len(refVals.Values) != 3 {
		return nil, fmt.Errorf("expecting three RefVals, SEAM, Enclave and TD however got: %d", len(refVals.Values))
	}
	return refVals, nil
}

// evidenceToComidTriples converts claim set to a seqeunce of ValueTriples
func evidenceToComidTriples(ec *proto.EvidenceContext) (*comid.ValueTriples, error) {
	evCorimJson, err := json.Marshal(ec.Evidence.AsMap())
	if err != nil {
		return nil, err
	}

	evComid, err := comidFromJson(evCorimJson)
	if err != nil {
		return nil, err
	}

	return evComid.Triples.ReferenceValues, nil
}

// compareMeasurements checks if two given comid.Measurement variables are equal.
func compareMeasurements(refM comid.Measurement, evM comid.Measurement) bool {
	// RawValue comparison
	if refM.Val.RawValue != nil {
		if evM.Val.RawValue == nil {
			return false
		}

		refDigest, _ := refM.Val.RawValue.GetBytes()
		return evM.Val.RawValue.CompareAgainstReference(refDigest, nil)
	}

	// Digests comparison
	if refM.Val.Digests != nil {
		if evM.Val.Digests == nil {
			return false
		}

		return evM.Val.Digests.CompareAgainstReference(*refM.Val.Digests)
	}

	// SVN comparison
	if refM.Val.SVN != nil {
		if evM.Val.SVN == nil {
			log.Debugf("evidence doesn't have SVN")
			return false
		}

		if c, ok := evM.Val.SVN.Value.(*comid.TaggedSVN); ok {
			if r, ok := refM.Val.SVN.Value.(*comid.TaggedSVN); ok {
				return c.CompareAgainstRefSVN(*r)
			} else if r, ok := refM.Val.SVN.Value.(*comid.TaggedMinSVN); ok {
				return c.CompareAgainstRefMinSVN(*r)
			} else {
				log.Debugf("unknown refVal SVN type")
				return false
			}
		} else if c, ok := evM.Val.SVN.Value.(*comid.TaggedMinSVN); ok {
			if r, ok := refM.Val.SVN.Value.(*comid.TaggedMinSVN); ok {
				return c.Equal(*r)
			}
			log.Debugf("can't compare TaggedMinSVN against TaggedSVN")
			return false
		} else {
			log.Debugf("unknown evidence SVN type")
			return false
		}
	}

	return true
}

func compareTcb(refM comid.Measurement, evM comid.Measurement) bool {

	return true
}

// AppraiseEvidence confirms if the claims in the evidence match with the provisioned
// reference values.
//
// Appraisal can confirm if the evidence is genuinely generated by AMD
// hardware and if SEV-SNP enables memory encryption. As such, set the
// "Hardware" and "RuntimeOpaque" values in the trustworthiness vector;
// we can't infer other aspects of the vector from SEV-SNP evidence alone.
func (o EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsStrings []string,
) (*ear.AttestationResult, error) {
	var (
		err error
	)

	refVals, err := refvalToComidTriples(endorsementsStrings)
	if err != nil {
		return nil, err
	}

	evTriples, err := evidenceToComidTriples(ec)
	if err != nil {
		return nil, err
	}

	schemeList := []string{"TDXSEAM", "Enclave", "TDVM"}
	result := handler.CreateAttestationResult(schemeList[0])
	for _, scheme := range schemeList {
		verifier := getVerifier(scheme)
		rv, err := getTripleforEnvironment(scheme, refVals)
		if err != nil {
			return nil, err
		}

		ev, err := getTripleforEnvironment(scheme, evTriples)
		if err != nil {
			return nil, err
		}

		appraisal, err := Appraise(verifier, ev, rv)
		if err != nil {
			return nil, err
		}
		result.Submods[scheme] = appraisal
	}

	return result, err
}

func getVerifier(model string) IVerifier {
	switch model {
	case "TDX_SEAM":
		return &SeamVerifier{}
	case "TDX_ENCLAVE":
		return &EnclaveVerifier{}
	case "TDX_VM":
		return &TdVmVerifier{}
	default:
		return nil
	}

}
func getTripleforEnvironment(model string, ref *comid.ValueTriples) (*comid.ValueTriple, error) {
	if ref == nil {
		return nil, errors.New("nil value triples")
	}
	if ref.IsEmpty() {
		return nil, errors.New("no triples exist")
	}
	if err := ref.Valid(); err != nil {
		return nil, fmt.Errorf("error in triples validity: %w", err)
	}
	for _, rv := range ref.Values {
		model := rv.Environment.Class.GetModel()
		switch model {
		case "TDX_SEAM":
			if strings.Contains(model, "SEAM") || strings.Contains(model, "TDXSEAM") {
				return &rv, nil
			}
		case "TDX_ENCLAVE":
			if strings.Contains(model, "QE") || strings.Contains(model, "Quoting Enclave") {
				return &rv, nil
			}
		case "TDX_VM":
			if strings.Contains(model, "TD_VM") || strings.Contains(model, "TD") {
				return &rv, nil
			}
		default:
			return nil, fmt.Errorf("invalid model: %s supplied", model)
		}
	}
	return nil, fmt.Errorf("unable to get the correct triples")
}

func Appraise(verifier IVerifier, ev *comid.ValueTriple, refv *comid.ValueTriple) (*ear.Appraisal, error) {
	return verifier.PerformAppraisal(ev, refv)
}
