// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

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
	// TO DO Complete this
	return nil, nil
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

func validateCertificateChain(certChain *tdx.CertificationData) error {

	return nil
}

func validateTA(certChain *tdx.CertificateChain, provisionedArk *comid.CryptoKey) error {
	if !bytes.Equal(certChain.GetArkCert(), []byte(provisionedArk.String())) {
		return handler.BadEvidence(ErrTAMismatch)
	}

	return nil
}

func validateReportIntegrity(tsm *tokens.TSMReport, certChain *tdx.CertificateChain) error {

	return nil
}

func validateSessionNonce(tsm *tokens.TSMReport, sessionNonce []byte) error {
	var evNonce []byte
	reportProto, err := abi.QuoteToProto(tsm.OutBlob)
	if err != nil {
		return err
	}
	reportV4 := reportProto.(*pb.QuoteV4)
	certdata := reportV4.GetSignedData().GetCertificationData()
	qedata := certdata.GetQeReportCertificationData()
	if qedata.QeReport != nil {
		evNonce = qedata.QeReport.ReportData
	}

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
	/*
		opts :=
		&Options{
					HeaderOptions: HeaderOptions{
						MinimumQeSvn:  qeSvn,
						MinimumPceSvn: pceSvn,
						QeVendorID:    qeVendorID,
					},
					TdQuoteBodyOptions: TdQuoteBodyOptions{
						MinimumTeeTcbSvn:   teeTcbSvn,
						MrSeam:             mrSeam,
						TdAttributes:       tdAttributes,
						Xfam:               xfam,
						MrTd:               mrTd,
						MrConfigID:         mrConfigID,
						MrOwner:            mrOwner,
						MrOwnerConfig:      mrOwnerConfig,
						Rtmrs:              [][]byte{rtmr0, rtmr1, rtmr2, rtmr3},
						ReportData:         reportData,
						EnableTdDebugCheck: true,
					},
				},
	*/
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

// refvalToComidTriple converts extracted reference values to CoMID value triple
func refvalToComidTriple(endorsementsStrings []string) (*comid.ValueTriple, error) {
	var (
		refValEndorsement *handler.Endorsement
		rv                comid.ValueTriple
	)

	for i, e := range endorsementsStrings {
		var endorsement handler.Endorsement

		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return nil, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		if endorsement.Type == handler.EndorsementType_REFERENCE_VALUE {
			refValEndorsement = &endorsement
			break
		}
	}

	if refValEndorsement == nil {
		return nil, handler.BadEvidence(ErrNoProvisionedRV)
	}

	err := json.Unmarshal(refValEndorsement.Attributes, &rv)
	if err != nil {
		return nil, err
	}

	return &rv, nil
}

// evidenceToComidTriple converts claim set to CoMID value triple
func evidenceToComidTriple(ec *proto.EvidenceContext) (*comid.ValueTriple, error) {
	evCorimJson, err := json.Marshal(ec.Evidence.AsMap())
	if err != nil {
		return nil, err
	}

	evComid, err := comidFromJson(evCorimJson)
	if err != nil {
		return nil, err
	}

	return &evComid.Triples.ReferenceValues.Values[0], nil
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
	if refM.Val.SVN == nil {
		log.Errorf("%w", ErrReferenceMissingSVN)
		return false
	}

	if evM.Val.SVN == nil {
		log.Errorf("%w", ErrEvidenceMissingSVN)
		return false
	}

	refTcbParts, err := transformSVNtoTCB(*refM.Val.SVN)
	if err != nil {
		log.Errorf("could not transform reference SVN to TCB parts: %v", err)
		return false
	}

	evTcbParts, err := transformSVNtoTCB(*evM.Val.SVN)
	if err != nil {
		log.Errorf("could not transform evidence SVN to TCB parts: %v", err)
	}

	if evTcbParts.BlSpl < refTcbParts.BlSpl ||
		evTcbParts.SnpSpl < refTcbParts.SnpSpl ||
		evTcbParts.TeeSpl < refTcbParts.TeeSpl ||
		evTcbParts.UcodeSpl < refTcbParts.UcodeSpl {
		return false
	}

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
		err         error
		evidenceMap map[string]interface{}
	)

	refVal, err := refvalToComidTriple(endorsementsStrings)
	if err != nil {
		return nil, err
	}

	evidence, err := evidenceToComidTriple(ec)
	if err != nil {
		return nil, err
	}

	result := handler.CreateAttestationResult(SchemeName)

	appraisal := result.Submods[SchemeName]

	// Init TrustVector to default values
	appraisal.TrustVector.InstanceIdentity = ear.NoClaim
	appraisal.TrustVector.Executables = ear.NoClaim
	appraisal.TrustVector.Configuration = ear.NoClaim
	appraisal.TrustVector.FileSystem = ear.NoClaim
	appraisal.TrustVector.StorageOpaque = ear.NoClaim
	appraisal.TrustVector.SourcedData = ear.NoClaim
	appraisal.TrustVector.Hardware = ear.UnsafeHardwareClaim
	appraisal.TrustVector.RuntimeOpaque = ear.VisibleMemoryRuntimeClaim

claimsLoop:
	for _, m := range refVal.Measurements.Values {
		var (
			k  uint64
			em *comid.Measurement
		)

		k, err = m.Key.GetKeyUint()
		if err != nil {
			break
		}

		// We can skip validating certain claims for the following reasons:
		// - POLICY ToDo: Do we need to test individual policy features?
		// - CURRENT_TCB is informational only. It's best handled by policy
		// - PLATFORM_INFO ToDO: Do we need to test individual platform features?
		// - REPORT_DATA is a nonce supplied by user for freshness. It's used
		//       for freshness verification, and verified as part of
		//       evidence integrity check (session nonce check).
		// - REPORT_ID is ephemeral, so we can't use it for verification.
		// - REPORT_ID_MA is also ephemeral, used for migration
		// - CHIP_ID is unique to an specific attester, but reference values could be used more generally
		// - Current Version (CURRENT_MAJOR/MINOR/BUILD) should already be part of REPORTED_TCB.
		//     ToDo: It is a good idea to test it anyway, but the Version type only tests for
		//     equality, and this would trigger spurious failures
		// - COMMITTED_TCB is informational, used by the host to advance REPORTED_TCB
		if k == mKeyPolicy ||
			k == mKeyCurrentTcb ||
			k == mKeyPlatformInfo ||
			k == mKeyReportData ||
			k == mKeyReportID ||
			k == mKeyReportIDMA ||
			k == mKeyChipID ||
			k == mKeyCommittedTcb ||
			k == mKeyCurrentVersion ||
			k == mKeyCommittedVersion {
			continue
		}

		em, err = measurementByUintKey(*evidence, k)
		if err != nil {
			break
		}

		if em == nil {
			err = fmt.Errorf("MKey %d not found in Evidence", k)
			break
		}

		switch k {
		case mKeyReportedTcb:
			if !compareTcb(m, *em) {
				err = ErrMismatchedReportedTCB
				break claimsLoop
			}
		case mKeyLaunchTcb:
			reportedTcb, err := measurementByUintKey(*evidence, mKeyReportedTcb)
			if err != nil {
				break claimsLoop
			}
			if !compareTcb(*reportedTcb, *em) {
				// ToDo: Is this a failure condition?
				log.Errorf("TEE launched with older TCB version")
			}
		default:
			if !compareMeasurements(m, *em) {
				err = fmt.Errorf("MKey %d in reference value doesn't match with evidence", k)
				break claimsLoop
			}
		}
	}

	if err == nil {
		appraisal.TrustVector.Hardware = ear.GenuineHardwareClaim
		appraisal.TrustVector.RuntimeOpaque = ear.EncryptedMemoryRuntimeClaim
	}

	appraisal.UpdateStatusFromTrustVector()

	evidenceJson, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(evidenceJson, &evidenceMap)
	if err != nil {
		return nil, err
	}

	appraisal.VeraisonAnnotatedEvidence = &evidenceMap

	return result, err
}
