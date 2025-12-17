// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/uuid"
	"github.com/veraison/cmw"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/proto"
)

// comidFromJson accepts a CoRIM in JSON format and returns its first CoMID
//
//	Returns error if there are more than a single CoMID, or passes on
//	error from corim routine.
func comidFromJson(buf []byte) (*comid.Comid, error) {
	extractedCorim, err := corim.UnmarshalUnsignedCorimFromJSON(buf)
	if err != nil {
		return nil, err
	}

	if len(extractedCorim.Tags) > 1 {
		return nil, errors.New("too many tags")
	}

	extractedComid, err := corim.UnmarshalComidFromCBOR(
		extractedCorim.Tags[0].Content,
		extractedCorim.Profile,
	)

	if err != nil {
		return nil, err
	}

	return extractedComid, nil
}

// measurementByUintKey looks up comid.Measurement in a CoMID by its MKey.
//
//	If no measurements are found, returns nil and no error. Otherwise,
//	returns the error encountered.
func measurementByUintKey(refVal comid.ValueTriple,
	key uint64) (*comid.Measurement, error) {
	for _, m := range refVal.Measurements.Values {
		if m.Key == nil || !m.Key.IsSet() ||
			m.Key.Type() != comid.UintType {
			continue
		}

		k, err := m.Key.GetKeyUint()
		if err != nil {
			return nil, err
		}

		if k == key {
			return &m, nil
		}
	}

	return nil, nil
}

func parseAttestationToken(token *proto.AttestationToken) (*tokens.TSMReport, error) {
	var (
		err           error
		tsm           = new(tokens.TSMReport)
		cmwCollection cmw.CMW
	)

	switch token.MediaType {
	case EvidenceMediaTypeRATSd:
		eat := make(map[string]interface{})

		err = json.Unmarshal(token.Data, &eat)
		if err != nil {
			return nil, err
		}

		cmwBase64, _ := eat["cmw"].(string)

		cmwJson, err := base64.StdEncoding.DecodeString(cmwBase64)
		if err != nil {
			return nil, err
		}

		err = cmwCollection.UnmarshalJSON(cmwJson)
		if err != nil {
			return nil, err
		}

		cmwMonad, err := cmwCollection.GetCollectionItem("tsm-report")
		if err != nil {
			return nil, err
		}

		cmwType, err := cmwMonad.GetMonadType()
		if err != nil {
			return nil, err
		}
		if cmwType != "application/vnd.veraison.configfs-tsm+json" {
			return nil, fmt.Errorf("unexpected CMW type: %s", cmwType)
		}
		cmwValue, err := cmwMonad.GetMonadValue()
		if err != nil {
			return nil, err
		}

		err = tsm.FromJSON(cmwValue)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected media type: %s", token.MediaType)
	}

	return tsm, nil
}

// reportToCoMID takes a tdReport and converts the same into a CoMID
func reportToCoMID(reportproto any) (*comid.Comid, error) {
	refValComid := comid.NewComid().
		SetLanguage("en-GB").
		SetTagIdentity(uuid.New(), 0)

	if reportproto == nil {
		return nil, errors.New("no report included")
	}

	reportV4 := reportproto.(*pb.QuoteV4)
	refValTriple, err := translateTdxPlatformToCoMIDTriple(reportV4, refValComid)
	if err != nil {
		return nil, fmt.Errorf("unable to extract Tdx platform from quote: %w", err)
	}
	refValComid.AddReferenceValue(refValTriple)

	refValTriple, err = translateQEReportToCoMIDTriple(reportV4, refValComid)
	if err != nil {
		return nil, fmt.Errorf("unable to extract qe report from quote: %w", err)
	}
	refValComid.AddReferenceValue(refValTriple)

	refValTriple, err = translateTDReportToCoMIDTriple(reportV4, refValComid)
	if err != nil {
		return nil, fmt.Errorf("unable to extract qe report from quote: %w", err)
	}
	refValComid.AddReferenceValue(refValTriple)

	return refValComid, nil
}

func translateTdxPlatformToCoMIDTriple(quote *pb.QuoteV4, m *comid.Comid) (*comid.ValueTriple, error) {
	if quote == nil {
		return nil, errors.New("no quote supplied")
	}
	if m == nil {
		return nil, errors.New("no comid supplied")
	}

	// Extract TEE_TCB_SVN from the Quote
	// Extract MRSEAM from the Quote
	// Extract SEAMATTRIBUTES from the Quote

	return nil, nil
}

func translateTDReportToCoMIDTriple(quote *pb.QuoteV4, m *comid.Comid) (*comid.ValueTriple, error) {
	if quote == nil {
		return nil, errors.New("no quote supplied")
	}
	if m == nil {
		return nil, errors.New("no comid supplied")
	}

	return nil, nil
}

func translateQEReportToCoMIDTriple(quote *pb.QuoteV4, m *comid.Comid) (*comid.ValueTriple, error) {
	// Get QEReportCertificationData

	// Using the QEReportCertificationData variable call the method GetQeReport()
	// var qe tdx.EnclaveReport
	// Extract MrEnclave from the QE_Report
	// Extract MISC-SELECT from the QE-Report
	// Extract ISV ProdID from the QE-Report
	// Get the QE Vendor ID from Quote Header : It must be: 33729a93-9cf7-a94c-940a-0db3957f0607
	return nil, nil
}

/*
func translatePCEToCoMIDTriple(token *proto.AttestationToken) (*comid.ValueTriple, error) {

	return nil, nil

}
For now there will no be any PCE Report, but everything is folded to TdxPlatform Report
*
*/
