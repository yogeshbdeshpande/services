// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/uuid"
	"github.com/veraison/cmw"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/comid/tdx"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/extensions"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/log"
	"github.com/veraison/services/proto"
	"github.com/veraison/swid"
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
	qb := quote.GetTdQuoteBody()

	env := comid.Environment{}
	measurement := &comid.Measurement{}
	env.Class = comid.NewClassBytes(qb.MrSeam)
	meas := comid.NewMeasurements()
	refVal := &comid.ValueTriple{
		Environment:  env,
		Measurements: *meas,
	}

	extMap := extensions.NewMap().Add(comid.ExtMval, &tdx.MValExtensions{})

	if err := measurement.Val.RegisterExtensions(extMap); err != nil {
		log.Fatal("could not register mval extensions")
	}

	// Set the Extensions now, here!!
	val := &measurement.Val

	// Extract TEE_TCB_SVN, MRSEAM and SEAMATTRIBUTES from the Quote
	svns := covertTeeTcbSvnToUintSvns(qb.TeeTcbSvn)
	c, err := tdx.NewTeeTcbCompSvnUint(svns)
	if err != nil {
		return nil, fmt.Errorf("failed to get TeeTcbCompSvn: %w", err)
	}
	err = val.Set("tcbcompsvn", c)
	if err != nil {
		return nil, fmt.Errorf("unable to set teetcbcompsvn: %w", err)
	}

	if len(qb.MrSeam) != 48 {
		return nil, fmt.Errorf("invalid len %d for MrSeam", len(qb.MrSeam))
	}
	dTee := comid.NewDigests()
	dTee.AddDigest(swid.Sha384, qb.MrSeam)
	ts, err := tdx.NewTeeDigest(*dTee)
	if err != nil {
		return nil, fmt.Errorf("unable to get TeeDigest: %w", err)
	}
	err = val.Set("mrtee", ts)
	if err != nil {
		return nil, fmt.Errorf("unable to set mrtee %w", err)
	}

	seamAttr := qb.SeamAttributes

	teeAttr, err := tdx.NewTeeAttributes(seamAttr)
	if err != nil {
		return nil, fmt.Errorf("unable to get teeAttributes: %w", err)
	}
	err = val.Set("attributes", teeAttr)
	if err != nil {
		return nil, fmt.Errorf("unable to set attributes: %w", err)
	}

	refVal.Measurements.Add(measurement)
	m.Triples.AddReferenceValue(refVal)

	return refVal, nil
}

func translateTDReportToCoMIDTriple(quote *pb.QuoteV4, m *comid.Comid) (*comid.ValueTriple, error) {
	if quote == nil {
		return nil, errors.New("no quote supplied")
	}
	if m == nil {
		return nil, errors.New("no comid supplied")
	}
	qb := quote.GetTdQuoteBody()

	env := comid.Environment{}
	measurement := &comid.Measurement{}
	mrtd := qb.MrTd
	env.Class = comid.NewClassBytes(mrtd)
	meas := comid.NewMeasurements()
	refVal := &comid.ValueTriple{
		Environment:  env,
		Measurements: *meas,
	}

	extMap := extensions.NewMap().Add(comid.ExtMval, &tdx.MValExtensions{})

	if err := measurement.Val.RegisterExtensions(extMap); err != nil {
		log.Fatal("could not register mval extensions")
	}

	// Set the Extensions now, here!!
	val := &measurement.Val
	if len(mrtd) != 48 {
		return nil, fmt.Errorf("invalid len %d for MrTd", len(mrtd))
	}
	dTee := comid.NewDigests()
	dTee.AddDigest(swid.Sha384, mrtd)
	ts, err := tdx.NewTeeDigest(*dTee)
	if err != nil {
		return nil, fmt.Errorf("unable to get TeeDigest: %w", err)
	}
	err = val.Set("mrtee", ts)
	if err != nil {
		return nil, fmt.Errorf("unable to set mrtee %w", err)
	}

	// Set XFAM as RawValue
	var mask []byte
	xfam := qb.GetXfam()
	measurement.SetRawValueBytes(xfam, mask)

	// Set TD Attributes
	tdAttr := qb.TdAttributes
	teeAttr, err := tdx.NewTeeAttributes(tdAttr)
	if err != nil {
		return nil, fmt.Errorf("unable to get td attributes: %w", err)
	}
	err = val.Set("attributes", teeAttr)
	if err != nil {
		return nil, fmt.Errorf("unable to set td attributes: %w", err)
	}

	refVal.Measurements.Add(measurement)
	rtmrs := qb.GetRtmrs()

	for index, rtmr := range rtmrs {
		if len(rtmr) != 48 {
			return nil, fmt.Errorf("invalid length %d for rtmr at index %d", len(rtmr), index)
		}
		switch index {
		case 0:
			/* MKey 0: RTMR0 */
			m0, err := comid.NewMeasurement("RTMR0", comid.StringType)
			if err != nil {
				return nil, err
			}
			m0.AddDigest(swid.Sha384, rtmr)
			// Set RTMR0 Digest here
			refVal.Measurements.Add(m0)
		case 1:
			/* MKey 1: RTMR1 */
			m1, err := comid.NewMeasurement("RTMR1", comid.StringType)
			if err != nil {
				return nil, err
			}
			m1.AddDigest(swid.Sha384, rtmr)
			refVal.Measurements.Add(m1)
		case 2:
			/* MKey 2: RTMR2 */
			m2, err := comid.NewMeasurement("RTMR2", comid.StringType)
			if err != nil {
				return nil, err
			}
			m2.AddDigest(swid.Sha384, rtmr)
			refVal.Measurements.Add(m2)
		case 3:
			/* MKey 3: RTMR3 */
			m3, err := comid.NewMeasurement("RTMR3", comid.StringType)
			if err != nil {
				return nil, err
			}
			m3.AddDigest(swid.Sha384, rtmr)
			refVal.Measurements.Add(m3)
		default:
			return nil, errors.New("rtmrs cannot be more than 4")
		}
	}

	m.Triples.AddReferenceValue(refVal)
	// Verify the values assigned by the creator of the TD are as expected: MROWNER and MROWNERCONFIG
	// Verify the software assigned ID MRCONFIGID
	// Verify the measurement of the initial contents of the TD: MRTD
	// Verify TDATTRIBUTES
	// Verify kernel measurements provided in RTMR[0] and RTMR[1]
	// By convention, RTMR[0] and RTMR[1] are updated by the TD virtual firmware/BIOS (TDVF).
	// The measurements and the log file may differ depending on the TDVF vendor.
	// For more information on the measurements in RTMR[0] and RTMR[1], contact your TDVF vendor.
	// Verify any expected runtime generated measurements in RTMR[2] and RTMR[3]

	return refVal, nil
}

func translateQEReportToCoMIDTriple(quote *pb.QuoteV4, m *comid.Comid) (*comid.ValueTriple, error) {
	rep, err := getQEReportFromQuote(quote)
	if err != nil {
		return nil, err
	}
	// Get QEReportCertificationData
	mrEnclave := rep.GetMrEnclave()   // This is important
	miscSelect := rep.GetMiscSelect() // This is important
	isvsvn := rep.GetIsvSvn()         // This is important

	// Get Enclave Report ID - ISVProdID
	pid := rep.GetIsvProdId()

	// Get QE Vendor ID from Quote Header..
	env := comid.Environment{}
	measurement := &comid.Measurement{}

	env.Class = comid.NewClassBytes(mrEnclave)
	meas := comid.NewMeasurements()
	refVal := &comid.ValueTriple{
		Environment:  env,
		Measurements: *meas,
	}

	extMap := extensions.NewMap().Add(comid.ExtMval, &tdx.MValExtensions{})
	if err := measurement.Val.RegisterExtensions(extMap); err != nil {
		log.Fatal("could not register mval extensions")
	}
	// Set the Extensions now, here!!
	val := &measurement.Val

	if len(mrEnclave) != 32 {
		return nil, fmt.Errorf("invalid len %d for mrEnclave", len(mrEnclave))
	}

	dE := comid.NewDigests()
	dE.AddDigest(swid.Sha256, mrEnclave)
	ts, err := tdx.NewTeeDigest(*dE)
	if err != nil {
		return nil, fmt.Errorf("unable to get TeeDigest: %w", err)
	}
	err = val.Set("mrtee", ts)
	if err != nil {
		return nil, fmt.Errorf("unable to set mrtee %w", err)
	}

	// Set the MISC_SELECT
	ms := make([]byte, 4)
	binary.BigEndian.PutUint32(ms, miscSelect)
	msel := tdx.NewTeeMiscSelect(ms)
	err = val.Set("miscselect", msel)
	if err != nil {
		return nil, fmt.Errorf("unable to set miscselect: %w", err)
	}

	//TO DO, support base uint32 type in ISVProdID in tdx package
	isvprodID, err := tdx.NewTeeISVProdID(uint(pid))
	if err != nil {
		return nil, fmt.Errorf("unable to get isvprodID: %w", err)
	}

	err = val.Set("isvprodid", isvprodID)
	if err != nil {
		return nil, fmt.Errorf("unable to set isvprodid: %w", err)
	}

	svn, err := tdx.NewSvnUint(uint(isvsvn))
	if err != nil {
		return nil, fmt.Errorf("unable to get isvsvn uint: %w", err)
	}

	err = val.Set("isvsvn", svn)
	if err != nil {
		return nil, fmt.Errorf("unable to set isvsvn: %w", err)
	}
	refVal.Measurements.Add(measurement)
	m.Triples.AddReferenceValue(refVal)
	// Using the QEReportCertificationData variable call the method GetQeReport()
	// var qe tdx.EnclaveReport
	// Extract MrEnclave from the QE_Report
	// Extract MISC-SELECT from the QE-Report
	// Extract ISV ProdID from the QE-Report
	// Get the QE Vendor ID from Quote Header : It must be: 33729a93-9cf7-a94c-940a-0db3957f0607
	// Set the Vendor ID as Environment for Enclave Report
	return refVal, nil
}

func getQEReportFromQuote(quote *pb.QuoteV4) (*pb.EnclaveReport, error) {
	sd := quote.GetSignedData()
	if sd == nil {
		return nil, errors.New("signed Data is nil")
	}
	cd := sd.GetCertificationData()
	if cd == nil {
		return nil, errors.New("certification data is nil")
	}
	qc := cd.GetQeReportCertificationData()
	if qc == nil {
		return nil, errors.New("qe report certification data is nil")
	}
	rep := qc.GetQeReport()
	if rep == nil {
		return nil, errors.New("enclave report is nil")
	}
	return rep, nil
}

func covertTeeTcbSvnToUintSvns(tcbsvn []byte) []uint {
	var svns []uint
	svns = make([]uint, len(tcbsvn))
	for i, svn := range tcbsvn {
		svns[i] = uint(svn)
	}
	return svns
}
