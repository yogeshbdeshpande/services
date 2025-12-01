// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tdx

/*
The profile identifier for the Intel Profile is the OID:

{joint-iso-itu-t(2) country(16) us(840) organization(1) intel(113741) (1) intel-comid(16) profile(1)}

2.16.840.1.113741.1.16.1
*/
const (
	SchemeName           = "TDX"
	EndorsementMediaType = `application/rim+cbor;profile="2.16.840.1.113741.1.16.1"`
	// TO DO As per Intel Profile document, the same profile for Endorsement and Evidence is suggested,so using the same profile for now!
	EvidenceMediaTypeRATSd = `application/eat+cwt; eat_profile="2.16.840.1.113741.1.16.1"`
)

var (
	EndorsementMediaTypes = []string{
		EndorsementMediaType,
	}

	EvidenceMediaTypes = []string{
		EvidenceMediaTypeRATSd,
	}
)

const (
	mKeyPolicy           = 2
	mKeyCurrentTcb       = 6
	mKeyPlatformInfo     = 7
	mKeyReportData       = 640
	mKeyMeasurement      = 641
	mKeyReportID         = 645
	mKeyReportIDMA       = 646
	mKeyReportedTcb      = 647
	mKeyChipID           = 3328
	mKeyCommittedTcb     = 3329
	mKeyCurrentVersion   = 3330
	mKeyCommittedVersion = 3936
	mKeyLaunchTcb        = 3968
)
