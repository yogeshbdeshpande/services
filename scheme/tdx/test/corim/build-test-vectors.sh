#!/bin/bash
# Copyright 2022-2024 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -eu
set -o pipefail

THIS_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
GEN_CORIM="$THIS_DIR/../../../common/scripts/gen-corim"

PROFILE="2.16.840.1.113741.1.16.1"
SUBATTESTERS=(
	tdx_platform
	tdx_td
)

CORIM_TD_TEMPLATES=(
	corimTdxTd
)

COMID_TD_TEMPLATES=(
	comidTdxTd
)

CORIM_PLATFORM_TEMPLATES=(
	corimTdxPlatform
)

COMID_PLATFORM_TEMPLATES=(
	comidTdxModule
	comidQe
    comidPce
)

# function to generate test vectors for the supplied CCA Platform or Realm
# $1 passed argument whose templates needs to be constructed
generate_templates() {
	local sub_at=$1

	echo "generating templates for subattester $sub_at"

	if [ "$sub_at" == "tdx_platform" ]; then
		COMID_TEMPLATES=("${COMID_PLATFORM_TEMPLATES[@]}")
		CORIM_TEMPLATES=("${CORIM_PLATFORM_TEMPLATES[@]}")
	else
		COMID_TEMPLATES=("${COMID_TD_TEMPLATES[@]}")
		CORIM_TEMPLATES=("${CORIM_TD_TEMPLATES[@]}")
	fi

	for corim in "${CORIM_TEMPLATES[@]}"
	do
		for comid in "${COMID_TEMPLATES[@]}"
		do
			"$GEN_CORIM" "$THIS_DIR" "$comid" "$corim" "unsigned" "$PROFILE"
		done
	done

}

for at in "${SUBATTESTERS[@]}"
do
	generate_templates "$at"
done

echo "done"
