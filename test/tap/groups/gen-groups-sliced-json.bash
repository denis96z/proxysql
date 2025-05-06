#!/usr/bin/env bash

# make sure we have correct cwd
pushd $(dirname $0) > /dev/null

SLICES=4

GRPS=$(ls -d */ | grep -Pv '\-slice\d+' | sort | xargs basename -a)
TESTS=$(ls -1 ../tests/*-t | sort | xargs basename -a)
TESTS+=$(ls -1 ../tests_with_deps/deprecate_eof_support/*-t | sort | xargs basename -a)


NUM=0
COUNT=$(echo ${TESTS} | wc -w)

echo "{" > groups.json
for T in ${TESTS}; do
	SLICE=$(((NUM/((COUNT/SLICES)+1))+1))
	G=$(echo "${GRPS}" | xargs -I{} echo -n "\"{}-slice${SLICE}\",")
	echo "  \""$T"\" : [ ${G%,} ]," >> groups.json
	((NUM++))
done
sed -i '$ s/.$//' groups.json
echo "}" >> groups.json

