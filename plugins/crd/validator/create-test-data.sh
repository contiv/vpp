#!/usr/bin/env bash

NODES=()
declare -A NODE_IP_ADDRESSES

get_data() {
    data=$( curl -s "$1$VPP_DUMP_PFX$2"| python -mjson.tool | sed -e 's|    |\t|g' | sed -e 's/\(^[\t}].*$\)/\t\t\t\1/')
    echo "$data"
}

VSWITCHES=$( kubectl get pods -o wide --all-namespaces | grep "contiv-vswitch" )
readarray -t VSWITCH_LINES <<< "$VSWITCHES"
for l in "${VSWITCH_LINES[@]}"
do
    IFS=' ' read -ra NODE_FIELDS <<< "$l"
    NODE="${NODE_FIELDS[7]}"
    NODES+=("$NODE")
    NODE_IP_ADDRESSES["$NODE"]="${NODE_FIELDS[6]}"
done

# for K in "${!NODE_IP_ADDRESSES[@]}"; do echo $K --- ${NODE_IP_ADDRESSES[$K]}; done

VT_RAW_DATA=$'package validator

type rawValidatorData map[string]map[string]string

func createTestData() *rawValidatorData {
\treturn &rawValidatorData{
'

VPP_DUMP_PFX=":9999/vpp/dump/v1/"
for nn in "${NODES[@]}"
do
    echo "$nn"
    IP_ADDR=${NODE_IP_ADDRESSES[$nn]}
    VT_RAW_DATA+=$'\t\t"'"$nn"$'": {\n'
    LIVENESS=$( curl -s "$IP_ADDR":9999/liveness | python -mjson.tool | sed -e 's|    |\t|g' | sed -e 's/\(^[\t}].*$\)/\t\t\t\1/')

    INTERFACES=$( get_data "$IP_ADDR" "interfaces" )
    BD=$( get_data "$IP_ADDR" "bd" )
    L2FIB=$( get_data "$IP_ADDR" "fib" )
    ARPS=$( get_data "$IP_ADDR" "arps" )
    ROUTES=$( get_data "$IP_ADDR" "routes" )

    VT_RAW_DATA+=$( printf "\t\t\t\"liveness\": \`%s\`,\n" "$LIVENESS" )
    VT_RAW_DATA+=$( printf "\n\t\t\t\"interfaces\": \`%s\`,\n" "$INTERFACES" )
    VT_RAW_DATA+=$( printf "\n\t\t\t\"bridgedomains\": \`%s\`,\n" "$BD" )
    VT_RAW_DATA+=$( printf "\n\t\t\t\"l2fib\": \`%s\`,\n" "$L2FIB" )
    VT_RAW_DATA+=$( printf "\n\t\t\t\"arps\": \`%s\`,\n" "$ARPS" )
    VT_RAW_DATA+=$( printf "\n\t\t\t\"routes\": \`%s\`,\n" "$ROUTES" )

    VT_RAW_DATA+=$'\n\t\t},\n'
done

VT_RAW_DATA+=$'\t}\n}'

echo "$VT_RAW_DATA"
echo "$VT_RAW_DATA" > rawdata_test.go