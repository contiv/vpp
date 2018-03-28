#!/bin/bash

set -e

IFS='
'

function vppctl {
    IP=$1
    shift
	echo -e "\n$@\n" | netcat -q 1 $IP 5002
}

function print_packet {
    echo -e "Packet $1:"
    echo -e $2
    echo -e ""
}

function print_help_and_exit {
    echo "Usage: $0  -i <VPP-IF-TYPE> [-a <VPP-ADDRESS>] [-r] [-f <REGEXP> / <SUBSTRING>]"
    echo '   -i <VPP-IF-TYPE> : VPP interface *type* to run the packet capture on (e.g. dpdk-input, virtio-input, etc.)'
    echo '                       - available aliases:'
    echo '                         - af-packet-input: afpacket, af-packet, veth'
    echo '                         - virtio-input: tap (version determined from the VPP config), tap2, tapv2'
    echo '                         - tapcli-rx: tap (version determined from the VPP config), tap1, tapv1'
    echo '                         - dpdk-input: dpdk, gbe, phys*'
    echo '   -a <VPP-ADDRESS> : IP address or hostname of the VPP to capture packets from'
    echo '                      - default = 127.0.0.1'
    echo '   -r               : apply filter string (passed with -f) as a regexp expression'
    echo '                      - by default the filter is NOT treated as regexp'
    echo '   -f               : filter string that packet must contain (without -r) or match as regexp (with -r) to be printed'
    echo '                      - default is no filtering'
    exit 1
}

function trace {
    VPPADDR="127.0.0.1"
    INTERFACE=$1

    while getopts i:a:rf:h option
    do
        case "${option}"
            in
            i) INTERFACE=${OPTARG};;
            a) VPPADDR=${OPTARG};;
            r) IS_REGEXP=1;;
            f) FILTER=${OPTARG};;
            h) print_help_and_exit;;
        esac
    done

    # afpacket aliases
    if [[ "$INTERFACE" == "afpacket" ]] || [[ "$INTERFACE" == "af-packet" ]] || [[ "$INTERFACE" == "veth" ]]; then
        INTERFACE="af-packet-input"
    fi

    # tapv1 + tapv2 alias
    if [[ "$INTERFACE" == "tap" ]]; then
        # find out the version of the tap used
        if vppctl $VPPADDR show interface | grep -q tapcli; then
            INTERFACE="tapcli-rx"
        else
            INTERFACE="virtio-input"
        fi
    fi

    # tapv1 aliases
    if [[ "$INTERFACE" == "tap1" ]] || [[ "$INTERFACE" == "tapv1" ]]; then
        INTERFACE="tapcli-rx"
    fi

    # tapv2 aliases
    if [[ "$INTERFACE" == "tap2" ]] || [[ "$INTERFACE" == "tapv2" ]]; then
        INTERFACE="virtio-input"
    fi

    # dpdk aliases
    if [[ "$INTERFACE" == "dpdk" ]] || [[ "$INTERFACE" == "gbe" ]] || [[ "$INTERFACE" == "phys"* ]]; then
        INTERFACE="dpdk-input"
    fi

    COUNT=0
    while true; do
        vppctl $VPPADDR clear trace >/dev/null
        vppctl $VPPADDR trace add $INTERFACE 50 >/dev/null

        IDX=0
        while true; do
            TRACE=`vppctl $IP show trace`
            STATE=0
            PACKET=""
            PACKETIDX=0

            for LINE in $TRACE; do
                if [[ $STATE -eq 0 ]]; then
                    # looking for "Packet <number>" of the first unconsumed packet
                    if [[ "$LINE" =~ ^Packet[[:space:]]([0-9]+) ]]; then
                        PACKETIDX=${BASH_REMATCH[1]}
                        if [[ $PACKETIDX -gt $IDX ]]; then
                            STATE=1
                            IDX=$PACKETIDX
                        fi
                    fi
                elif [[ $STATE -eq 1 ]]; then
                    # looking for the start of the packet trace
                    if ! [[ "${LINE}" =~ ^[[:space:]]$ ]]; then
                        # found line with non-whitespace character
                        STATE=2
                        PACKET="$LINE"
                    fi
                else
                    # consuming packet trace
                    if [[ "${LINE}" =~ ^[[:space:]]$ ]]; then
                        # end of the trace
                        if [[ -n "${PACKET// }" ]]; then
                            if ([[ -n $IS_REGEXP ]] && [[ "$PACKET" =~ "$FILTER" ]]) || \
                                ([[ -z $IS_REGEXP ]] && [[ "$PACKET" == *"$FILTER"* ]]); then
                                COUNT=$((COUNT+1))
                                print_packet $COUNT "$PACKET"
                            fi
                        fi
                        PACKET=""
                        STATE=0
                    else
                        PACKET="$PACKET\n$LINE"
                    fi
                fi
            done
            if [[ -n "${PACKET// }" ]]; then
                if ([[ -n $IS_REGEXP ]] && [[ "$PACKET" =~ "$FILTER" ]]) || \
                    ([[ -z $IS_REGEXP ]] && [[ "$PACKET" == *"$FILTER"* ]]); then
                    COUNT=$((COUNT+1))
                    print_packet $COUNT "$PACKET"
                fi
            fi
            if [[ $PACKETIDX -gt 35 ]]; then
                echo -e "\nClearing packet trace (some packets may slip uncaptured)..."
                break;
            fi

            sleep 0.2
        done
    done
}

if [[ $# -lt 1 ]]; then
    print_help_and_exit
fi

trace $@
