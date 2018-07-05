#!/bin/bash

# Contiv network connectivity report.

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
    echo "-d <report-dir>     Directory with the unzipped bug report created by the "
    echo "                    'cont-vpp-bug-report.sh' script."
    echo
    echo "-h                  Show this help message."
    echo
    echo "-p                  Show previous log (if it exists)."
    echo
    echo "-s <search-string>  Search lhe logs for this string. If not specified,"
    echo "                    the default search string 'level=error' is used."
    echo
}

get_log_file_name() {
    for file in "$1"/{.*,*}
    do
        if LOG_FILE_NAME=$( echo "$file" | grep "$2" ) && [ -n "$LOG_FILE_NAME" ]
        then
            echo "$LOG_FILE_NAME"
            return
        fi
    done
}

NODE_NAMES=()
NODES_FILE="k8s-nodes.txt"
VSWITCH_LOG="contiv-vswitch.log"
VSWITCH_PREVIOUS_LOG="contiv-vswitch-previous.log"
SEARCH_STRING="level=error\\|SIGABRT"
SHOW_PREVIOUS=0

while getopts "d:hnps:" opt
do
    case "$opt" in
    d)  REPORT_DIR=$OPTARG
        ;;
    h)
        usage
        exit 0
        ;;
    p)  SHOW_PREVIOUS=1
        ;;
    s)  SEARCH_STRING=$OPTARG
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

pushd "$REPORT_DIR" > /dev/null

# Get all nodes in the cluster and their host IP addresses
NODES=$( grep -v "NAME " < "$NODES_FILE" )
readarray -t NODE_LINES <<< "$NODES"

for l in "${NODE_LINES[@]}"
do
    IFS=' ' read -ra NODE_FIELDS <<< "$l"
    NODE_NAMES+=("${NODE_FIELDS[0]}")
done

for nn in "${NODE_NAMES[@]}"
do
    # Print node header
    printf "%s:\\n" "$nn"
    printf '%0.s=' $( seq 1 $(( ${#nn} + 1 )) )
    echo

    VSWITCH_LOG_FILE_NAME=$( get_log_file_name "$nn" "$VSWITCH_LOG" )
    if [ -n "$VSWITCH_LOG_FILE_NAME" ]
    then
        echo "Vswitch log:"
        echo "------------"
        grep -n "$SEARCH_STRING" < "$VSWITCH_LOG_FILE_NAME" || true
    else
        echo "Logfile for contiv-vswitch not present."
    fi
    echo

    if [ "$SHOW_PREVIOUS" == "1" ]
    then
        VSWITCH_LOG_FILE_NAME=$( get_log_file_name "$nn" "$VSWITCH_PREVIOUS_LOG" )
        if [ -n "$VSWITCH_LOG_FILE_NAME" ]
        then
            echo "Previous vswitch log:"
            echo "---------------------"
            grep -n "$SEARCH_STRING" < "$VSWITCH_LOG_FILE_NAME"
        else
            echo "Previous logfile for contiv-vswitch not present."
        fi
        echo
    fi
done