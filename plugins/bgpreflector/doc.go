// Package bgpreflector reflects BGP routes installed in the host system's network stack
// (default network namespace) into VPP.
//
// For now it only reflects the routes installed by the Bird daemon (https://bird.network.cz/)
// - routes with the protocol number 12, as defined in /etc/iproute2/rt_protos
package bgpreflector
