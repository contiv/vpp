package main

import (
	"context"
	"log"

	"google.golang.org/grpc"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

const (
	stnServer = ":50051"
)

// grpcConnect sets up a connection to the gRPC stnServer specified in grpcServer argument
// as a stnServer:port tuple (e.g. "localhost:9111").
func grpcConnect(grpcServer string) (*grpc.ClientConn, stn.STNClient, error) {
	conn, err := grpc.Dial(grpcServer, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}
	return conn, stn.NewSTNClient(conn), nil
}

func main() {
	// connect to the STN GRPC server
	conn, c, err := grpcConnect(stnServer)
	if err != nil {
		return
	}
	defer conn.Close()

	// TODO: this is currently just a boilerplate code that steals a hardcoded interface

	reply, err := c.StealInterface(context.Background(), &stn.STNRequest{
		InterfaceName: "enp0s9",
	})

	log.Println(reply)
}
