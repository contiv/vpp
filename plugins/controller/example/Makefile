all: build

build:
	go build .

run:
	INITIAL_LOGLVL=debug ./example --bolt-config=bolt.conf --etcd-config=etcd.conf --controller-config=controller.conf --http-config=http.conf
