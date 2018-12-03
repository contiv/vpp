VERSION := $(shell git describe --always --tags --dirty)
COMMIT  := $(shell git rev-parse HEAD)
DATE    := $(shell date +'%Y-%m-%dT%H:%M%:z')

CNINFRA_AGENT := github.com/contiv/vpp/vendor/github.com/ligato/cn-infra/agent
LDFLAGS = -s -w -X $(CNINFRA_AGENT).BuildVersion=$(VERSION) -X $(CNINFRA_AGENT).CommitHash=$(COMMIT) -X $(CNINFRA_AGENT).BuildDate=$(DATE)

COVER_DIR ?= /tmp/

# Build commands
build: contiv-agent contiv-ksr contiv-crd contiv-cni contiv-stn contiv-init contiv-netctl

# Run all
all: lint build test install

# Build agent
contiv-agent:
	@echo "# building contiv-agent"
	cd cmd/contiv-agent && go build -v -i -ldflags "${LDFLAGS}" -tags="${GO_BUILD_TAGS}"

# Build contiv-ksr
contiv-ksr:
	@echo "# building contiv-ksr"
	cd cmd/contiv-ksr && go build -v -i -ldflags "${LDFLAGS}"

# Build contiv-crd
contiv-crd:
	@echo "# building contiv-crd"
	cd cmd/contiv-crd && go build -v -i -ldflags "${LDFLAGS}"

# Build contiv-cni
contiv-cni:
	@echo "# building contiv-cni"
	cd cmd/contiv-cni && go build -v -i -ldflags "-linkmode external -extldflags -static"

# Build contiv-stn
contiv-stn:
	@echo "# building contiv-stn"
	cd cmd/contiv-stn && go build -v -i -ldflags '-s -w -X main.BuildVersion=$(VERSION) -X main.BuildDate=$(DATE)'

# Build contiv-init
contiv-init:
	@echo "# building contiv-init"
	cd cmd/contiv-init && go build -v -i -ldflags "${LDFLAGS}" -tags="${GO_BUILD_TAGS}"

# Build contiv-netctl
contiv-netctl:
	@echo "# building contiv-init"
	cd cmd/contiv-netctl && go build -v -i -ldflags "${LDFLAGS}" -tags="${GO_BUILD_TAGS}"

# Install commands
install:
	@echo "# installing commands"
	cd cmd/contiv-agent && go install -v -ldflags "${LDFLAGS}" -tags="${GO_BUILD_TAGS}"
	cd cmd/contiv-ksr && go install -v -ldflags "${LDFLAGS}"
	cd cmd/contiv-crd && go install -v -ldflags "${LDFLAGS}"
	cd cmd/contiv-cni && go install -v -ldflags "${LDFLAGS}"
	cd cmd/contiv-stn && go install -v -ldflags "${LDFLAGS}"
	cd cmd/contiv-init && go install -v -ldflags "${LDFLAGS}"
	cd cmd/contiv-netctl && go install -v -ldflags "${LDFLAGS}"

# Clean commands
clean:
	@echo "# cleaning binaries"
	rm -f cmd/contiv-agent/contiv-agent
	rm -f cmd/contiv-cni/contiv-cni
	rm -f cmd/contiv-ksr/contiv-ksr
	rm -f cmd/contiv-crd/contiv-crd
	rm -f cmd/contiv-stn/contiv-stn
	rm -f cmd/contiv-init/contiv-init
	rm -f cmd/contiv-netctl/contiv-netctl

# Run tests
test:
	@echo "# running unit tests"
	go test ./cmd/contiv-cni -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ipv4net -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ipv4net/ipam -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ksr -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/configurator -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/renderer/cache -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/renderer/acl -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/namespaceidx -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/podidx -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/policyidx -tags="${GO_BUILD_TAGS}"
	go test ./plugins/statscollector -tags="${GO_BUILD_TAGS}"
	go test ./plugins/service -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/datastore -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/validator/l2 -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/validator/l3 -tags="${GO_BUILD_TAGS}"
	#go test ./plugins/crd/cache -tags="${GO_BUILD_TAGS}"

# Run tests with race
test-race:
	@echo "# running unit tests with -race"
	go test ./cmd/contiv-cni -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ipv4net -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ipv4net/ipam -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/ksr -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/configurator -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/renderer/cache -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/renderer/acl -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/namespaceidx -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/podidx -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/policy/cache/policyidx -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/statscollector -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/service -race -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/datastore -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/validator/l2 -tags="${GO_BUILD_TAGS}"
	go test ./plugins/crd/validator/l3 -tags="${GO_BUILD_TAGS}"
	#go test ./plugins/crd/cache -tags="${GO_BUILD_TAGS}"


# Get coverage report tools
get-covtools:
	go install -v ./vendor/github.com/wadey/gocovmerge

# Run coverage report
test-cover: get-covtools
	@echo "# running unit tests with coverage analysis"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u1.out ./cmd/contiv-cni -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u2.out ./plugins/ipv4net -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u3.out ./plugins/ipv4net/ipam -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u6.out ./plugins/ksr -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u7.out ./plugins/policy/configurator -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u8.out ./plugins/policy/renderer/cache -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u9.out ./plugins/policy/renderer/acl -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u11.out -coverpkg=./plugins/service/processor,./plugins/service/configurator ./plugins/service -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u12.out ./plugins/policy/cache -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u13.out ./plugins/policy/cache/namespaceidx -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u14.out ./plugins/policy/cache/podidx -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u15.out ./plugins/policy/cache/policyidx -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u16.out ./plugins/statscollector -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u17.out ./plugins/crd/datastore -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u18.out ./plugins/crd/validator/l2 -tags="${GO_BUILD_TAGS}"
	go test -covermode=count -coverprofile=${COVER_DIR}cov_u19.out ./plugins/crd/validator/l3 -tags="${GO_BUILD_TAGS}"
	#go test -covermode=count -coverprofile=${COVER_DIR}cov_u20.out ./plugins/crd/cache -tags="${GO_BUILD_TAGS}"

	@echo "# merging coverage results"
	gocovmerge \
			${COVER_DIR}cov_u1.out \
			${COVER_DIR}cov_u2.out \
			${COVER_DIR}cov_u3.out \
			${COVER_DIR}cov_u6.out \
			${COVER_DIR}cov_u7.out \
			${COVER_DIR}cov_u8.out \
			${COVER_DIR}cov_u9.out \
			${COVER_DIR}cov_u11.out \
			${COVER_DIR}cov_u12.out \
			${COVER_DIR}cov_u13.out \
			${COVER_DIR}cov_u14.out \
			${COVER_DIR}cov_u15.out \
			${COVER_DIR}cov_u16.out \
			${COVER_DIR}cov_u17.out \
			${COVER_DIR}cov_u18.out \
			${COVER_DIR}cov_u19.out \
		> ${COVER_DIR}coverage.out
	@echo "# coverage data generated into ${COVER_DIR}coverage.out"

# Run coverage report with HTML output
test-cover-html: test-cover
	go tool cover -html=${COVER_DIR}coverage.out -o ${COVER_DIR}coverage.html
	@echo "# coverage report generated into ${COVER_DIR}coverage.html"

# Run coverage report with XML output
test-cover-xml: test-cover
	gocov convert ${COVER_DIR}coverage.out | gocov-xml > ${COVER_DIR}coverage.xml
	@echo "# coverage report generated into ${COVER_DIR}coverage.xml"

# Get generator tools
get-generators:
	go install -v ./vendor/github.com/gogo/protobuf/protoc-gen-gogo

# Generate sources
generate: get-generators
	@echo "# generating sources"
	cd plugins/nodesync && go generate
	cd plugins/podmanager && go generate
	cd plugins/ipv4net/ipam && go generate
	cd plugins/ksr && go generate
	cd cmd/contiv-stn && go generate
	cd plugins/crd/handler/nodeconfig && go generate

# Get linter tools
get-linters:
	@echo " => installing linters"
	go get -v golang.org/x/lint/golint

# Run code analysis
lint:
	@echo "# running code analysis"
	./scripts/golint.sh
	./scripts/govet.sh

# Run metalinter tool
metalinter:
	docker build -t vpp_metalinter -f ./docker/development/Dockerfile.metalinter .
	docker run --rm vpp_metalinter

# Format code
format:
	@echo "# formatting the code"
	./scripts/gofmt.sh

# Check if the files are go formatted
check-format:
	@echo "# checking go fmt"
	./scripts/check_fmt.sh

LINKCHECK := $(shell command -v markdown-link-check 2> /dev/null)

# Get link check tool
get-linkcheck:
ifndef LINKCHECK
	sudo apt-get update && sudo apt-get install npm
	npm install -g markdown-link-check@3.6.2
endif

# Validate links in markdown files
check-links: get-linkcheck
	./scripts/check_links.sh

DEP := $(shell command -v dep 2> /dev/null)

# Get dependency manager tool
get-dep:
ifndef DEP
	go get -v github.com/golang/dep/cmd/dep
endif

# Install Go dependencies
dep-install: get-dep
	@echo "# installing Go dependencies"
	$(DEP) ensure -v

# Update Go dependencies
dep-update: get-dep
	@echo "# updating Go dependencies"
	$(DEP) ensure -v -update

describe:
	./scripts/contiv_describe.sh

docker-images:
	cd docker && ./build-all.sh -s
	cd docker && ./push-all.sh -s

docker-dev: contiv-agent contiv-init
	cd docker/development && ./build.sh

vagrant-images:
	cd docker && ./save.sh -s

generate-manifest:
	helm template k8s/contiv-vpp/ > k8s/contiv-vpp.yaml

generate-manifest-arm64:
	helm template k8s/contiv-vpp -f k8s/contiv-vpp/values-arm64.yaml,k8s/contiv-vpp/values.yaml > k8s/contiv-vpp-arm64.yaml

helm-package:
	helm package k8s/contiv-vpp/

helm-yaml:
	helm template --set vswitch.image.tag=${TAG} --set cni.image.tag=${TAG} --set ksr.image.tag=${TAG} k8s/contiv-vpp > k8s/contiv-vpp.yaml

helm-yaml-arm64:
	helm template --set vswitch.image.tag=${TAG} --set cni.image.tag=${TAG} --set ksr.image.tag=${TAG} k8s/contiv-vpp -f k8s/contiv-vpp/values-arm64.yaml,k8s/contiv-vpp/values.yaml > k8s/contiv-vpp-arm64.yaml

.PHONY: build all \
	install clean test test-race \
	get-covtools test-cover test-cover-html test-cover-xml \
	get-generators generate \
	get-linters lint metalinter format check-format \
	get-linkcheck check-links \
	get-dep dep-install \
	docker-images docker-dev vagrant-images\
	describe generate-manifest helm-package helm-yaml \
	generate-manifest-arm64 helm-yaml-arm64
