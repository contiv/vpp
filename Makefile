include Makeroutines.mk

VERSION=$(shell git rev-parse HEAD)
DATE=$(shell date +'%Y-%m-%dT%H:%M%:z')
LDFLAGS=-ldflags '-X github.com/contiv/vpp/vendor/github.com/ligato/cn-infra/core.BuildVersion=$(VERSION) -X github.com/contiv/vpp/vendor/github.com/ligato/cn-infra/core.BuildDate=$(DATE)'
COVER_DIR=/tmp/


# generate go structures from proto files
define generate_sources
	$(call install_generators)
	@echo "# generating sources"
	@cd plugins/contiv && go generate
	@cd plugins/contiv/bin_api/session && pkgreflect
	@cd plugins/ksr && go generate
	@cd plugins/policy/renderer/vpptcp && go generate
	@cd plugins/policy/renderer/vpptcp/bin_api/session && pkgreflect
	@echo "# done"
endef

# install-only binaries
define install_only
	@echo "# installing contiv agent"
	@cd cmd/contiv-agent && go install -v ${LDFLAGS}
	@echo "# installing contiv-ksr"
	@cd cmd/contiv-ksr && go install -v ${LDFLAGS}
	@echo "# installing contiv-cri"
	@cd cmd/contiv-cri && go install -v ${LDFLAGS}
	@echo "# installing contiv-cni"
	@cd cmd/contiv-cni && go install -v ${LDFLAGS}
	@echo "# installing ldpreload-label-injector"
	@cd cmd/tools/ldpreload-label-injector && go install -v
	@echo "# done"
endef

# run all tests
define test_only
	@echo "# running unit tests"
	@go test ./cmd/contiv-cni
	@go test ./plugins/contiv
	@go test ./plugins/contiv/ipam
	@go test ./plugins/contiv/containeridx
	@go test ./plugins/kvdbproxy
	@go test ./plugins/ksr
	@go test ./plugins/policy/renderer/acl/cache
	@go test ./plugins/policy/renderer/acl
	@go test ./plugins/policy/configurator
	@go test ./plugins/policy/renderer/vpptcp/cache
	@go test ./plugins/policy/renderer/vpptcp
	@echo "# done"
endef

# run all tests with coverage
define test_cover_only
	@echo "# running unit tests with coverage analysis"
	@go test -covermode=count -coverprofile=${COVER_DIR}cov_u1.out ./cmd/contiv-cni
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u2.out ./plugins/contiv
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u3.out ./plugins/contiv/ipam
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u4.out ./plugins/contiv/containeridx
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u5.out ./plugins/kvdbproxy
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u6.out ./plugins/ksr
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u7.out ./plugins/policy/renderer/acl/cache
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u8.out ./plugins/policy/renderer/acl
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u9.out ./plugins/policy/configurator
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u10.out ./plugins/policy/renderer/vpptcp/cache
    @go test -covermode=count -coverprofile=${COVER_DIR}cov_u11.out ./plugins/policy/renderer/vpptcp
    @echo "# merging coverage results"
    @cd vendor/github.com/wadey/gocovmerge && go install -v
    @gocovmerge ${COVER_DIR}cov_u1.out ${COVER_DIR}cov_u2.out ${COVER_DIR}cov_u3.out \
		${COVER_DIR}cov_u4.out ${COVER_DIR}cov_u5.out ${COVER_DIR}cov_u6.out \
		${COVER_DIR}cov_u7.out ${COVER_DIR}cov_u8.out ${COVER_DIR}cov_u9.out \
		${COVER_DIR}cov_u10.out ${COVER_DIR}cov_u11.out > ${COVER_DIR}coverage.out
    @echo "# coverage data generated into ${COVER_DIR}coverage.out"
    @echo "# done"
endef

# run all tests with coverage and display HTML report
define test_cover_html
    $(call test_cover_only)
    @go tool cover -html=${COVER_DIR}coverage.out -o ${COVER_DIR}coverage.html
    @echo "# coverage report generated into ${COVER_DIR}coverage.html"
    @go tool cover -html=${COVER_DIR}coverage.out
endef

# run all tests with coverage and display XML report
define test_cover_xml
	$(call test_cover_only)
	@gocov convert ${COVER_DIR}coverage.out | gocov-xml > ${COVER_DIR}coverage.xml
    @echo "# coverage report generated into ${COVER_DIR}coverage.xml"
endef

# run code analysis
define lint_only
   @echo "# running code analysis"
    @./scripts/golint.sh
    @./scripts/govet.sh
    @echo "# done"
endef

# run code formatter
define format_only
    @echo "# formatting the code"
    @./scripts/gofmt.sh
    @echo "# done"
endef

# build contiv agent
define build_contiv_agent_only
    @echo "# building contiv-agent"
    @cd cmd/contiv-agent && go build -v -i ${LDFLAGS}
    @echo "# done"
endef

# build contiv-ksr only
define build_contiv_ksr_only
    @echo "# building contiv-ksr"
    @cd cmd/contiv-ksr && go build -v -i ${LDFLAGS}
    @echo "# done"
endef

# build contiv-cni only
define build_contiv_cni_only
    @echo "# building contiv-cni"
    @cd cmd/contiv-cni && go build -v -i -ldflags "-linkmode external -extldflags -static"
    @echo "# done"
endef

# build contiv-cri only
define build_contiv_cri_only
    @echo "# building contiv-cri"
    @cd cmd/contiv-cri && go build -v -i ${LDFLAGS}
    @echo "# done"
endef

# build ldpreload-inject-tool only
define build_ldpreload_inject_tool_only
    @echo "# building ldpreload inject tool"
    @cd cmd/tools/ldpreload-label-injector && go build -v -i
    @echo "# done"
endef


# verify that links in markdown files are valid
# requires npm install -g markdown-link-check
define check_links_only
    @echo "# checking links"
    @./scripts/check_links.sh
    @echo "# done"
endef

define check_format_only
    @echo "# checking go fmt"
    @./scripts/check_fmt.sh
    @echo "# done"
endef

define describe_only
    @./scripts/contiv_describe.sh
endef


# build all binaries
build:
	$(call build_contiv_agent_only)
	$(call build_contiv_cni_only)
	$(call build_contiv_ksr_only)
	$(call build_contiv_cri_only)
	$(call build_ldpreload_inject_tool_only)

# build agent
agent:
	$(call build_contiv_agent_only)

# build contiv-ksr
contiv-ksr:
	$(call build_contiv_ksr_only)

# build contiv-cni
contiv-cni:
	$(call build_contiv_cni_only)

# build contiv-cri
contiv-cri:
	$(call build_contiv_cri_only)

ldpreload-inject-tool:
	$(call build_ldpreload_inject_tool_only)

# install binaries
install:
	$(call install_only)

# install dependencies
install-dep:
	$(call install_dependencies)

# update dependencies
update-dep:
	$(call update_dependencies)

# unify sirupsen imports
unify-sirupsen:
	$(call unify_sirupsen)

# generate structures
generate:
	$(call generate_sources)

# run tests
test:
	$(call test_only)

# run tests with coverage report
test-cover:
	$(call test_cover_only)

# run tests with HTML coverage report
test-cover-html:
	$(call test_cover_html)

# run tests with XML coverage report
test-cover-xml:
	$(call test_cover_xml)

# run & print code analysis
lint:
	$(call lint_only)

# format the code
format:
	$(call format_only)

# validate links in markdown files
check_links:
	$(call check_links_only)

# check if the files are go formatted
check_format:
	$(call check_format_only)

describe:
	$(call describe_only)

# clean
clean:
	rm -f cmd/contiv-agent/contiv-agent
	rm -f cmd/contiv-cni/contiv-cni
	rm -f cmd/contiv-ksr/contiv-ksr
	rm -f cmd/contiv-ksr/contiv-cri
	rm -f cmd/tools/ldpreload-label-injector/ldpreload-label-injector
	@echo "# cleanup completed"

# run all targets
all:
	$(call lint_only)
	$(call build)
	$(call test_only)
	$(call install_only)

.PHONY: build update-dep install-dep test lint clean
