# install dependencies according to Gopkg.toml
define install_dependencies
	@echo "# installing dependencies, please wait ..."
	@dep ensure
endef

# install code generators
define install_generators
	$(if $(shell command -v protoc --gogo_out=. 2> /dev/null),$(info # gogo/protobuf is installed),$(error gogo/protobuf missing, please install it with go get github.com/gogo/protobuf))
    @go get github.com/golang/protobuf/protoc-gen-go
endef
