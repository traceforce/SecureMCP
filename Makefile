.PHONY: all build proto clean install-dependencies help

# Build everything (proto + binary)
all: proto build

# Build the binary
build:
	go build -o mcpxray ./cmd/xray

# install tools
install-dependencies:
	brew install bufbuild/buf/buf

# Generate protobuf Go code
proto:
	buf generate proto

# Clean generated files
clean:
	rm -f proto/*.pb.go
	rm -f mcpxray

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Generate protobuf code and build the binary"
	@echo "  build         - Build the mcpxray binary"
	@echo "  proto         - Generate Go code from protobuf"
	@echo "  clean         - Clean generated protobuf files and binary"
	@echo "  install-dependencies - Install required dependencies (protobuf, protoc-gen-go)"
	@echo "  help          - Show this help message"
