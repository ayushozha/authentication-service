package grpc

import (
	"encoding/json"
	"fmt"
)

// JSONCodec implements grpc encoding.Codec using JSON serialization.
// This allows us to use plain Go structs as gRPC messages without
// protobuf code generation.
type JSONCodec struct{}

// Name returns the name of the codec, used in content-type negotiation.
func (JSONCodec) Name() string {
	return "json"
}

// Marshal encodes a Go value to JSON bytes.
func (JSONCodec) Marshal(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("grpc json codec marshal: %w", err)
	}
	return b, nil
}

// Unmarshal decodes JSON bytes into a Go value.
func (JSONCodec) Unmarshal(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("grpc json codec unmarshal: %w", err)
	}
	return nil
}
