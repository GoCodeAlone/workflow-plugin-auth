# contracts

Generated protobuf Go bindings for `workflow-plugin-auth`.

The `.proto.go` file in this directory (`auth.pb.go`) is generated from
`auth.proto`. There is no `buf` config and no `//go:generate` directive — the
command below must be run by hand when the proto changes.

## Regenerate

Requires (per the `auth.pb.go` header):

- `protoc` v7.35.0 (libprotoc 35.0)
- `protoc-gen-go` v1.36.11

Run from the **repo root** (`workflow-plugin-auth/`):

```sh
protoc --go_out=. --go_opt=paths=source_relative -I . internal/contracts/auth.proto
```

Notes:

- `paths=source_relative` writes the output next to the source
  (`internal/contracts/auth.pb.go`), matching the import path resolved by the
  proto's own `option go_package = "github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"`.
- No `-M` remappings are needed — `go_package` is set in the proto.
- `google/protobuf/struct.proto` is resolved by the well-known types bundled
  with `protoc` (no extra `-I` entry required).
