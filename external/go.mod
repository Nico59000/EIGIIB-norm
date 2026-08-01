module eigiib.example/external

go 1.23

require (
	eigiib.example/independent v0.0.0
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/veraison/go-cose v1.3.0
)

require github.com/x448/float16 v0.8.4 // indirect

replace eigiib.example/independent => ../independent
