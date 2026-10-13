package audit

import (
	"context"
	"testing"
)

func TestTamperDetection(t *testing.T) {
	m := &Memory{}
	m.Append(context.Background(), Event{Decision: "allow", Reason: "authorized", Policy: "aegis/v1"})
	m.Append(context.Background(), Event{Decision: "deny", Reason: "tenant_boundary", Policy: "aegis/v1"})
	if e := Verify(m.Records); e != nil {
		t.Fatal(e)
	}
	m.Records[0].Event.Decision = "deny"
	if Verify(m.Records) == nil {
		t.Fatal("tamper undetected")
	}
}
