package email

import (
	"testing"

	"github.com/go-mail/mail/v2"
)

func TestNewSMTPClientConfiguresPort587(t *testing.T) {
	client := NewSMTPClient("smtp.example.com", 587, "user", "pass", "from@example.com")

	if client.from != "from@example.com" {
		t.Fatalf("expected from address to be set, got %q", client.from)
	}
	if client.dialer.StartTLSPolicy != mail.MandatoryStartTLS {
		t.Fatalf("expected MandatoryStartTLS, got %#v", client.dialer.StartTLSPolicy)
	}
}

func TestNewSMTPClientConfiguresPort465(t *testing.T) {
	client := NewSMTPClient("smtp.example.com", 465, "user", "pass", "from@example.com")

	if !client.dialer.SSL {
		t.Fatal("expected SSL to be enabled for port 465")
	}
	if client.dialer.StartTLSPolicy != mail.NoStartTLS {
		t.Fatalf("expected NoStartTLS, got %#v", client.dialer.StartTLSPolicy)
	}
}

func TestLoggingClientSendVerificationCode(t *testing.T) {
	client := NewLoggingClient()

	if err := client.SendVerificationCode("user@example.com", "123456"); err != nil {
		t.Fatalf("SendVerificationCode returned error: %v", err)
	}
}
