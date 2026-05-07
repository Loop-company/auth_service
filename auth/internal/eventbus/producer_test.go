package eventbus

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewKafkaProducerConfiguresWriter(t *testing.T) {
	producer := NewKafkaProducer([]string{"localhost:9092"}, testLogger())
	defer func() {
		if err := producer.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	}()

	if producer.writer == nil {
		t.Fatal("writer is nil")
	}
	if producer.log == nil {
		t.Fatal("logger is nil")
	}
	if producer.writer.AllowAutoTopicCreation {
		t.Fatal("auto topic creation should be disabled")
	}
	if producer.writer.Balancer == nil {
		t.Fatal("balancer is nil")
	}
}

func TestPublishReturnsMarshalError(t *testing.T) {
	producer := NewKafkaProducer([]string{"localhost:9092"}, testLogger())
	defer producer.Close()

	err := producer.publish(context.Background(), "auth.events", UserLoggedIn, "guid-1", map[string]interface{}{
		"bad": func() {},
	})
	if err == nil {
		t.Fatal("expected marshal error")
	}
	if !strings.Contains(err.Error(), "failed to marshal event") {
		t.Fatalf("error = %v", err)
	}
}
