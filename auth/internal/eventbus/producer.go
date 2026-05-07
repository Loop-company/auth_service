package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

type EventType string

const (
	UserRegistered EventType = "user.registered"
	UserLoggedIn   EventType = "user.logged_in"
)

type Event struct {
	EventID       string      `json:"event_id"`
	UserID        string      `json:"user_id"`
	EventType     EventType   `json:"event_type"`
	SourceService string      `json:"source_service"`
	Payload       interface{} `json:"payload"`
	OccurredAt    string      `json:"occurred_at"`
}

type KafkaProducer struct {
	writer *kafka.Writer
	log    *slog.Logger
}

func NewKafkaProducer(brokers []string, log *slog.Logger) *KafkaProducer {
	return &KafkaProducer{
		writer: &kafka.Writer{
			Addr:                   kafka.TCP(brokers...),
			Balancer:               &kafka.LeastBytes{},
			AllowAutoTopicCreation: false,
		},
		log: log,
	}
}

func (p *KafkaProducer) Close() error {
	return p.writer.Close()
}

func (p *KafkaProducer) publish(ctx context.Context, topic string, eventType EventType, userID string, payload interface{}) error {
	event := Event{
		EventID:       uuid.New().String(),
		UserID:        userID,
		EventType:     eventType,
		SourceService: "auth-service",
		Payload:       payload,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	err = p.writer.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Value: encoded,
	})

	if err != nil {
		p.log.Error("failed to publish message", "topic", topic, "type", eventType, "error", err)
		return err
	}

	p.log.Info("published message", "topic", topic, "type", eventType)
	return nil
}

func (p *KafkaProducer) SendUserRegistered(ctx context.Context, userID, email string) {
	payload := map[string]string{
		"email": email,
	}

	_ = p.publish(ctx, "user.events", UserRegistered, userID, payload)
}

func (p *KafkaProducer) SendUserLoggedIn(ctx context.Context, userID, email string) {
	payload := map[string]string{
		"email": email,
	}

	_ = p.publish(ctx, "auth.events", UserLoggedIn, userID, payload)
}
