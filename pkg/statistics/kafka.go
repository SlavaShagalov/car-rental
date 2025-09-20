package statistics

import (
	"context"
	"github.com/SlavaShagalov/car-rental/internal/requests/repository"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/segmentio/kafka-go"
	"log/slog"
	"time"
)

type BacklogError string

func (e BacklogError) Error() string {
	return string(e)
}

const (
	ErrNoWriter BacklogError = "statistics has no writer"
	ErrNoReader BacklogError = "statistics has no reader"
)

type KafkaStatistics struct {
	reader *kafka.Reader
	writer *kafka.Writer
	logger *slog.Logger
	repo   *repository.SqlxRepository
}

func NewKafkaStatistics(reader *kafka.Reader, writer *kafka.Writer, logger *slog.Logger, repo *repository.SqlxRepository) *KafkaStatistics {
	return &KafkaStatistics{
		reader: reader,
		writer: writer,
		logger: logger,
		repo:   repo,
	}
}

type header struct {
	Key    string
	Values []string
}

type Request struct {
	Method  string
	URL     string
	Body    string
	Headers string
}

func (backlog *KafkaStatistics) HealthCheck(_ context.Context) error {
	return nil // TODO ?
}

func (backlog *KafkaStatistics) Push(ctx context.Context, req Request) error {
	if backlog.writer == nil {
		return ErrNoWriter
	}

	payload, err := kafka.Marshal(req)
	if err != nil {
		return err
	}

	uid := uuid.New().String()
	msg := kafka.Message{
		Key:   []byte(uid),
		Value: payload,
	}
	backlog.logger.Debug("write message to kafka...",
		slog.String("topic", backlog.writer.Topic),
		slog.String("key", uid),
	)

	err = backlog.writer.WriteMessages(ctx, msg)
	if errors.Is(err, kafka.UnknownTopicOrPartition) {
		time.Sleep(5 * time.Second) // Wait for auto creating topic
		err = backlog.writer.WriteMessages(ctx, msg)
	}

	return err
}

func (backlog *KafkaStatistics) SaveRequest(ctx context.Context) (err error) {
	if backlog.reader == nil {
		return ErrNoReader
	}

	msg, err := backlog.reader.ReadMessage(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = multierror.Append(err, backlog.reader.SetOffset(msg.Offset))
		}
	}()

	backlog.logger.Debug("read message from kafka",
		slog.String("topic", msg.Topic),
		slog.Int("partition", msg.Partition),
		slog.Int64("offset", msg.Offset),
		slog.String("key", string(msg.Key)),
	)

	var rawRequest Request
	err = kafka.Unmarshal(msg.Value, &rawRequest)
	if err != nil {
		return err
	}

	repoReq := repository.Request{
		Method:  rawRequest.Method,
		URL:     rawRequest.URL,
		Body:    rawRequest.Body,
		Headers: rawRequest.Headers,
	}

	// save to db request
	return backlog.repo.SaveRequest(ctx, repoReq)
}
