package main

import (
	"context"
	"github.com/SlavaShagalov/car-rental/internal/requests/repository"
	"github.com/SlavaShagalov/car-rental/pkg/migrations"
	"github.com/SlavaShagalov/car-rental/pkg/statistics"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lmittmann/tint"
	"github.com/segmentio/kafka-go"
	"github.com/spf13/pflag"

	"github.com/SlavaShagalov/car-rental/internal/pkg/app"
)

func main() {
	var configPath, migrationsPath string
	pflag.StringVarP(&configPath, "config", "c", "configs/statistics.yaml", "Config file path")
	pflag.StringVarP(&migrationsPath, "migrations", "", "migrations", "Migrations directory path")
	pflag.Parse()

	config, err := app.ReadLocalConfig(configPath)
	if err != nil {
		panic(err)
	}

	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{Level: slog.Level(config.Logging.Level)}))

	db, err := sqlx.Connect(config.DB.DriverName, config.DB.ConnectionString)
	if err != nil {
		panic(err)
	}

	defer func(db *sqlx.DB) {
		err = db.Close()
		if err != nil {
			panic(err)
		}
	}(db)

	err = migrations.Do(config.DB.ConnectionString, migrationsPath, logger)
	if err != nil {
		panic(err)
	}

	repo := repository.NewSqlxRepository(db, logger)

	kafkaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: config.Kafka.Addresses,
		Topic:   config.Kafka.Topic,
	})

	stat := statistics.NewKafkaStatistics(kafkaReader, nil, logger, repo)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	for {
		select {
		case <-quit:
			cancel()
			kafkaReader.Close()
			return
		default:
			err = stat.SaveRequest(ctx)
			if err != nil {
				logger.Error(err.Error())
			}
		}
	}
}
