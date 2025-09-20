package main

import (
	"context"
	"fmt"
	carAPI "github.com/SlavaShagalov/car-rental/internal/car/api"
	"github.com/SlavaShagalov/car-rental/internal/gateway"
	paymentAPI "github.com/SlavaShagalov/car-rental/internal/payment/api"
	"github.com/SlavaShagalov/car-rental/internal/pkg/app"
	rentalAPI "github.com/SlavaShagalov/car-rental/internal/rental/api"
	"github.com/SlavaShagalov/car-rental/internal/requests/repository"
	"github.com/SlavaShagalov/car-rental/pkg/retryer"
	"github.com/SlavaShagalov/car-rental/pkg/statistics"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/lmittmann/tint"
	"github.com/segmentio/kafka-go"
	"github.com/spf13/pflag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type WebApp interface {
	Start() error
	Shutdown(ctx context.Context) error
}

func startApp(webApp WebApp, config app.Config, logger *slog.Logger) {
	logger.Debug(fmt.Sprintf("web app starts at %s with configuration: %+v", config.Web.Host+":"+config.Web.Port, config))

	go func() {
		err := webApp.Start()
		if err != nil {
			panic(err)
		}
	}()
}

func shutdownApp(webApp WebApp, logger *slog.Logger) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Debug("shutdown web app ...")

	const shutdownTimeout = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)

	err := webApp.Shutdown(ctx)
	if err != nil {
		panic(err)
	}

	cancel()
	logger.Debug("web app exited")
}

func main() {
	var configPath string
	pflag.StringVarP(&configPath, "config", "c", "configs/gateway.yaml", "Config file path")
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

	repo := repository.NewSqlxRepository(db, logger)

	kafkaWriter := &kafka.Writer{
		Addr:                   kafka.TCP(config.Kafka.Addresses...),
		Topic:                  config.Kafka.Topic,
		Balancer:               &kafka.LeastBytes{},
		AllowAutoTopicCreation: true,
	}
	defer kafkaWriter.Close()

	kafkaStatWriter := &kafka.Writer{
		Addr:                   kafka.TCP(config.Kafka.Addresses...),
		Topic:                  config.Kafka.StatTopic,
		Balancer:               &kafka.LeastBytes{},
		AllowAutoTopicCreation: true,
	}
	defer kafkaStatWriter.Close()

	requestBacklog := retryer.NewKafkaRequestBacklog(nil, kafkaWriter, logger)
	stat := statistics.NewKafkaStatistics(nil, kafkaStatWriter, logger, nil)

	delivery := gateway.New(
		carAPI.New(config.CarsApiAddr, http.DefaultClient, requestBacklog, config.MaxRequestFails, logger),
		rentalAPI.New(config.RentalApiAddr, http.DefaultClient, requestBacklog, config.MaxRequestFails, logger),
		paymentAPI.New(config.PaymentApiAddr, http.DefaultClient, requestBacklog, config.MaxRequestFails, logger),
		logger,
		repo,
	)

	auth, err := app.NewAuth(config.Web.JWKsURL, logger)
	if err != nil {
		panic(err)
	}

	statisticsMW, err := app.NewStatisticsMW(stat, logger)
	if err != nil {
		panic(err)
	}

	webApp := app.NewFiberApp(config.Web, delivery, statisticsMW, auth, logger)

	startApp(webApp, config, logger)
	shutdownApp(webApp, logger)
}
