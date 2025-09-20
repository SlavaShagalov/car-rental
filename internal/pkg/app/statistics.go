package app

import (
	"github.com/SlavaShagalov/car-rental/pkg/statistics"
	"github.com/gofiber/fiber/v2"
	"log/slog"
	"strings"
)

// NewStatisticsMW create auth middleware
func NewStatisticsMW(stat *statistics.KafkaStatistics, logger *slog.Logger) (fiber.Handler, error) {
	return func(ctx *fiber.Ctx) error {
		headers := ctx.GetReqHeaders()

		headersStr := ""
		for key, header := range headers {
			value := strings.Join(header, ", ")

			headerStr := key + ": " + value + "\r\n"

			headersStr += headerStr
		}

		req := statistics.Request{
			Method:  ctx.Method(),
			URL:     ctx.OriginalURL(),
			Body:    string(ctx.Body()),
			Headers: headersStr,
		}

		if req.URL == "/api/v1/statistics" {
			return ctx.Next()
		}

		err := stat.Push(ctx.Context(), req)
		if err != nil {
			logger.Error("ERROR", err.Error())
		}

		return ctx.Next()
	}, nil
}
