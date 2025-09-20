# ===== RUN =====
.PHONY: build
build:
	#docker compose -f docker-compose.yml build retryer gateway cars-api rental-api payment-api
	docker compose -f docker-compose.yml build gateway auth

.PHONY: up
up:
	docker compose -f docker-compose.yml up -d --build postgres kafka retryer gateway auth statistics cars-api rental-api payment-api
	#docker compose -f docker-compose.yml up -d --build postgres kafka gateway auth

.PHONY: stop
stop:
	docker compose -f docker-compose.yml stop

.PHONY: down
down:
	docker compose -f docker-compose.yml down -v

# ===== LOGS =====
service = api
.PHONY: logs
logs:
	docker compose logs -f $(service)

# ===== TEST =====
.PHONY: unit-test
unit-test:
	go test ./internal/...
