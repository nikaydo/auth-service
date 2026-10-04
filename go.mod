module github.com/nikaydo/auth-service

go 1.24.2

require (
	github.com/caarlos0/env/v11 v11.3.1
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/golang-migrate/migrate/v4 v4.18.3
	github.com/jackc/pgx/v5 v5.7.6
	github.com/joho/godotenv v1.5.1
	github.com/nikaydo/grpc-contract v0.0.0
	golang.org/x/crypto v0.37.0
	google.golang.org/grpc v1.73.0
)

require (
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.9 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

// Контракт берётся из локальной копии: сервисы разрабатываются вместе,
// и ссылка на конкретный коммит зафиксировала бы зависимость от порядка
// релизов. В CI перед сборкой выполняется go mod edit -replace.
replace github.com/nikaydo/grpc-contract => ../grpc-contract
