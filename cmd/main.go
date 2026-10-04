package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	authpb "github.com/nikaydo/grpc-contract/gen/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/nikaydo/auth-service/internal/auth"
	"github.com/nikaydo/auth-service/internal/config"
	"github.com/nikaydo/auth-service/internal/database"
	grpcsrv "github.com/nikaydo/auth-service/internal/grpc"
	"github.com/nikaydo/auth-service/internal/jwt"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("сервис завершился с ошибкой", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("конфигурация загружена", "addr", cfg.Addr(), "issuer", cfg.Issuer)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := database.RunMigrations(startupCtx, cfg.DatabaseURL, migrationsDir()); err != nil {
		return err
	}

	store, err := database.New(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	tokens := jwt.NewManager(cfg.JWTSecret, cfg.Issuer, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	hasher := auth.NewPasswordHasher(cfg.BcryptCost)

	lis, err := net.Listen("tcp", cfg.Addr())
	if err != nil {
		return err
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(cfg.MaxMessageBytes),
		// Без интерцептора паника в обработчике обрушивает весь процесс:
		// gRPC-обработчики выполняются в горутинах сервера.
		grpc.UnaryInterceptor(grpcsrv.LoggingInterceptor(log)),
		grpc.ChainStreamInterceptor(grpcsrv.StreamLoggingInterceptor(log)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	authpb.RegisterAuthServer(server, grpcsrv.New(store, tokens, hasher, log))
	reflection.Register(server)

	errCh := make(chan error, 1)
	go func() {
		log.Info("gRPC-сервер запущен", "addr", cfg.Addr())
		if err := server.Serve(lis); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("получен сигнал завершения")
	}

	// GracefulStop ждёт завершения текущих запросов. Контекст приложения
	// к этому моменту уже отменён, поэтому таймаут задаётся отдельным.
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
		log.Info("сервер остановлен")
		return nil
	case <-time.After(30 * time.Second):
		server.Stop()
		log.Warn("сервер остановлен принудительно: не все запросы завершились")
		return <-errCh
	}
}
