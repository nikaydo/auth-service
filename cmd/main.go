package main

import (
	"fmt"
	"log"
	"main/internal/config"
	"main/internal/database"
	au "main/internal/grpc"
	"net"
	"os"
	"os/signal"
	"syscall"

	auth "github.com/nikaydo/grpc-contract/gen/auth"
	"google.golang.org/grpc"
)

func main() {
	env, err := config.ReadEnv()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}
	log.Println("Database auth succesful read")
	db, err := database.DatabaseInit(env)
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}
	log.Println("Database succesful connected")
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%s", env.EnvMap["HOST"], env.EnvMap["PORT"]))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServer(grpcServer, &au.AuthService{User: db})
	log.Println("gRPC server started on ", fmt.Sprintf("%s:%s", env.EnvMap["HOST"], env.EnvMap["PORT"]))
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	<-quit
	log.Println("Shutting down server...")
	grpcServer.GracefulStop()
	log.Println("Server gracefully stopped")
}
