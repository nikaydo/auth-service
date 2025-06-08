package main

import (
	"log"
	"main/internal/config"
	"main/internal/database"
	au "main/internal/grpc"
	"net"

	auth "github.com/nikaydo/grpc-contract/gen/auth"
	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	env, err := config.ReadEnv()
	if err != nil {
		log.Fatal("Error loading .env file:", err)

	}
	log.Println("Database succesful read")
	db, err := database.DatabaseInit(env)
	if err != nil {
		log.Fatal("Error loading .env file:", err)

	}
	log.Println("Database succesful connected")
	auth.RegisterAuthServer(grpcServer, &au.AuthService{User: db})
	log.Println("gRPC server started on :50052")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
