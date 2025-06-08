package grpc

import (
	"context"
	"main/internal/database"

	myjwt "main/internal/jwt"

	auth "github.com/nikaydo/grpc-contract/gen/auth"
)

type AuthService struct {
	auth.UnimplementedAuthServer
	User database.UserDB
}

func (as *AuthService) SignUp(ctx context.Context, req *auth.SignUpRequest) (*auth.SignUpResponse, error) {
	n, err := as.User.CreateUser(req.Login, req.Password)
	if err != nil {
		return &auth.SignUpResponse{}, err
	}
	return &auth.SignUpResponse{UserId: int32(n)}, nil
}

func (as *AuthService) SignIn(ctx context.Context, req *auth.SignInRequest) (*auth.SignInResponse, error) {
	user, err := as.User.CheckUser(req.Login, req.Password, true)
	if err != nil {
		return &auth.SignInResponse{}, err
	}
	var j myjwt.JwtTokens
	j.Env = as.User.ENV
	if err = j.CreateTokens(user.Id, user.Login, ""); err != nil {
		return &auth.SignInResponse{}, err
	}
	if err = as.User.UpdateUser(user.Login, j.RefreshToken); err != nil {
		return &auth.SignInResponse{}, err
	}
	return &auth.SignInResponse{Token: j.AccessToken}, nil
}

func (as *AuthService) CheckUser(ctx context.Context, req *auth.CheckUserRequest) (*auth.CheckUserResponse, error) {
	u, err := as.User.CheckUser(req.Login, req.Password, req.WithPass)
	if err != nil {
		return &auth.CheckUserResponse{}, err
	}
	return &auth.CheckUserResponse{User: &auth.User{Id: int32(u.Id), Login: u.Login, Refresh: u.RefreshToken}}, nil
}

func (as *AuthService) CreateTokens(ctx context.Context, req *auth.CreateTokensRequest) (*auth.CreateTokensResponse, error) {
	var j myjwt.JwtTokens
	j.Env = as.User.ENV
	if err := j.CreateTokens(int(req.Id), req.Login, req.Role); err != nil {
		return &auth.CreateTokensResponse{}, err
	}
	if err := as.User.UpdateUser(req.Login, j.RefreshToken); err != nil {
		return &auth.CreateTokensResponse{}, err
	}
	return &auth.CreateTokensResponse{JwtToken: j.AccessToken}, nil
}

func (as *AuthService) ValidateJWT(ctx context.Context, req *auth.ValidateJWTRequest) (*auth.ValidateJWTResponse, error) {
	var secret string
	if req.Refresh {
		secret = as.User.ENV.EnvMap["SECRET_REFRESH"]
	} else {
		secret = as.User.ENV.EnvMap["SECRET"]
	}
	id, login, err := myjwt.ValidateToken(req.Token, secret)
	if err != nil {
		if err == myjwt.ErrTokenExpired {
			return &auth.ValidateJWTResponse{Id: int32(id), Login: login, Expired: true}, nil
		}
		return &auth.ValidateJWTResponse{Id: int32(id), Login: login, Expired: false}, err
	}
	return &auth.ValidateJWTResponse{Id: int32(id), Login: login, Expired: false}, err
}
