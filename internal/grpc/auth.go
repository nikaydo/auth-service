// Package grpc реализует gRPC-сервис авторизации.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authpb "github.com/nikaydo/grpc-contract/gen/auth"

	"github.com/nikaydo/auth-service/internal/auth"
	"github.com/nikaydo/auth-service/internal/database"
	"github.com/nikaydo/auth-service/internal/jwt"
)

// AuthService — реализация контракта Auth.
type AuthService struct {
	authpb.UnimplementedAuthServer

	store  *database.Store
	tokens *jwt.Manager
	hasher *auth.PasswordHasher
	log    *slog.Logger
}

// New создаёт сервис авторизации.
func New(store *database.Store, tokens *jwt.Manager, hasher *auth.PasswordHasher, log *slog.Logger) *AuthService {
	if log == nil {
		log = slog.Default()
	}
	return &AuthService{store: store, tokens: tokens, hasher: hasher, log: log}
}

// SignUp регистрирует пользователя.
//
// Пароль хешируется до записи в базу: открытым текстом он не сохраняется
// и не передаётся дальше по gRPC.
func (s *AuthService) SignUp(ctx context.Context, req *authpb.SignUpRequest) (*authpb.SignUpResponse, error) {
	if err := database.ValidateLogin(req.GetLogin()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := database.ValidatePassword(req.GetPassword()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	hash, err := s.hasher.Hash(req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "не удалось обработать пароль")
	}

	id, err := s.store.CreateUser(ctx, database.CreateUserParams{
		Login:        req.GetLogin(),
		PasswordHash: hash,
		Role:         "user",
	})
	if err != nil {
		if errors.Is(err, database.ErrLoginTaken) {
			return nil, status.Error(codes.AlreadyExists, "логин уже занят")
		}
		return nil, internalError(ctx, s.log, "не удалось создать пользователя", err)
	}

	s.log.Info("пользователь зарегистрирован", "user_id", id, "login", req.GetLogin())
	return &authpb.SignUpResponse{UserId: int32(id)}, nil
}

// SignIn проверяет пароль и выдаёт пару токенов.
func (s *AuthService) SignIn(ctx context.Context, req *authpb.SignInRequest) (*authpb.SignInResponse, error) {
	user, err := s.store.UserByLogin(ctx, req.GetLogin())
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			// Считаем пароль против фиктивного хеша, иначе время ответа
			// выдало бы, какие логины существуют.
			auth.DummyVerify(req.GetPassword())
			return nil, status.Error(codes.Unauthenticated, "неверный логин или пароль")
		}
		return nil, internalError(ctx, s.log, "не удалось получить пользователя", err)
	}

	if !s.hasher.Verify(user.PasswordHash, req.GetPassword()) {
		return nil, status.Error(codes.Unauthenticated, "неверный логин или пароль")
	}

	pair, err := s.issueSession(ctx, user, "", "")
	if err != nil {
		return nil, internalError(ctx, s.log, "не удалось создать сессию", err)
	}

	return &authpb.SignInResponse{
		Token:        pair.AccessToken,
		RefreshToken: pair.RefreshToken,
	}, nil
}

// CheckUser возвращает пользователя по логину.
//
// Пароль в ответе не возвращается: поле require_password управляет только
// тем, участвует ли он в условии поиска.
func (s *AuthService) CheckUser(ctx context.Context, req *authpb.CheckUserRequest) (*authpb.CheckUserResponse, error) {
	user, err := s.store.UserByLogin(ctx, req.GetLogin())
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "пользователь не найден")
		}
		return nil, internalError(ctx, s.log, "не удалось получить пользователя", err)
	}

	if req.GetRequirePassword() && !s.hasher.Verify(user.PasswordHash, req.GetPassword()) {
		return nil, status.Error(codes.Unauthenticated, "неверный логин или пароль")
	}

	// Refresh-токен здесь не возвращается: он хранится у клиента в
	// HttpOnly-cookie и предъявляется при ротации. Возвращать его через
	// gRPC означало бы гонять секретный материал по сети без необходимости.
	return &authpb.CheckUserResponse{
		User: &authpb.User{
			Id:    int32(user.ID),
			Login: user.Login,
		},
	}, nil
}

// CreateTokens выпускает новую пару токенов для пользователя.
//
// Если передан rotate_from, предыдущий токен семейства заменяется новым.
// Это ротация при обновлении сессии.
func (s *AuthService) CreateTokens(ctx context.Context, req *authpb.CreateTokensRequest) (*authpb.CreateTokensResponse, error) {
	userID := int64(req.GetId())
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "некорректный идентификатор пользователя")
	}

	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "пользователь не найден")
		}
		return nil, internalError(ctx, s.log, "не удалось получить пользователя", err)
	}

	// Логин и роль берутся из базы, а не из запроса. Поля login и role в
	// CreateTokensRequest оставлены для совместимости контракта, но значения
	// из них намеренно игнорируются: иначе вызывающий мог бы выпустить токен
	// с произвольной ролью, просто указав её в запросе.
	pair, err := s.issueSession(ctx, user, req.GetRotateFrom(), req.GetFamilyId())
	if err != nil {
		var reused *database.ErrRefreshReused
		if errors.As(err, &reused) {
			return nil, status.Error(codes.Unauthenticated, "сессия завершена: токен уже использован")
		}
		return nil, internalError(ctx, s.log, "не удалось создать сессию", err)
	}

	return &authpb.CreateTokensResponse{
		JwtToken:     pair.AccessToken,
		RefreshToken: pair.RefreshToken,
	}, nil
}

// ValidateJWT проверяет токен.
//
// При истечении срока возвращается expired = true, а не ошибка: вызывающий
// должен отличить «просрочено» от «подделано». Раньше это поле игнорировалось,
// и просроченный refresh-токен проходил проверку.
func (s *AuthService) ValidateJWT(ctx context.Context, req *authpb.ValidateJWTRequest) (*authpb.ValidateJWTResponse, error) {
	var (
		userID int64
		login  string
		err    error
	)

	if req.GetRefresh() {
		// Refresh-токен непрозрачный, поэтому проверяется только по таблице:
		// наличие записи означает, что токен выдан и ещё не отозван.
		user, uErr := s.store.UserByRefreshHash(ctx, auth.HashRefreshToken(req.GetToken()))
		switch {
		case uErr == nil:
			userID, login = user.ID, user.Login
		case errors.Is(uErr, database.ErrNotFound):
			return nil, status.Error(codes.Unauthenticated, "refresh-токен недействителен")
		default:
			return nil, internalError(ctx, s.log, "не удалось проверить токен", uErr)
		}
	} else {
		userID, login, _, err = s.tokens.ParseAccess(req.GetToken())
	}

	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return &authpb.ValidateJWTResponse{
			Id:      int32(userID),
			Login:   login,
			Expired: true,
		}, nil
	case err != nil:
		return nil, status.Error(codes.Unauthenticated, "токен недействителен")
	}

	return &authpb.ValidateJWTResponse{
		Id:      int32(userID),
		Login:   login,
		Expired: false,
	}, nil
}

// issueSession выпускает и сохраняет пару токенов.
func (s *AuthService) issueSession(ctx context.Context, user database.User, rotateFrom, familyID string) (jwt.Pair, error) {
	refreshToken, _, family, err := auth.NewRefreshToken()
	if err != nil {
		return jwt.Pair{}, err
	}
	// При ротации новая пара продолжает то же семейство, что и предыдущая.
	if familyID != "" {
		family = familyID
	}

	pair, err := s.tokens.NewPair(user.ID, user.Login, user.Role, refreshToken, family)
	if err != nil {
		return jwt.Pair{}, err
	}

	if rotateFrom != "" {
		if err := s.store.RotateRefreshToken(ctx, user.ID, family, rotateFrom, pair.RefreshHash, pair.RefreshExpiresAt); err != nil {
			return jwt.Pair{}, err
		}
	} else if err := s.store.SaveRefreshToken(ctx, user.ID, family, pair.RefreshHash, pair.RefreshExpiresAt); err != nil {
		return jwt.Pair{}, err
	}

	return pair, nil
}

// internalError логирует причину и возвращает клиенту нейтральный ответ.
//
// Наружу уходит только код: тексты SQL-ошибок раскрывают имена таблиц и
// колонок, а детали провайдера могут содержать внутренние адреса.
func internalError(ctx context.Context, log *slog.Logger, public string, cause error) error {
	log.LogAttrs(ctx, slog.LevelError, "ошибка сервиса авторизации",
		slog.String("public", public),
		slog.String("cause", cause.Error()),
	)
	return status.Error(codes.Internal, fmt.Sprintf("%s: %v", public, internalSuffix(cause)))
}

// internalSuffix оставляет в тексте ошибки только тип, без деталей.
func internalSuffix(err error) string {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return "ошибка базы данных (" + pgErr.SQLState() + ")"
	}
	return "внутренняя ошибка"
}
