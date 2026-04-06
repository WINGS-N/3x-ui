package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/util/random"
)

// APITokenService manages hashed API tokens used to authenticate panel API requests.
type APITokenService struct{}

// CreateToken generates, hashes, and stores a new API token for the given user.
// The returned plain token is shown only once to the caller.
func (s *APITokenService) CreateToken(userID int, name string) (*model.APIToken, string, error) {
	token := newPlainAPIToken()
	tokenInfo := &model.APIToken{
		UserId:    userID,
		Name:      strings.TrimSpace(name),
		TokenHash: crypto.HashTokenSHA256(token),
		Preview:   tokenPreview(token),
	}
	if tokenInfo.Name == "" {
		tokenInfo.Name = defaultAPITokenName()
	}

	err := database.GetDB().Create(tokenInfo).Error
	if err != nil {
		return nil, "", err
	}
	return tokenInfo, token, nil
}

// GetTokens returns API tokens created by the given user without exposing token secrets.
func (s *APITokenService) GetTokens(userID int) ([]*model.APIToken, error) {
	tokens := make([]*model.APIToken, 0)
	err := database.GetDB().
		Model(model.APIToken{}).
		Where("user_id = ?", userID).
		Order("id DESC").
		Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// DeleteToken removes the selected API token belonging to the given user.
func (s *APITokenService) DeleteToken(userID int, tokenID int) error {
	db := database.GetDB()
	token := &model.APIToken{}
	err := db.Model(model.APIToken{}).
		Where("id = ? AND user_id = ?", tokenID, userID).
		First(token).Error
	if err != nil {
		return err
	}
	return db.Delete(token).Error
}

// AuthenticateToken resolves an API token to a user and updates its last-used timestamp.
func (s *APITokenService) AuthenticateToken(token string) (*model.User, *model.APIToken, error) {
	db := database.GetDB()

	tokenInfo := &model.APIToken{}
	err := db.Model(model.APIToken{}).
		Where("token_hash = ?", crypto.HashTokenSHA256(strings.TrimSpace(token))).
		First(tokenInfo).Error
	if err != nil {
		return nil, nil, err
	}

	user := &model.User{}
	err = db.Model(model.User{}).
		Where("id = ?", tokenInfo.UserId).
		First(user).Error
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	if err := db.Model(tokenInfo).Update("last_used_at", &now).Error; err != nil {
		logger.Warning("unable to update API token last_used_at:", err)
	} else {
		tokenInfo.LastUsedAt = &now
	}

	return user, tokenInfo, nil
}

func newPlainAPIToken() string {
	return "3xui_" + random.Seq(48)
}

func defaultAPITokenName() string {
	return fmt.Sprintf("API Token %s", time.Now().Format("2006-01-02 15:04:05"))
}

func tokenPreview(token string) string {
	if len(token) <= 18 {
		return token
	}
	return token[:12] + "..." + token[len(token)-6:]
}
