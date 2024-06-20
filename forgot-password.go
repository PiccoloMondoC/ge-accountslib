// ge-accounts/pkg/clientlib/accountslib/forgot-password.go
package accountslib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// ForgotPasswordToken represents a forgot password token record in the database
type ForgotPasswordToken struct {
	Token  string    `json:"token"`
	UserID uuid.UUID `json:"user_id"`
	Expiry string    `json:"expiry"`
}

// CreateForgotPasswordTokenInput represents the input required to create a forgot password token
type CreateForgotPasswordTokenInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// CreateForgotPasswordToken creates a forgot password token for the user
func (c *Client) CreateForgotPasswordToken(input CreateForgotPasswordTokenInput) (*ForgotPasswordToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/forgotpasswordtokens", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var createdForgotPasswordToken ForgotPasswordToken
	if err := json.NewDecoder(resp.Body).Decode(&createdForgotPasswordToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &createdForgotPasswordToken, nil
}

// GetForgotPasswordTokensByUserIDInput represents the input required to get forgot password tokens by user ID
type GetForgotPasswordTokensByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// GetForgotPasswordTokensByUserID retrieves all forgot password tokens for a given user
func (c *Client) GetForgotPasswordTokensByUserID(input GetForgotPasswordTokensByUserIDInput) ([]ForgotPasswordToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request URL
	reqURL := fmt.Sprintf("%s/forgotpasswordtokens", c.BaseURL)

	// Prepare the request
	req, err := http.NewRequest(http.MethodGet, reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var forgotPasswordTokens []ForgotPasswordToken
	if err := json.NewDecoder(resp.Body).Decode(&forgotPasswordTokens); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return forgotPasswordTokens, nil
}

// GetForgotPasswordTokenByPlaintextInput represents the input required to get a forgot password token by plaintext
type GetForgotPasswordTokenByPlaintextInput struct {
	Plaintext string `json:"plaintext"`
}

// GetForgotPasswordTokenByPlaintext retrieves a forgot password token by plaintext
func (c *Client) GetForgotPasswordTokenByPlaintext(input GetForgotPasswordTokenByPlaintextInput) (*ForgotPasswordToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/forgotpasswordtokens/byplaintext", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var forgotPasswordToken ForgotPasswordToken
	if err := json.NewDecoder(resp.Body).Decode(&forgotPasswordToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &forgotPasswordToken, nil
}

// DeleteForgotPasswordTokenInput represents the input required to delete a forgot password token
type DeleteForgotPasswordTokenInput struct {
	TokenID uuid.UUID `json:"token_id"`
}

// DeleteForgotPasswordToken deletes a forgot password token
func (c *Client) DeleteForgotPasswordToken(input DeleteForgotPasswordTokenInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/forgotpasswordtokens", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeleteForgotPasswordTokenByUserIDInput represents the input required to delete forgot password tokens by user ID
type DeleteForgotPasswordTokenByUserIDInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// DeleteForgotPasswordTokenByUserID deletes all forgot password tokens for a given user ID
func (c *Client) DeleteForgotPasswordTokenByUserID(input DeleteForgotPasswordTokenByUserIDInput) error {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/forgotpasswordtokens", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeleteExpiredForgotPasswordTokensInput represents the input required to delete expired forgot password tokens
type DeleteExpiredForgotPasswordTokensInput struct{}

// DeleteExpiredForgotPasswordTokens deletes all expired forgot password tokens
func (c *Client) DeleteExpiredForgotPasswordTokens() error {
	// Prepare the payload
	input := DeleteExpiredForgotPasswordTokensInput{}
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/forgotpasswordtokens/expired", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// VerifyForgotPasswordTokenInput represents the input required to verify a forgot password token
type VerifyForgotPasswordTokenInput struct {
	Token string `json:"token"`
}

// VerifyForgotPasswordToken verifies a forgot password token for the user
func (c *Client) VerifyForgotPasswordToken(input VerifyForgotPasswordTokenInput) (*ForgotPasswordToken, error) {
	// Prepare the payload
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/forgotpasswordtokens/verify", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var verifiedForgotPasswordToken ForgotPasswordToken
	if err := json.NewDecoder(resp.Body).Decode(&verifiedForgotPasswordToken); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &verifiedForgotPasswordToken, nil
}
