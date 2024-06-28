// ge-accounts/pkg/clientlib/accountslib/password-change.go
package accountslib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// PasswordChange represents a password change event for a user.
type PasswordChange struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	ChangedAt string    `json:"changed_at"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// ChangePasswordInput represents the input required to change a password.
type ChangePasswordInput struct {
	UserID      uuid.UUID `json:"user_id"`
	NewPassword string    `json:"new_password"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// ChangePasswordResponse represents the response from the password change endpoint.
type ChangePasswordResponse struct {
	Message string    `json:"message"`
	UserID  uuid.UUID `json:"user_id"` // Add the UserID field
}

// ChangePassword initiates a password change request using the provided user ID and new password.
func (c *Client) ChangePassword(ctx context.Context, input ChangePasswordInput) (*ChangePasswordResponse, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/changepassword", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var changePasswordResponse ChangePasswordResponse
	if err := json.NewDecoder(resp.Body).Decode(&changePasswordResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &changePasswordResponse, nil
}

// LogPasswordChangeInput represents the input required to log a password change.
type LogPasswordChangeInput struct {
	UserID    uuid.UUID `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// LogPasswordChange initiates a request to log a password change event without actually changing the password.
func (c *Client) LogPasswordChange(ctx context.Context, input LogPasswordChangeInput) error {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/logpasswordchange", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
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

// GetPasswordChangeHistoryInput represents the input required to retrieve password change history.
type GetPasswordChangeHistoryInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// GetPasswordChangeHistoryResponse represents the response from the password change history endpoint.
type GetPasswordChangeHistoryResponse struct {
	Message string           `json:"message"`
	History []PasswordChange `json:"history"`
}

// GetPasswordChangeHistory retrieves the password change history for a user.
func (c *Client) GetPasswordChangeHistory(ctx context.Context, input GetPasswordChangeHistoryInput) (*GetPasswordChangeHistoryResponse, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/getpasswordchangehistory", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var getPasswordChangeHistoryResponse GetPasswordChangeHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&getPasswordChangeHistoryResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &getPasswordChangeHistoryResponse, nil
}

// DeletePasswordChangeRecordsInput represents the input required to delete password change records.
type DeletePasswordChangeRecordsInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// DeletePasswordChangeRecordsResponse represents the response from the password change records deletion endpoint.
type DeletePasswordChangeRecordsResponse struct {
	Message string `json:"message"`
}

func (c *Client) DeletePasswordChangeRecords(ctx context.Context, input DeletePasswordChangeRecordsInput) (*DeletePasswordChangeRecordsResponse, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/deletepasswordchangerecords", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var deletePasswordChangeRecordsResponse DeletePasswordChangeRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&deletePasswordChangeRecordsResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &deletePasswordChangeRecordsResponse, nil
}

// GetRecentPasswordChangeInput represents the input required to get the most recent password change.
type GetRecentPasswordChangeInput struct {
	UserID uuid.UUID `json:"user_id"`
}

// GetRecentPasswordChangeResponse represents the response from the password change retrieval endpoint.
type GetRecentPasswordChangeResponse struct {
	Message        string         `json:"message"`
	PasswordChange PasswordChange `json:"password_change"`
}

func (c *Client) GetRecentPasswordChange(ctx context.Context, input GetRecentPasswordChangeInput) (*GetRecentPasswordChangeResponse, error) {
	// Prepare the payload.
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/getrecentpasswordchange", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Api-Key", c.ApiKey)

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response.
	var getRecentPasswordChangeResponse GetRecentPasswordChangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&getRecentPasswordChangeResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &getRecentPasswordChangeResponse, nil
}
