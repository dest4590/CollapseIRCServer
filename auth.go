package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (s *Server) authenticateUser(token string) (string, string, string, error) {
	client := &http.Client{
		Timeout: adminTimeout,
	}

	resp, err := client.Get(userIDURL + "/" + token + "/")
	if err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to authenticate token %s: %v", maskToken(token), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", "", createSecureError(
			"authentication failed",
			"invalid token, status code: %d, token: %s", resp.StatusCode, maskToken(token))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to read auth response for token %s: %v", maskToken(token), err)
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(body, &authResponse); err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to parse auth JSON for token %s: %v", maskToken(token), err)
	}

	var userID string
	switch v := authResponse.UserID.(type) {
	case string:
		userID = v
	case float64:
		userID = fmt.Sprintf("%.0f", v)
	case int:
		userID = fmt.Sprintf("%d", v)
	default:
		return "", "", "", createSecureError(
			"authentication failed",
			"unexpected user_id type %T for token %s", v, maskToken(token))
	}

	role := strings.TrimSpace(authResponse.Role)
	username := strings.TrimSpace(authResponse.Username)

	return userID, username, role, nil
}

func (s *Server) authenticateAdmin(token string) bool {
	client := &http.Client{
		Timeout: adminTimeout,
	}

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		// log.Printf("[ERROR] Failed to create admin auth request: %v", err)
		return false
	}

	req.Header.Set("Authorization", "Token "+token)

	resp, err := client.Do(req)
	if err != nil {
		// log.Printf("[ERROR] Failed to authenticate admin token %s: %v", maskToken(token), err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (s *Server) fetchUserProfile(userID string, token string) (*UserProfile, error) {
	client := &http.Client{
		Timeout: adminTimeout,
	}

	url := fmt.Sprintf(userProfileURL, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch profile, status: %d", resp.StatusCode)
	}

	var profile UserProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}
