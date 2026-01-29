package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func authClient() *http.Client {
	return &http.Client{Timeout: adminTimeout}
}

func stringifyUserID(v any) (string, error) {
	switch typed := v.(type) {
	case string:
		return typed, nil
	case float64:
		return fmt.Sprintf("%.0f", typed), nil
	case int:
		return fmt.Sprintf("%d", typed), nil
	default:
		return "", fmt.Errorf("unexpected user_id type %T", v)
	}
}

func (s *Server) authenticateUser(token string) (string, string, string, error) {
	userID, username, role, err := s.authenticateUserAtlas(token)
	if err == nil {
		return userID, username, role, nil
	}

	return s.authenticateUserLegacy(token)
}

func (s *Server) authenticateUserLegacy(token string) (string, string, string, error) {
	resp, err := authClient().Get(userIDURL + "/" + token + "/")
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

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to decode auth JSON for token %s: %v", maskToken(token), err)
	}

	userID, err := stringifyUserID(authResponse.UserID)
	if err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"%v for token %s", err, maskToken(token))
	}

	role := strings.TrimSpace(authResponse.Role)
	username := strings.TrimSpace(authResponse.Username)

	return userID, username, role, nil
}

func (s *Server) authenticateUserAtlas(token string) (string, string, string, error) {
	url := s.atlasBaseURL + atlasInfoPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to create Atlas request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := authClient().Do(req)
	if err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to authenticate via Atlas: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", "", createSecureError(
			"authentication failed",
			"Atlas invalid token, status code: %d", resp.StatusCode)
	}

	var atlasResponse AtlasApiResponse[AtlasUserMeResponse]
	if err := json.NewDecoder(resp.Body).Decode(&atlasResponse); err != nil {
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to decode Atlas auth JSON: %v", err)
	}

	if !atlasResponse.Success {
		return "", "", "", createSecureError(
			"authentication failed",
			"Atlas authentication unsuccessful: %s", atlasResponse.Error)
	}

	user := atlasResponse.Data
	userID := fmt.Sprintf("%d", user.ID)
	username := user.Username
	role := strings.ToLower(user.Role)

	return userID, username, role, nil
}

func (s *Server) authenticateAdmin(token string) bool {
	if s.authenticateAdminAtlas(token) {
		return true
	}

	return s.authenticateAdminLegacy(token)
}

func (s *Server) authenticateAdminLegacy(token string) bool {
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		// log.Printf("[ERROR] Failed to create admin auth request: %v", err)
		return false
	}

	req.Header.Set("Authorization", "Token "+token)

	resp, err := authClient().Do(req)
	if err != nil {
		// log.Printf("[ERROR] Failed to authenticate admin token %s: %v", maskToken(token), err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (s *Server) authenticateAdminAtlas(token string) bool {
	url := s.atlasBaseURL + atlasInfoPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := authClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	var atlasResponse AtlasApiResponse[AtlasUserMeResponse]
	if err := json.NewDecoder(resp.Body).Decode(&atlasResponse); err != nil {
		return false
	}

	if !atlasResponse.Success {
		return false
	}

	role := strings.ToLower(atlasResponse.Data.Role)
	return role == "admin" || role == "owner" || role == "developer"
}

func (s *Server) fetchUserProfile(userID string, token string) (*UserProfile, error) {
	url := fmt.Sprintf(userProfileURL, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	resp, err := authClient().Do(req)
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
