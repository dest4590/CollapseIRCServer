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

func normalizeRole(role string) string {
	normalized := strings.ToLower(strings.TrimSpace(role))
	if normalized == "" {
		return ""
	}

	normalized = strings.TrimPrefix(normalized, "role_")
	return normalized
}

func resolveAtlasRole(user AtlasUserMeResponse) string {
	if user.Profile.Role != nil {
		if profileRole := normalizeRole(*user.Profile.Role); profileRole != "" {
			return profileRole
		}
	}

	return normalizeRole(user.Role)
}

func (s *Server) authenticateUser(token string) (string, string, string, error) {
	return s.authenticateUserAtlas(token)
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
			"Atlas invalid token (URL: %s), status code: %d", url, resp.StatusCode)
	}

	var atlasResponse AtlasApiResponse[AtlasUserMeResponse]
	if err := json.NewDecoder(resp.Body).Decode(&atlasResponse); err != nil {
		// Try to read and log the raw body on decode failure
		return "", "", "", createSecureError(
			"authentication failed",
			"failed to decode Atlas auth JSON for token %s: %v", maskToken(token), err)
	}

	if !atlasResponse.Success {
		return "", "", "", createSecureError(
			"authentication failed",
			"Atlas authentication unsuccessful: %s", atlasResponse.Error)
	}

	user := atlasResponse.Data
	userID := fmt.Sprintf("%d", user.ID)
	username := user.Username
	role := resolveAtlasRole(user)
	if role == "" {
		role = "user"
	}

	return userID, username, role, nil
}

func (s *Server) authenticateAdmin(token string) bool {
	return s.authenticateAdminAtlas(token)
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

	resolvedRole := resolveAtlasRole(atlasResponse.Data)
	return resolvedRole == "admin" || resolvedRole == "owner" || resolvedRole == "developer"
}

func (s *Server) fetchUserProfile(userID string, token string) (*UserProfile, error) {
	url := fmt.Sprintf(s.atlasBaseURL+atlasUserPath, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := authClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch profile from Atlas, status: %d", resp.StatusCode)
	}

	var atlasResponse AtlasApiResponse[AtlasPublicUserResponse]
	if err := json.NewDecoder(resp.Body).Decode(&atlasResponse); err != nil {
		return nil, err
	}

	if !atlasResponse.Success {
		return nil, fmt.Errorf("failed to fetch profile from Atlas: %s", atlasResponse.Error)
	}

	data := atlasResponse.Data
	profile := &UserProfile{
		ID:       data.ID,
		Username: data.Username,
	}

	if data.Profile != nil {
		profile.Nickname = data.Profile.Nickname
		profile.AvatarURL = data.Profile.AvatarURL
		if data.Profile.Role != nil {
			role := normalizeRole(*data.Profile.Role)
			if role != "" {
				profile.Role = &role
			}
		}
		profile.SocialLinks = data.Profile.SocialLinks
	}

	if data.Status != nil {
		isOnline := strings.EqualFold(data.Status.Status, "ONLINE")
		profile.Status = &UserStatus{
			IsOnline:      isOnline,
			CurrentClient: data.Status.ClientName,
		}
	}

	return profile, nil
}
