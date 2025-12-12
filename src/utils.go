package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode"
)

func maskToken(token string) string {
	if len(token) <= tokenMaskLength {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

func sanitizeUsername(username string) (string, error) {
	if len(username) == 0 {
		return "", fmt.Errorf("username cannot be empty")
	}
	if len(username) > maxUsernameChars {
		return "", fmt.Errorf("username too long")
	}

	username = strings.TrimSpace(username)

	if !usernamePattern.MatchString(username) {
		return "", fmt.Errorf("username contains invalid characters")
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(username) {
			return "", fmt.Errorf("username contains prohibited content")
		}
	}

	return username, nil
}

func sanitizeMessage(message string) (string, error) {
	if len(message) == 0 {
		return "", fmt.Errorf("message cannot be empty")
	}
	if len(message) > maxMessageChars {
		return "", fmt.Errorf("message too long")
	}

	var cleaned strings.Builder
	for _, r := range message {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		cleaned.WriteRune(r)
	}
	message = cleaned.String()

	if !messagePattern.MatchString(message) {
		return "", fmt.Errorf("message contains invalid characters")
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(message) {
			return "", fmt.Errorf("message contains prohibited content")
		}
	}

	message = sanitizeMinecraftColors(message)

	return message, nil
}

func sanitizeMinecraftColors(text string) string {
	invalidColorCode := regexp.MustCompile(`§[^0-9a-fklmnor]`)
	return invalidColorCode.ReplaceAllString(text, "§f")
}

func sanitizeString(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()

	for _, p := range dangerousPatterns {
		s = p.ReplaceAllString(s, "")
	}

	spaceRe := regexp.MustCompile(`\s+`)
	s = spaceRe.ReplaceAllString(s, " ")

	runes := []rune(s)
	if len(runes) > maxMessageChars {
		s = string(runes[:maxMessageChars])
	} else {
		s = string(runes)
	}

	s = sanitizeMinecraftColors(s)
	return s
}

func createSecureError(publicMsg, logDetails string, args ...interface{}) error {
	if len(args) > 0 {
		log.Printf("[SECURITY] "+logDetails, args...)
	} else {
		log.Printf("[SECURITY] %s", logDetails)
	}
	return fmt.Errorf("%s", publicMsg)
}

func formatNameWithRole(u *User) string {
	role := strings.ToLower(strings.TrimSpace(u.role))
	if role == "" {
		role = "user"
	}
	color, ok := roleColorMap[role]
	if !ok {
		color = "f"
	}

	roleLabel, ok := displayRoleMap[role]
	if !ok {
		if len(role) > 0 {
			roleLabel = strings.Title(strings.ToLower(role))
		} else {
			roleLabel = role
		}
	}

	client := strings.TrimSpace(u.clientName)
	clientPart := ""
	if client != "" {
		clientPart = fmt.Sprintf(" §7(%s)§r", client)
	}

	return fmt.Sprintf("§%s%s§r%s [§%s%s§r]", color, u.name, clientPart, color, roleLabel)
}
