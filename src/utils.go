package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode"
	"unicode/utf8"
)

func maskToken(token string) string {
	if len(token) <= tokenMaskLength {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

func sanitizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}
	if utf8.RuneCountInString(username) > maxUsernameChars {
		return "", fmt.Errorf("username too long")
	}

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
	if message == "" {
		return "", fmt.Errorf("message cannot be empty")
	}
	if utf8.RuneCountInString(message) > maxMessageChars {
		return "", fmt.Errorf("message too long")
	}

	message = removeControlChars(message)

	if !messagePattern.MatchString(message) {
		return "", fmt.Errorf("message contains invalid characters")
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(message) {
			return "", fmt.Errorf("message contains prohibited content")
		}
	}

	return sanitizeMinecraftColors(message), nil
}

func sanitizeMinecraftColors(text string) string {
	return invalidMCColorRe.ReplaceAllString(text, "§f")
}

func sanitizeString(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	s := removeControlChars(input)

	for _, p := range dangerousPatterns {
		s = p.ReplaceAllString(s, "")
	}

	s = multiSpaceRe.ReplaceAllString(s, " ")

	runes := []rune(s)
	if len(runes) > maxMessageChars {
		s = string(runes[:maxMessageChars])
	} else {
		s = string(runes)
	}

	s = sanitizeMinecraftColors(s)
	return s
}

func removeControlChars(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func createSecureError(publicMsg, logDetails string, args ...interface{}) error {
	if len(args) > 0 {
		log.Printf("[SECURITY] "+logDetails, args...)
	} else {
		log.Printf("[SECURITY] %s", logDetails)
	}
	return errors.New(publicMsg)
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
		roleLabel = titleASCII(strings.ToLower(role))
	}

	client := strings.TrimSpace(u.clientName)
	clientPart := ""
	if client != "" {
		clientPart = fmt.Sprintf(" §7(%s)§r", client)
	}

	return fmt.Sprintf("§%s%s§r%s [§%s%s§r]", color, u.name, clientPart, color, roleLabel)
}

func titleASCII(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
