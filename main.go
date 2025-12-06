package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	cooldown         = 1 * time.Second
	maxMsgLength     = 256
	authURL          = "https://auth.collapseloader.org/auth/status"
	userIDURL        = "https://auth.collapseloader.org/auth/irc-info"
	adminTimeout     = 10 * time.Second
	bannedUsersFile  = "banned_users.txt"
	maxUsernameChars = 32
	maxMessageChars  = 256
	tokenMaskLength  = 8
	historyLimit     = 50
)

var (
	usernamePattern   = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§<>\?{}\[\]"';]{1,256}$`)
	messagePattern    = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§<>\?{}\[\]"';]{1,256}$`)
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0E|\x0F`),
		regexp.MustCompile(`\\x[0-9a-fA-F]{2}`),
	}
)

type IncomingPacket struct {
	Op      string `json:"op"`
	Token   string `json:"token,omitempty"`
	Type    string `json:"type,omitempty"`
	Client  string `json:"client,omitempty"`
	Content string `json:"content,omitempty"`
}

type AuthResponse struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	Role     string      `json:"role"`
}

type Server struct {
	users         map[*User]bool
	bannedUsers   map[string]bool
	broadcast     chan OutgoingPacket
	register      chan *User
	unregister    chan *User
	mutex         sync.Mutex
	userIDCounter uint64
	history       []OutgoingPacket
}

type User struct {
	socket             net.Conn
	encoder            *json.Encoder
	name               string
	userID             string
	role               string
	token              string
	clientName         string
	clientType         string
	lastMessageTime    time.Time
	lastPrivatePartner string
	isBanned           bool
}

type OutgoingPacket struct {
	Type    string `json:"type"`
	Time    string `json:"time,omitempty"`
	Content string `json:"content"`
	History bool   `json:"history,omitempty"`
}

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

func newServer() *Server {
	server := &Server{
		users:         make(map[*User]bool),
		bannedUsers:   make(map[string]bool),
		broadcast:     make(chan OutgoingPacket),
		register:      make(chan *User),
		unregister:    make(chan *User),
		userIDCounter: 1,
		history:       make([]OutgoingPacket, 0, historyLimit),
	}
	server.loadBannedUsers()
	return server
}

func (s *Server) loadBannedUsers() {
	data, err := os.ReadFile(bannedUsersFile)
	if err != nil {
		log.Printf("[INFO] No banned users file found, starting with empty ban list")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.bannedUsers[line] = true
		}
	}
	log.Printf("[INFO] Loaded %d banned users", len(s.bannedUsers))
}

func (s *Server) saveBannedUsers() {
	file, err := os.Create(bannedUsersFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create banned users file: %v", err)
		return
	}
	defer file.Close()

	for userID := range s.bannedUsers {
		file.WriteString(userID + "\n")
	}
	log.Printf("[INFO] Saved %d banned users to file", len(s.bannedUsers))
}

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

func (s *Server) run() {
	for {
		select {
		case user := <-s.register:
			s.mutex.Lock()
			s.users[user] = true
			s.mutex.Unlock()
			log.Printf("[REGISTER] User '%s' (ID: %s, role: %s, client: %s, type: %s) connected from %s", user.name, user.userID, user.role, user.clientName, user.clientType, user.socket.RemoteAddr())
		case user := <-s.unregister:
			s.mutex.Lock()
			if _, ok := s.users[user]; ok {
				delete(s.users, user)
				log.Printf("[UNREGISTER] User '%s' (ID: %s, role: %s, client: %s, type: %s) disconnected from %s", user.name, user.userID, user.role, user.clientName, user.clientType, user.socket.RemoteAddr())
			}
			s.mutex.Unlock()
		case packet := <-s.broadcast:
			s.mutex.Lock()
			activeUsers := 0
			for user := range s.users {
				go func(u *User, p OutgoingPacket) {
					u.sendPacket(p)
				}(user, packet)
				activeUsers++
			}
			s.mutex.Unlock()
			log.Printf("[BROADCAST] Message sent to %d active users", activeUsers)
		}
	}
}

func (s *Server) appendToHistory(packet OutgoingPacket) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.history = append(s.history, packet)
	if len(s.history) > historyLimit {
		overflow := len(s.history) - historyLimit
		s.history = append([]OutgoingPacket(nil), s.history[overflow:]...)
	}
}

func (s *Server) sendHistoryToUser(user *User) {
	s.mutex.Lock()
	historyCopy := append([]OutgoingPacket(nil), s.history...)
	s.mutex.Unlock()

	for _, item := range historyCopy {
		item.History = true
		user.sendPacket(item)
	}
}

func (s *Server) broadcastMessage(packet OutgoingPacket) {
	s.appendToHistory(packet)
	s.broadcast <- packet
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var authPacket IncomingPacket
	err := decoder.Decode(&authPacket)
	if err != nil {
		log.Printf("[ERROR] Failed to decode auth packet from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if authPacket.Op != "auth" {
		log.Printf("[SECURITY] First packet was not auth from %s", conn.RemoteAddr())
		json.NewEncoder(conn).Encode(OutgoingPacket{Type: "error", Content: "Authentication required"})
		return
	}

	token := strings.TrimSpace(authPacket.Token)
	clientType := strings.TrimSpace(authPacket.Type)
	clientName := sanitizeString(authPacket.Client)

	if clientType == "" {
		clientType = "client"
	}
	if clientType == "loader" && clientName == "" {
		clientName = "CollapseLoader"
	}

	isAuthenticated := true
	var realUserID string
	var usernameFromAuth string
	var role string

	if token == "" {
		isAuthenticated = false
		role = "guest"
		s.mutex.Lock()
		guestID := fmt.Sprintf("guest-%d", s.userIDCounter)
		s.userIDCounter++
		s.mutex.Unlock()
		realUserID = guestID
		log.Printf("[AUTH] Guest connection from %s", conn.RemoteAddr())
	} else {
		var err error
		realUserID, usernameFromAuth, role, err = s.authenticateUser(token)
		if err != nil {
			log.Printf("[AUTH] Invalid token for connection %s: %s", conn.RemoteAddr(), maskToken(token))
			s.mutex.Lock()
			guestID := fmt.Sprintf("guest-%d", s.userIDCounter)
			s.userIDCounter++
			s.mutex.Unlock()
			realUserID = guestID
			role = "guest"
			isAuthenticated = false
		}
	}

	username := usernameFromAuth
	if !isAuthenticated {
		username = fmt.Sprintf("Guest-%s", realUserID)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = fmt.Sprintf("User-%s", realUserID)
	}

	sanitizedUsername, err := sanitizeUsername(username)
	if err == nil {
		username = sanitizedUsername
	} else {
		username = sanitizeString(username)
		if username == "" {
			username = fmt.Sprintf("User-%s", realUserID)
		}
	}

	s.mutex.Lock()
	isBanned := s.bannedUsers[realUserID]
	s.mutex.Unlock()

	user := &User{
		socket:             conn,
		encoder:            encoder,
		name:               username,
		userID:             realUserID,
		role:               role,
		token:              token,
		clientName:         clientName,
		clientType:         clientType,
		lastPrivatePartner: "",
		isBanned:           isBanned,
	}

	if !isAuthenticated {
		user.sendSystem("Connected as guest. Commands are disabled, but you can chat.")
	} else if isBanned {
		user.sendSystem("You are banned from writing messages.")
	} else {
		user.sendPacket(OutgoingPacket{
			Type:    "auth_success",
			Content: fmt.Sprintf("Welcome %s!", username),
		})
	}

	s.register <- user
	s.sendHistoryToUser(user)

	defer func() {
		s.unregister <- user
	}()

	for {
		var packet IncomingPacket
		err := decoder.Decode(&packet)
		if err != nil {
			if err != io.EOF {
				log.Printf("[DISCONNECT] Decode error for '%s': %v", user.name, err)
			}
			break
		}

		switch packet.Op {
		case "ping":
			user.sendPacket(OutgoingPacket{Type: "pong", Content: "PONG"})
			continue

		case "chat":
			message := strings.TrimSpace(packet.Content)

			sanitizedMessage, err := sanitizeMessage(message)
			if err != nil {
				user.sendSystem("Invalid message format")
				continue
			}
			message = sanitizedMessage

			currentTime := time.Now()
			if currentTime.Sub(user.lastMessageTime) < cooldown {
				continue
			}
			user.lastMessageTime = currentTime

			if strings.HasPrefix(message, "@") {
				if !isAuthenticated {
					user.sendSystem("Login required to use commands.")
					continue
				}
				log.Printf("[COMMAND] User '%s' issued command: %s", user.name, message)

				if user.isBanned && !strings.HasPrefix(message, "@help") && !strings.HasPrefix(message, "@ping") && !strings.HasPrefix(message, "@online") {
					user.sendSystem("You are banned.")
					continue
				}

				if strings.HasPrefix(message, "@ban ") || strings.HasPrefix(message, "@unban ") || strings.HasPrefix(message, "@sysmsg ") {
					s.handleAdminCommand(user, message)
					continue
				}
				if strings.HasPrefix(message, "@msg ") {
					s.handlePrivateMessage(user, message)
					continue
				}
				if strings.HasPrefix(message, "@r ") {
					s.handleQuickReply(user, message)
					continue
				}
				if s.handleUserCommand(user, message) {
					continue
				}

				var commandPrefix string

				if user.clientType == "loader" {
					commandPrefix = "@"
				} else {
					commandPrefix = "@@"
				}

				user.sendSystem(fmt.Sprintf("Unknown command. Use %shelp", commandPrefix))
				continue
			}

			if user.isBanned {
				user.sendSystem("You are banned.")
				continue
			}

			sender := formatNameWithRole(user)
			fullMessage := fmt.Sprintf("%s: %s", sender, message)
			log.Printf("[MESSAGE] %s", fullMessage)

			outPacket := OutgoingPacket{
				Type:    "chat",
				Time:    time.Now().UTC().Format(time.RFC3339),
				Content: fullMessage,
			}

			s.broadcastMessage(outPacket)
		}
	}
}

func (s *Server) findUserByPartialName(partialName string) *User {
	partialLower := strings.ToLower(partialName)

	for u := range s.users {
		if strings.ToLower(u.name) == partialLower {
			return u
		}
	}

	for u := range s.users {
		if strings.HasPrefix(strings.ToLower(u.name), partialLower) {
			return u
		}
	}

	return nil
}

func (s *Server) findAllMatchingUsers(partialName string) []*User {
	partialLower := strings.ToLower(partialName)
	var matches []*User

	for u := range s.users {
		if strings.ToLower(u.name) == partialLower {
			return []*User{u}
		}
	}

	for u := range s.users {
		if strings.HasPrefix(strings.ToLower(u.name), partialLower) {
			matches = append(matches, u)
		}
	}

	return matches
}

func (s *Server) getMatchingUserNames(partialName string) []string {
	matches := s.findAllMatchingUsers(partialName)
	var names []string
	for _, user := range matches {
		names = append(names, user.name)
	}
	return names
}

func (s *Server) handlePrivateMessage(user *User, message string) {
	parts := strings.Fields(message)
	if len(parts) < 3 {
		user.sendSystem("Usage: @msg <nickname> <message>")
		return
	}

	targetName := parts[1]
	privateMessage := strings.Join(parts[2:], " ")

	matches := s.findAllMatchingUsers(targetName)

	if len(matches) == 0 {
		user.sendSystem(fmt.Sprintf("User '%s' not found", targetName))
		return
	}

	uniqueIDs := make(map[string]bool)
	targetUserID := ""
	targetUsername := ""

	for _, u := range matches {
		if _, exists := uniqueIDs[u.userID]; !exists {
			uniqueIDs[u.userID] = true
			targetUserID = u.userID
			targetUsername = u.name
		}
	}

	if len(uniqueIDs) > 1 {
		var names []string
		for _, u := range matches {
			found := false
			for _, n := range names {
				if n == u.name {
					found = true
					break
				}
			}
			if !found {
				names = append(names, u.name)
			}
		}
		user.sendSystem(fmt.Sprintf("Multiple users match '%s': %s. Be more specific.", targetName, strings.Join(names, ", ")))
		return
	}

	if targetUserID == user.userID {
		user.sendSystem("You cannot send a message to yourself")
		return
	}

	user.lastPrivatePartner = targetUsername

	sentCount := 0
	for _, targetUser := range matches {
		targetUser.lastPrivatePartner = user.name
		targetUser.sendPacket(OutgoingPacket{
			Type:    "private",
			Content: fmt.Sprintf("[PM from %s]: %s", formatNameWithRole(user), privateMessage),
		})
		sentCount++
	}

	user.sendPacket(OutgoingPacket{
		Type:    "private",
		Content: fmt.Sprintf("[PM to %s]: %s", formatNameWithRole(matches[0]), privateMessage),
	})

	log.Printf("[PRIVATE] %s (ID: %s) -> %s (ID: %s) [%d sessions]: %s",
		user.name, user.userID, targetUsername, targetUserID, sentCount, privateMessage)
}

func (s *Server) handleQuickReply(user *User, message string) {
	if user.lastPrivatePartner == "" {
		user.sendSystem("No previous private conversation found")
		return
	}

	parts := strings.Fields(message)
	if len(parts) < 2 {
		user.sendSystem("Usage: @r <message>")
		return
	}

	replyMessage := strings.Join(parts[1:], " ")

	matches := s.findAllMatchingUsers(user.lastPrivatePartner)

	if len(matches) == 0 {
		user.sendSystem(fmt.Sprintf("User '%s' is no longer online", user.lastPrivatePartner))
		return
	}

	var exactMatches []*User

	for _, m := range matches {
		if strings.EqualFold(m.name, user.lastPrivatePartner) {
			exactMatches = append(exactMatches, m)
		}
	}

	if len(exactMatches) == 0 {
		exactMatches = matches
	}

	for _, targetUser := range exactMatches {
		targetUser.lastPrivatePartner = user.name
		targetUser.sendPacket(OutgoingPacket{
			Type:    "private",
			Content: fmt.Sprintf("[PM from %s]: %s", formatNameWithRole(user), replyMessage),
		})
	}

	user.sendPacket(OutgoingPacket{
		Type:    "private",
		Content: fmt.Sprintf("[PM to %s]: %s", formatNameWithRole(exactMatches[0]), replyMessage),
	})

	log.Printf("[PRIVATE REPLY] %s -> %s: %s", user.name, user.lastPrivatePartner, replyMessage)
}
func (u *User) sendPacket(packet OutgoingPacket) {
	err := u.encoder.Encode(packet)
	if err != nil {
		log.Printf("[ERROR] Failed to send JSON to user '%s': %v", u.name, err)
	}
}

func (u *User) sendSystem(message string) {
	u.sendPacket(OutgoingPacket{
		Type:    "system",
		Content: message,
		Time:    time.Now().UTC().Format(time.RFC3339),
	})
}

var roleColorMap = map[string]string{
	"user":      "f",
	"tester":    "a",
	"admin":     "c",
	"developer": "6",
	"owner":     "d",
}

var displayRoleMap = map[string]string{
	"user":      "User",
	"tester":    "Tester",
	"admin":     "Admin",
	"developer": "Developer",
	"owner":     "Owner",
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

func (s *Server) authenticateAdmin(token string) bool {
	client := &http.Client{
		Timeout: adminTimeout,
	}

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create admin auth request: %v", err)
		return false
	}

	req.Header.Set("Authorization", "Token "+token)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to authenticate admin token %s: %v", maskToken(token), err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (s *Server) handleUserCommand(user *User, command string) bool {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}

	cmd := strings.ToLower(parts[0])

	switch cmd {
	case "@ping":
		user.sendSystem("PONG")
		return true
	case "online":
		s.mutex.Lock()
		userCount := len(s.users)
		guestCount := 0
		for u := range s.users {
			if strings.ToLower(u.role) == "guest" {
				guestCount++
			}
		}
		s.mutex.Unlock()

		if guestCount > 0 {
			user.sendSystem(fmt.Sprintf("Channel info: %d users online (%d guests)", userCount, guestCount))
		} else {
			user.sendSystem(fmt.Sprintf("Channel info: %d users online", userCount))
		}
		return true
	case "@who", "@list":
		s.mutex.Lock()
		var userNames []string
		for u := range s.users {
			displayName := u.name

			clientInfo := u.clientName
			if clientInfo == "" {
				clientInfo = u.clientType
			}

			if clientInfo != "" {
				displayName += fmt.Sprintf(" §7(%s)§r", clientInfo)
			}

			if strings.ToLower(u.role) == "guest" {
				displayName += " [guest]"
			}

			userNames = append(userNames, displayName)
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("Online users (%d): %s", len(userNames), strings.Join(userNames, ", ")))
		return true
	case "@help":
		var commandPrefix string

		if user.clientType == "loader" {
			commandPrefix = "@"
		} else {
			commandPrefix = "@@"
		}

		helpText := "Available commands:\n" +
			commandPrefix + "ping - Test server connection\n" +
			commandPrefix + "online - Show number of online users\n" +
			commandPrefix + "who / " + commandPrefix + "list - List online users\n" +
			commandPrefix + "help - Show this help message\n" +
			commandPrefix + "msg <nickname> <message> - Send private message (supports partial names)\n" +
			commandPrefix + "r <message> - Reply to last private message\n" +
			"Admin commands (require authentication):\n" +
			commandPrefix + "ban <user_id> - Ban a user\n" +
			commandPrefix + "unban <user_id> - Unban a user\n" +
			commandPrefix + "sysmsg <message> - Send system message to all users"

		user.sendSystem(helpText)
		return true
	default:
		return false
	}
}

func (s *Server) handleAdminCommand(user *User, command string) bool {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		user.sendSystem("ERROR: Admin command requires parameters")
		return true
	}

	if !s.authenticateAdmin(user.token) {
		user.sendSystem("ERROR: You are not authorized")
		return true
	}

	cmd := strings.ToLower(parts[0])
	action := cmd[1:]

	switch action {
	case "ban":
		targetID := parts[1]
		s.mutex.Lock()
		s.bannedUsers[targetID] = true
		s.mutex.Unlock()
		s.saveBannedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isBanned = true
				connectedUser.sendSystem("You have been banned.")
				break
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("User %s banned", targetID))
		return true
	case "unban":
		targetID := parts[1]
		s.mutex.Lock()
		delete(s.bannedUsers, targetID)
		s.mutex.Unlock()
		s.saveBannedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isBanned = false
				connectedUser.sendSystem("You have been unbanned.")
				break
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("User %s unbanned", targetID))
		return true
	case "sysmsg":
		role := strings.ToLower(strings.TrimSpace(user.role))
		if role != "admin" && role != "developer" && role != "owner" {
			user.sendSystem("Permission denied")
			return true
		}

		systemMessage := strings.Join(parts[1:], " ")
		mcBold := "§l" + systemMessage + "§r"
		fullMessage := fmt.Sprintf("§c§lSystem§r: %s", mcBold)

		s.broadcastMessage(OutgoingPacket{
			Type:    "chat",
			Content: fullMessage,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
		user.sendSystem("System message sent")
		return true
	default:
		user.sendSystem("Unknown admin command")
		return true
	}
}

func main() {
	port := "1338"
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[FATAL] Error starting server: %v", err)
	}
	defer listener.Close()

	server := newServer()
	go server.run()

	log.Printf("[STARTUP] IRC Server started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Connection error: %v", err)
			continue
		}
		go server.handleConnection(conn)
	}
}
