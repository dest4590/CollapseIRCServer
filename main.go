package main

import (
	"bufio"
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
	maxNameLength    = 32
	maxMsgLength     = 256
	authURL          = "https://auth.collapseloader.org/auth/status"
	userIDURL        = "https://auth.collapseloader.org/auth/irc-info"
	adminTimeout     = 10 * time.Second
	bannedUsersFile  = "banned_users.txt"
	maxUsernameChars = 32
	maxMessageChars  = 256
	tokenMaskLength  = 8
)

var (
	usernamePattern   = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§]{1,256}$`)
	messagePattern    = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§]{1,256}$`)
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0E|\x0F`),
		regexp.MustCompile(`\\x[0-9a-fA-F]{2}`),
	}
)

type AuthResponse struct {
	UserID interface{} `json:"user_id"`
	Role   string      `json:"role"`
}

type Server struct {
	users         map[*User]bool
	bannedUsers   map[string]bool
	broadcast     chan string
	register      chan *User
	unregister    chan *User
	mutex         sync.Mutex
	userIDCounter uint64
}

type User struct {
	socket             net.Conn
	name               string
	userID             string
	role               string
	token              string
	clientName         string
	lastMessageTime    time.Time
	lastPrivatePartner string
	isBanned           bool
}

func maskToken(token string) string {
	if len(token) <= tokenMaskLength {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]

	//return token
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
		broadcast:     make(chan string),
		register:      make(chan *User),
		unregister:    make(chan *User),
		userIDCounter: 1,
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

func (s *Server) authenticateUser(token string) (string, string, error) {
	client := &http.Client{
		Timeout: adminTimeout,
	}

	resp, err := client.Get(userIDURL + "/" + token + "/")
	if err != nil {
		return "", "", createSecureError(
			"authentication failed",
			"failed to authenticate token %s: %v", maskToken(token), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", createSecureError(
			"authentication failed",
			"invalid token, status code: %d, token: %s", resp.StatusCode, maskToken(token))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", createSecureError(
			"authentication failed",
			"failed to read auth response for token %s: %v", maskToken(token), err)
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(body, &authResponse); err != nil {
		return "", "", createSecureError(
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
		return "", "", createSecureError(
			"authentication failed",
			"unexpected user_id type %T for token %s", v, maskToken(token))
	}

	role := strings.TrimSpace(authResponse.Role)

	return userID, role, nil
}

func (s *Server) run() {
	for {
		select {
		case user := <-s.register:
			s.mutex.Lock()
			s.users[user] = true
			s.mutex.Unlock()
			log.Printf("[REGISTER] User '%s' (ID: %s, role: %s, client: %s) connected from %s", user.name, user.userID, user.role, user.clientName, user.socket.RemoteAddr())
		case user := <-s.unregister:
			s.mutex.Lock()
			if _, ok := s.users[user]; ok {
				delete(s.users, user)
				log.Printf("[UNREGISTER] User '%s' (ID: %s, role: %s, client: %s) disconnected from %s", user.name, user.userID, user.role, user.clientName, user.socket.RemoteAddr())
			}
			s.mutex.Unlock()
		case message := <-s.broadcast:
			s.mutex.Lock()
			activeUsers := 0
			for user := range s.users {
				go user.send(message)
				activeUsers++
			}
			s.mutex.Unlock()
			log.Printf("[BROADCAST] Message sent to %d active users", activeUsers)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	authData, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ERROR] Could not read auth data from %s: %v", conn.RemoteAddr(), err)
		return
	}
	authData = strings.TrimSpace(authData)

	if isHTTPRequest(authData) {
		log.Printf("[SECURITY] Ignoring HTTP request from: %s", conn.RemoteAddr())
		return
	}

	parts := strings.Split(authData, "@:@")
	if len(parts) < 3 {
		conn.Write([]byte("Invalid authentication format\n"))
		log.Printf("[SECURITY] Invalid auth format from %s (length: %d)", conn.RemoteAddr(), len(parts))
		return
	}

	providedUserID := strings.TrimSpace(parts[0])
	username := strings.TrimSpace(parts[1])
	token := strings.TrimSpace(parts[2])
	clientName := ""

	if len(parts) >= 4 {
		clientName = strings.TrimSpace(strings.Join(parts[3:], "@:@"))
		clientName = sanitizeString(clientName)
	}

	sanitizedUsername, err := sanitizeUsername(username)
	if err != nil {
		conn.Write([]byte("Invalid username\n"))
		log.Printf("[SECURITY] Username validation failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	username = sanitizedUsername

	realUserID, role, err := s.authenticateUser(token)
	if err != nil {
		conn.Write([]byte("Authentication failed\n"))
		return
	}

	if providedUserID != realUserID {
		conn.Write([]byte("Authentication failed\n"))
		log.Printf("[SECURITY] User ID mismatch from %s. Provided: %s, Expected: %s, Token: %s",
			conn.RemoteAddr(), providedUserID, realUserID, maskToken(token))
		return
	}

	s.mutex.Lock()
	isBanned := s.bannedUsers[realUserID]
	s.mutex.Unlock()

	user := &User{
		socket:             conn,
		name:               username,
		userID:             realUserID,
		role:               role,
		token:              token,
		clientName:         clientName,
		lastPrivatePartner: "",
		isBanned:           isBanned,
	}

	if isBanned {
		user.send("You are banned from writing messages, but you can read them")
		log.Printf("[SECURITY] Banned user %s (%s) role=%s connected from %s", username, realUserID, role, conn.RemoteAddr())
	}

	s.register <- user

	defer func() {
		s.unregister <- user
	}()

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[DISCONNECT] Socket closed for '%s' (ID: %s) from %s", user.name, user.userID, conn.RemoteAddr())
			break
		}
		message = strings.TrimSpace(message)

		sanitizedMessage, err := sanitizeMessage(message)
		if err != nil {
			user.send("Invalid message format")
			log.Printf("[SECURITY] Message validation failed from user '%s' (ID: %s): %v", user.name, user.userID, err)
			continue
		}
		message = sanitizedMessage

		currentTime := time.Now()
		if currentTime.Sub(user.lastMessageTime) < cooldown {
			log.Printf("[COOLDOWN] Message from user '%s' (ID: %s) blocked due to cooldown", user.name, user.userID)
			continue
		}
		user.lastMessageTime = currentTime

		if user.isBanned && !strings.HasPrefix(message, "@ping") && !strings.HasPrefix(message, "@online") && !strings.HasPrefix(message, "@help") {
			user.send("You are banned and cannot send messages")
			log.Printf("[BANNED] Message blocked from banned user '%s' (ID: %s): %s", user.name, user.userID, message)
			continue
		}

		if strings.HasPrefix(message, "@") {
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

			user.send("Unknown command. Use @@help to see available commands")
			log.Printf("[WARNING] Unknown command '%s' from user '%s' (ID: %s)", message, user.name, user.userID)
			continue
		}

		sender := formatNameWithRole(user)
		fullMessage := fmt.Sprintf("%s: %s", sender, message)
		log.Printf("[MESSAGE] %s", fullMessage)

		s.broadcast <- fullMessage
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
		user.send("Usage: @msg <nickname> <message>")
		return
	}

	targetName := parts[1]
	privateMessage := strings.Join(parts[2:], " ")

	s.mutex.Lock()
	targetUser := s.findUserByPartialName(targetName)
	s.mutex.Unlock()

	if targetUser == nil {
		user.send(fmt.Sprintf("User '%s' not found", targetName))
		return
	}

	if len(s.findAllMatchingUsers(targetName)) > 1 {
		matches := s.getMatchingUserNames(targetName)
		user.send(fmt.Sprintf("Multiple users match '%s': %s. Please be more specific.", targetName, strings.Join(matches, ", ")))
		return
	}

	if targetUser == user {
		user.send("You cannot send a message to yourself")
		return
	}

	user.lastPrivatePartner = targetName
	targetUser.lastPrivatePartner = user.name

	targetUser.send(fmt.Sprintf("[PM from %s]: %s", formatNameWithRole(user), privateMessage))
	user.send(fmt.Sprintf("[PM to %s]: %s", formatNameWithRole(targetUser), privateMessage))

	log.Printf("[PRIVATE] %s -> %s: %s", user.name, targetName, privateMessage)
}

func (s *Server) handleQuickReply(user *User, message string) {
	if user.lastPrivatePartner == "" {
		user.send("No previous private conversation found")
		return
	}

	parts := strings.Fields(message)
	if len(parts) < 2 {
		user.send("Usage: @r <message>")
		return
	}

	replyMessage := strings.Join(parts[1:], " ")

	s.mutex.Lock()
	targetUser := s.findUserByPartialName(user.lastPrivatePartner)
	s.mutex.Unlock()

	if targetUser == nil {
		user.send(fmt.Sprintf("User '%s' is no longer online", user.lastPrivatePartner))
		return
	}

	targetUser.lastPrivatePartner = user.name

	targetUser.send(fmt.Sprintf("[PM from %s]: %s", formatNameWithRole(user), replyMessage))
	user.send(fmt.Sprintf("[PM to %s]: %s", formatNameWithRole(targetUser), replyMessage))

	log.Printf("[PRIVATE REPLY] %s -> %s: %s", user.name, user.lastPrivatePartner, replyMessage)
}

func (u *User) send(message string) {
	_, err := u.socket.Write([]byte(message + "\n"))
	if err != nil {
		log.Printf("[ERROR] Failed to send message to user '%s' (ID: %s): %v", u.name, u.userID, err)
	}
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
			first := strings.ToUpper(role[:1])
			rest := ""
			if len(role) > 1 {
				rest = strings.ToLower(role[1:])
			}
			roleLabel = first + rest
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

	isAdmin := resp.StatusCode == 200
	log.Printf("[AUTH] Admin authentication %s for token %s",
		map[bool]string{true: "successful", false: "failed"}[isAdmin], maskToken(token))
	return isAdmin
}

func (s *Server) handleUserCommand(user *User, command string) bool {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}

	cmd := strings.ToLower(parts[0])
	log.Printf("[COMMAND] User '%s' (ID: %s) executed command: %s", user.name, user.userID, cmd)

	switch cmd {
	case "@ping":
		user.send("PONG")
		return true
	case "@online":
		s.mutex.Lock()
		userCount := len(s.users)
		s.mutex.Unlock()
		user.send(fmt.Sprintf("Channel info: %d users online", userCount))
		return true
	case "@who", "@list":
		s.mutex.Lock()
		var userNames []string
		for user := range s.users {
			userNames = append(userNames, user.name)
		}
		s.mutex.Unlock()
		user.send(fmt.Sprintf("Online users (%d): %s", len(userNames), strings.Join(userNames, ", ")))
		return true
	case "@help":
		helpText := "Available commands:\n" +
			"@@ping - Test server connection\n" +
			"@@online - Show number of online users\n" +
			"@@who / @@list - List online users\n" +
			"@@help - Show this help message\n" +
			"@@msg <nickname> <message> - Send private message (supports partial names)\n" +
			"@@r <message> - Reply to last private message\n" +
			"Admin commands (require authentication):\n" +
			"@@ban <user_id> - Ban a user\n" +
			"@@unban <user_id> - Unban a user\n" +
			"@@sysmsg <message> - Send system message to all users"
		user.send(helpText)
		return true
	default:
		return false
	}
}

func (s *Server) handleAdminCommand(user *User, command string) bool {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		user.send("ERROR: Admin command requires parameters")
		return true
	}

	if !s.authenticateAdmin(user.token) {
		user.send("ERROR: You are not authorized to use admin commands")
		log.Printf("[SECURITY] Failed admin authentication attempt from user '%s' (ID: %s)", user.name, user.userID)
		return true
	}

	cmd := strings.ToLower(parts[0])
	action := cmd[1:]
	log.Printf("[ADMIN] User '%s' (ID: %s) executed admin command: %s", user.name, user.userID, action)

	switch action {
	case "ban":
		if len(parts) < 2 {
			user.send("ERROR: ban requires user ID")
			return true
		}
		targetID := parts[1]
		s.mutex.Lock()
		s.bannedUsers[targetID] = true
		s.mutex.Unlock()

		s.saveBannedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isBanned = true
				connectedUser.send("You have been banned from writing messages")
				break
			}
		}
		s.mutex.Unlock()

		user.send(fmt.Sprintf("User %s has been banned", targetID))
		log.Printf("[ADMIN] User %s banned by admin '%s' (ID: %s)", targetID, user.name, user.userID)
		return true
	case "unban":
		if len(parts) < 2 {
			user.send("ERROR: unban requires user ID")
			return true
		}
		targetID := parts[1]
		s.mutex.Lock()
		delete(s.bannedUsers, targetID)
		s.mutex.Unlock()

		s.saveBannedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isBanned = false
				connectedUser.send("You have been unbanned")
				break
			}
		}
		s.mutex.Unlock()

		user.send(fmt.Sprintf("User %s has been unbanned", targetID))
		log.Printf("[ADMIN] User %s unbanned by admin '%s' (ID: %s)", targetID, user.name, user.userID)
		return true
	case "sysmsg":
		if len(parts) < 2 {
			user.send("ERROR: sysmsg requires a message")
			return true
		}

		role := strings.ToLower(strings.TrimSpace(user.role))
		if role != "admin" && role != "developer" && role != "owner" {
			user.send("ERROR: You do not have permission to use sysmsg")
			log.Printf("[SECURITY] User '%s' (ID: %s) with role '%s' attempted sysmsg", user.name, user.userID, user.role)
			return true
		}

		systemMessage := strings.Join(parts[1:], " ")
		mcBold := "§l" + systemMessage + "§r"
		fullMessage := fmt.Sprintf("§c§lSystem§r: %s", mcBold)

		s.broadcast <- fullMessage
		user.send("System message sent successfully")
		log.Printf("[ADMIN] System message sent by admin '%s' (ID: %s): %s", user.name, user.userID, systemMessage)
		return true
	default:
		user.send("ERROR: Unknown admin command")
		return true
	}
}

func isHTTPRequest(firstLine string) bool {
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	for _, method := range httpMethods {
		if strings.HasPrefix(firstLine, method+" ") {
			return true
		}
	}
	return false
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
	log.Printf("[STARTUP] Auth endpoint: %s", authURL)
	log.Printf("[STARTUP] Server ready to accept connections")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Error accepting connection: %v", err)
			continue
		}

		log.Printf("[CONNECTION] New connection from %s", conn.RemoteAddr())

		go server.handleConnection(conn)
	}
}
