package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	s.mutex.Lock()
	ipBanned := s.bannedIPs[host]
	ipMuted := s.mutedIPs[host]
	s.mutex.Unlock()

	if ipBanned {
		log.Printf("[SECURITY] Rejected connection from banned IP: %s", host)
		json.NewEncoder(conn).Encode(OutgoingPacket{Type: "error", Content: "Your IP is banned"})
		return
	}

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var authPacket IncomingPacket
	err = decoder.Decode(&authPacket)
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
		if after, ok := strings.CutPrefix(realUserID, "guest-"); ok {
			username = "Guest-" + after
		} else {
			username = fmt.Sprintf("Guest-%s", realUserID)
		}
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
	isMuted := s.mutedUsers[realUserID] || ipMuted
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
		ip:                 host,
		lastPrivatePartner: "",
		isBanned:           isBanned,
		isMuted:            isMuted,
	}

	if !isAuthenticated {
		user.sendSystem("Connected as guest. Commands are disabled, but you can chat.")
	} else if isBanned {
		user.sendSystem("You are banned from writing messages.")
	} else if isMuted {
		user.sendSystem("You are muted.")
	}

	s.register <- user

	if strings.ToLower(strings.TrimSpace(user.clientType)) != "client" {
		s.sendHistoryToUser(user)
	}

	defer func() {
		s.unregister <- user
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
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

			if user.isMuted {
				user.sendSystem("You are muted.")
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
