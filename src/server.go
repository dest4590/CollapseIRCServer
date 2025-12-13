package main

import (
	"log"
	"strings"
	"time"
)

const roomStateTick = 15 * time.Second

func newServer() *Server {
	server := &Server{
		users:         make(map[*User]bool),
		usernames:     make(map[string]*User),
		bannedUsers:   make(map[string]bool),
		mutedUsers:    make(map[string]bool),
		mutedIPs:      make(map[string]bool),
		bannedIPs:     make(map[string]bool),
		broadcast:     make(chan OutgoingPacket),
		register:      make(chan *User),
		unregister:    make(chan *User),
		userIDCounter: 1,
		history:       make([]OutgoingPacket, 0, historyLimit),
	}
	server.loadMutedUsers()
	server.loadMutedIPs()
	server.loadBannedUsers()
	server.loadBannedIPs()
	return server
}

func (s *Server) run() {
	ticker := time.NewTicker(roomStateTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.broadcastRoomState()
		case user := <-s.register:
			s.addUser(user)
			log.Printf("[REGISTER] User '%s' (ID: %s, role: %s, client: %s, type: %s) connected from %s", user.name, user.userID, user.role, user.clientName, user.clientType, user.socket.RemoteAddr())
		case user := <-s.unregister:
			if s.removeUser(user) {
				log.Printf("[UNREGISTER] User '%s' (ID: %s, role: %s, client: %s, type: %s) disconnected from %s", user.name, user.userID, user.role, user.clientName, user.clientType, user.socket.RemoteAddr())
			}
		case packet := <-s.broadcast:
			users := s.snapshotUsers()
			for _, u := range users {
				go u.sendPacket(packet)
			}
			log.Printf("[BROADCAST] Message sent to %d active users", len(users))
		}
	}
}

func (s *Server) addUser(user *User) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.users[user] = true
	s.usernames[strings.ToLower(user.name)] = user
}

func (s *Server) removeUser(user *User) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.users[user]; !ok {
		return false
	}
	delete(s.users, user)
	delete(s.usernames, strings.ToLower(user.name))
	return true
}

func (s *Server) snapshotUsers() []*User {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	users := make([]*User, 0, len(s.users))
	for u := range s.users {
		users = append(users, u)
	}
	return users
}

func (s *Server) findUserByID(userID string) *User {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for u := range s.users {
		if u.userID == userID {
			return u
		}
	}
	return nil
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

func (s *Server) broadcastRoomState() {
	s.mutex.Lock()
	usersCount := 0
	guestsCount := 0
	var targets []*User

	for user := range s.users {
		if user.role == "guest" {
			guestsCount++
		} else {
			usersCount++
		}
		if user.clientType == "loader" {
			targets = append(targets, user)
		}
	}
	s.mutex.Unlock()

	packet := OutgoingPacket{
		Type: "room_state",
		RoomState: &RoomState{
			OnlineUsers:  usersCount,
			OnlineGuests: guestsCount,
		},
	}

	for _, user := range targets {
		go user.sendPacket(packet)
	}
}

func (s *Server) findUserByPartialName(partialName string) *User {
	partialLower := strings.ToLower(strings.TrimSpace(partialName))
	if partialLower == "" {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if u, ok := s.usernames[partialLower]; ok {
		return u
	}
	for u := range s.users {
		if strings.HasPrefix(strings.ToLower(u.name), partialLower) {
			return u
		}
	}
	return nil
}

func (s *Server) findAllMatchingUsers(partialName string) []*User {
	partialLower := strings.ToLower(strings.TrimSpace(partialName))
	if partialLower == "" {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if u, ok := s.usernames[partialLower]; ok {
		return []*User{u}
	}

	var matches []*User
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
