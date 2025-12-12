package main

import (
	"log"
	"strings"
	"time"
)

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
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.broadcastRoomState()
		case user := <-s.register:
			s.mutex.Lock()
			s.users[user] = true
			s.usernames[strings.ToLower(user.name)] = user
			s.mutex.Unlock()
			log.Printf("[REGISTER] User '%s' (ID: %s, role: %s, client: %s, type: %s) connected from %s", user.name, user.userID, user.role, user.clientName, user.clientType, user.socket.RemoteAddr())
		case user := <-s.unregister:
			s.mutex.Lock()
			if _, ok := s.users[user]; ok {
				delete(s.users, user)
				delete(s.usernames, strings.ToLower(user.name))
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

func (s *Server) broadcastRoomState() {
	s.mutex.Lock()
	usersCount := 0
	guestsCount := 0
	for user := range s.users {
		if user.role == "guest" {
			guestsCount++
		} else {
			usersCount++
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

	s.mutex.Lock()
	for user := range s.users {
		if user.clientType == "loader" {
			go user.sendPacket(packet)
		}
	}
	s.mutex.Unlock()
}

func (s *Server) findUserByPartialName(partialName string) *User {
	partialLower := strings.ToLower(partialName)

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
	partialLower := strings.ToLower(partialName)
	var matches []*User

	if u, ok := s.usernames[partialLower]; ok {
		return []*User{u}
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
