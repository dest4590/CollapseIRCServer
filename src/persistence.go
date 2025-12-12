package main

import (
	"log"
	"os"
	"strings"
)

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

func (s *Server) loadBannedIPs() {
	data, err := os.ReadFile(bannedIPsFile)
	if err != nil {
		log.Printf("[INFO] No banned IPs file found, starting with empty IP ban list")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.bannedIPs[line] = true
		}
	}
	log.Printf("[INFO] Loaded %d banned IPs", len(s.bannedIPs))
}

func (s *Server) saveBannedIPs() {
	file, err := os.Create(bannedIPsFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create banned IPs file: %v", err)
		return
	}
	defer file.Close()

	for ip := range s.bannedIPs {
		file.WriteString(ip + "\n")
	}
	log.Printf("[INFO] Saved %d banned IPs to file", len(s.bannedIPs))
}

func (s *Server) loadMutedUsers() {
	data, err := os.ReadFile(mutedUsersFile)
	if err != nil {
		log.Printf("[INFO] No muted users file found, starting with empty mute list")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.mutedUsers[line] = true
		}
	}
	log.Printf("[INFO] Loaded %d muted users", len(s.mutedUsers))
}

func (s *Server) saveMutedUsers() {
	file, err := os.Create(mutedUsersFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create muted users file: %v", err)
		return
	}
	defer file.Close()

	for userID := range s.mutedUsers {
		file.WriteString(userID + "\n")
	}
	log.Printf("[INFO] Saved %d muted users to file", len(s.mutedUsers))
}

func (s *Server) loadMutedIPs() {
	data, err := os.ReadFile(mutedIPsFile)
	if err != nil {
		log.Printf("[INFO] No muted IPs file found, starting with empty IP mute list")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.mutedIPs[line] = true
		}
	}
	log.Printf("[INFO] Loaded %d muted IPs", len(s.mutedIPs))
}

func (s *Server) saveMutedIPs() {
	file, err := os.Create(mutedIPsFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create muted IPs file: %v", err)
		return
	}
	defer file.Close()

	for ip := range s.mutedIPs {
		file.WriteString(ip + "\n")
	}
	log.Printf("[INFO] Saved %d muted IPs to file", len(s.mutedIPs))
}
