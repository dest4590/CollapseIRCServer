package main

import (
	"log"
	"os"
	"sort"
	"strings"
)

func loadStringSet(filename, label string, set map[string]bool) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO] No %s file found, starting with empty list", label)
			return
		}
		log.Printf("[ERROR] Failed to read %s file: %v", label, err)
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	log.Printf("[INFO] Loaded %d %s", len(set), label)
}

func saveStringKeys(filename, label string, keys []string) {
	sort.Strings(keys)
	data := strings.Join(keys, "\n")
	if len(keys) > 0 {
		data += "\n"
	}

	if err := os.WriteFile(filename, []byte(data), 0644); err != nil {
		log.Printf("[ERROR] Failed to write %s file: %v", label, err)
		return
	}
	log.Printf("[INFO] Saved %d %s to file", len(keys), label)
}

func (s *Server) loadBannedUsers() {
	loadStringSet(bannedUsersFile, "banned users", s.bannedUsers)
}

func (s *Server) saveBannedUsers() {
	s.mutex.Lock()
	keys := make([]string, 0, len(s.bannedUsers))
	for k := range s.bannedUsers {
		keys = append(keys, k)
	}
	s.mutex.Unlock()
	saveStringKeys(bannedUsersFile, "banned users", keys)
}

func (s *Server) loadBannedIPs() {
	loadStringSet(bannedIPsFile, "banned IPs", s.bannedIPs)
}

func (s *Server) saveBannedIPs() {
	s.mutex.Lock()
	keys := make([]string, 0, len(s.bannedIPs))
	for k := range s.bannedIPs {
		keys = append(keys, k)
	}
	s.mutex.Unlock()
	saveStringKeys(bannedIPsFile, "banned IPs", keys)
}

func (s *Server) loadMutedUsers() {
	loadStringSet(mutedUsersFile, "muted users", s.mutedUsers)
}

func (s *Server) saveMutedUsers() {
	s.mutex.Lock()
	keys := make([]string, 0, len(s.mutedUsers))
	for k := range s.mutedUsers {
		keys = append(keys, k)
	}
	s.mutex.Unlock()
	saveStringKeys(mutedUsersFile, "muted users", keys)
}

func (s *Server) loadMutedIPs() {
	loadStringSet(mutedIPsFile, "muted IPs", s.mutedIPs)
}

func (s *Server) saveMutedIPs() {
	s.mutex.Lock()
	keys := make([]string, 0, len(s.mutedIPs))
	for k := range s.mutedIPs {
		keys = append(keys, k)
	}
	s.mutex.Unlock()
	saveStringKeys(mutedIPsFile, "muted IPs", keys)
}
