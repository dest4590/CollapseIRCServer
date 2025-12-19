package main

import (
	"log"
	"strings"
	"time"
)

func (u *User) sendPacket(packet OutgoingPacket) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
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

func (u *User) isAdminOrOwner() bool {
	role := strings.ToLower(strings.TrimSpace(u.role))
	return role == "admin" || role == "owner"
}
