package main

import (
	"log"
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
