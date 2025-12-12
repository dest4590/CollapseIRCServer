package main

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

type IncomingPacket struct {
	Op      string `json:"op"`
	Token   string `json:"token,omitempty"`
	Type    string `json:"type,omitempty"`
	Client  string `json:"client,omitempty"`
	Content string `json:"content,omitempty"`
}

type AuthResponse struct {
	UserID   any    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type UserProfile struct {
	ID          int          `json:"id"`
	Username    string       `json:"username"`
	Nickname    *string      `json:"nickname"`
	Role        *string      `json:"role"`
	MemberSince *string      `json:"member_since"`
	AvatarURL   *string      `json:"avatar_url"`
	SocialLinks []SocialLink `json:"social_links"`
	Status      *UserStatus  `json:"status"`
}

type SocialLink struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
}

type UserStatus struct {
	IsOnline      bool    `json:"is_online"`
	LastSeen      *string `json:"last_seen"`
	CurrentClient *string `json:"current_client"`
}

type Server struct {
	users         map[*User]bool
	usernames     map[string]*User
	bannedUsers   map[string]bool
	bannedIPs     map[string]bool
	mutedUsers    map[string]bool
	mutedIPs      map[string]bool
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
	ip                 string
	lastMessageTime    time.Time
	lastPrivatePartner string
	isBanned           bool
	isMuted            bool
	mutex              sync.Mutex
}

type SenderInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type RoomState struct {
	OnlineUsers  int `json:"online_users"`
	OnlineGuests int `json:"online_guests"`
}

type OutgoingPacket struct {
	Type      string      `json:"type"`
	ID        string      `json:"id,omitempty"`
	Time      string      `json:"time,omitempty"`
	Sender    *SenderInfo `json:"sender,omitempty"`
	Content   string      `json:"content,omitempty"`
	History   bool        `json:"history,omitempty"`
	RoomState *RoomState  `json:"room_state,omitempty"`
}
