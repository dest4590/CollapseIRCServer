package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

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
		var usersList []string
		var guestsList []string
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
				guestsList = append(guestsList, displayName)
			} else {
				usersList = append(usersList, displayName)
			}
		}
		s.mutex.Unlock()

		total := len(usersList) + len(guestsList)
		var b strings.Builder
		fmt.Fprintf(&b, "Online users (%d):\n", total)
		if len(usersList) > 0 {
			b.WriteString("Users:\n")
			b.WriteString(strings.Join(usersList, "\n"))
			b.WriteString("\n")
		} else {
			b.WriteString("Users: none\n")
		}
		if len(guestsList) > 0 {
			b.WriteString("Guests:\n")
			b.WriteString(strings.Join(guestsList, "\n"))
		} else {
			b.WriteString("Guests: none")
		}

		user.sendSystem(b.String())
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
			commandPrefix + "r <message> - Reply to last private message\n"

		role := strings.ToLower(strings.TrimSpace(user.role))
		if role == "admin" || role == "owner" {
			helpText += "Admin commands (require authentication):\n" +
				commandPrefix + "profile [nickname] - View user profile\n" +
				commandPrefix + "ban <user_id> - Ban a user\n" +
				commandPrefix + "unban <user_id> - Unban a user\n" +
				commandPrefix + "banip <user_id|ip> - Ban an IP address\n" +
				commandPrefix + "unbanip <ip> - Unban an IP address\n" +
				commandPrefix + "mute <user_id> - Mute a user\n" +
				commandPrefix + "unmute <user_id> - Unmute a user\n" +
				commandPrefix + "muteip <user_id|ip> - Mute an IP address\n" +
				commandPrefix + "unmuteip <ip> - Unmute an IP address\n" +
				commandPrefix + "sysmsg <message> - Send system message to all users"
		}

		user.sendSystem(helpText)
		return true
	case "@profile":
		if !s.authenticateAdmin(user.token) {
			user.sendSystem("ERROR: You are not authorized")
			return true
		}

		var targetUserID string
		if len(parts) < 2 {
			targetUserID = user.userID
		} else {
			targetName := parts[1]
			if _, err := strconv.Atoi(targetName); err == nil {
				targetUserID = targetName
			} else {
				targetUser := s.findUserByPartialName(targetName)
				if targetUser == nil {
					user.sendSystem(fmt.Sprintf("User '%s' not found online.", targetName))
					return true
				}
				targetUserID = targetUser.userID
			}
		}

		if strings.HasPrefix(targetUserID, "guest-") {
			var targetUser *User
			s.mutex.Lock()
			for u := range s.users {
				if u.userID == targetUserID {
					targetUser = u
					break
				}
			}
			s.mutex.Unlock()

			if targetUser != nil {
				info := fmt.Sprintf("Guest Profile:\nName: %s\nID: %s\nIP: %s\nConnected: Yes", targetUser.name, targetUser.userID, targetUser.ip)
				user.sendSystem(info)
			} else {
				user.sendSystem("Guest not found online.")
			}
			return true
		}

		var targetIP string
		s.mutex.Lock()
		for u := range s.users {
			if u.userID == targetUserID {
				targetIP = u.ip
				break
			}
		}
		s.mutex.Unlock()

		go func(uid, token, ip string) {
			profile, err := s.fetchUserProfile(uid, token)
			if err != nil {
				user.sendSystem("Failed to fetch profile: " + err.Error())
				return
			}
			s.sendProfileInfo(user, profile, ip)
		}(targetUserID, user.token, targetIP)

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
	case "banip":
		target := parts[1]
		var ipToBan string

		s.mutex.Lock()
		for u := range s.users {
			if u.userID == target {
				ipToBan = u.ip
				break
			}
		}
		s.mutex.Unlock()

		if ipToBan == "" {
			ipToBan = target
		}

		s.mutex.Lock()
		s.bannedIPs[ipToBan] = true
		s.mutex.Unlock()
		s.saveBannedIPs()

		s.mutex.Lock()
		for u := range s.users {
			if u.ip == ipToBan {
				u.isBanned = true
				u.sendSystem("Your IP has been banned.")
				u.socket.Close()
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("IP %s banned", ipToBan))
		return true
	case "unbanip":
		targetIP := parts[1]
		s.mutex.Lock()
		delete(s.bannedIPs, targetIP)
		s.mutex.Unlock()
		s.saveBannedIPs()

		user.sendSystem(fmt.Sprintf("IP %s unbanned", targetIP))
		return true
	case "mute":
		targetID := parts[1]
		s.mutex.Lock()
		s.mutedUsers[targetID] = true
		s.mutex.Unlock()
		s.saveMutedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isMuted = true
				connectedUser.sendSystem("You have been muted.")
				break
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("User %s muted", targetID))
		return true
	case "unmute":
		targetID := parts[1]
		s.mutex.Lock()
		delete(s.mutedUsers, targetID)
		s.mutex.Unlock()
		s.saveMutedUsers()

		s.mutex.Lock()
		for connectedUser := range s.users {
			if connectedUser.userID == targetID {
				connectedUser.isMuted = false
				connectedUser.sendSystem("You have been unmuted.")
				break
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("User %s unmuted", targetID))
		return true
	case "muteip":
		target := parts[1]
		var ipToMute string

		s.mutex.Lock()
		for u := range s.users {
			if u.userID == target {
				ipToMute = u.ip
				break
			}
		}
		s.mutex.Unlock()

		if ipToMute == "" {
			ipToMute = target
		}

		s.mutex.Lock()
		s.mutedIPs[ipToMute] = true
		s.mutex.Unlock()
		s.saveMutedIPs()

		s.mutex.Lock()
		for u := range s.users {
			if u.ip == ipToMute {
				u.isMuted = true
				u.sendSystem("Your IP has been muted.")
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("IP %s muted", ipToMute))
		return true
	case "unmuteip":
		targetIP := parts[1]
		s.mutex.Lock()
		delete(s.mutedIPs, targetIP)
		s.mutex.Unlock()
		s.saveMutedIPs()

		s.mutex.Lock()
		for u := range s.users {
			if u.ip == targetIP {
				u.isMuted = false
				u.sendSystem("Your IP has been unmuted.")
			}
		}
		s.mutex.Unlock()

		user.sendSystem(fmt.Sprintf("IP %s unmuted", targetIP))
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
			found := slices.Contains(names, u.name)
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

	// log.Printf("[PRIVATE] %s (ID: %s) -> %s (ID: %s) [%d sessions]: %s",
	// 	user.name, user.userID, targetUsername, targetUserID, sentCount, privateMessage)
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

	// log.Printf("[PRIVATE REPLY] %s -> %s: %s", user.name, user.lastPrivatePartner, replyMessage)
}

func (s *Server) sendProfileInfo(user *User, profile *UserProfile, ip string) {
	var b strings.Builder
	fmt.Fprintf(&b, "Profile for %s (ID: %d):\n", profile.Username, profile.ID)
	if ip != "" {
		fmt.Fprintf(&b, "IP: %s\n", ip)
	}
	if profile.Nickname != nil {
		fmt.Fprintf(&b, "Nickname: %s\n", *profile.Nickname)
	}
	if profile.Role != nil {
		fmt.Fprintf(&b, "Role: %s\n", *profile.Role)
	}
	if profile.MemberSince != nil {
		fmt.Fprintf(&b, "Member Since: %s\n", *profile.MemberSince)
	}
	if profile.Status != nil {
		status := "Offline"
		if profile.Status.IsOnline {
			status = "Online"
		}
		fmt.Fprintf(&b, "Status: %s", status)
		if profile.Status.CurrentClient != nil {
			fmt.Fprintf(&b, " using %s", *profile.Status.CurrentClient)
		}
		b.WriteString("\n")
	}
	if len(profile.SocialLinks) > 0 {
		b.WriteString("Social Links:\n")
		for _, link := range profile.SocialLinks {
			fmt.Fprintf(&b, "- %s: %s\n", link.Platform, link.URL)
		}
	}

	user.sendSystem(b.String())
}
