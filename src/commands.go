package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func commandPrefixFor(user *User) string {
	if user.clientType == "loader" {
		return "@"
	}
	return "@@"
}

func isGuest(user *User) bool {
	return strings.EqualFold(strings.TrimSpace(user.role), "guest")
}

func userDisplayName(user *User) string {
	displayName := user.name

	clientInfo := strings.TrimSpace(user.clientName)
	if clientInfo == "" {
		clientInfo = strings.TrimSpace(user.clientType)
	}
	if clientInfo != "" {
		displayName += fmt.Sprintf(" §7(%s)§r", clientInfo)
	}

	return displayName
}

func (s *Server) resolveTarget(target string) (userID string, ip string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", ""
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if u, ok := s.usernames[strings.ToLower(target)]; ok {
		return u.userID, u.ip
	}
	for u := range s.users {
		if u.userID == target {
			return u.userID, u.ip
		}
	}
	return target, ""
}

type resolvedUserTarget struct {
	userID        string
	username      string
	usernameLower string
	ip            string
}

func (s *Server) resolveUserTarget(input string) (*resolvedUserTarget, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("missing target")
	}

	if id, ip := s.resolveTarget(input); ip != "" || id != input {
		u := s.findUserByID(id)
		if u != nil {
			return &resolvedUserTarget{
				userID:        u.userID,
				username:      u.name,
				usernameLower: strings.ToLower(u.name),
				ip:            u.ip,
			}, nil
		}
		return &resolvedUserTarget{userID: id, ip: ip}, nil
	}

	matches := s.findAllMatchingUsers(input)
	if len(matches) == 1 {
		u := matches[0]
		return &resolvedUserTarget{
			userID:        u.userID,
			username:      u.name,
			usernameLower: strings.ToLower(u.name),
			ip:            u.ip,
		}, nil
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, u := range matches {
			names = append(names, u.name)
		}
		return nil, fmt.Errorf("multiple users match '%s': %s", input, strings.Join(names, ", "))
	}

	if _, err := strconv.Atoi(input); err == nil || strings.HasPrefix(strings.ToLower(input), "guest-") {
		return &resolvedUserTarget{userID: input}, nil
	}

	username := strings.TrimSpace(input)
	return &resolvedUserTarget{username: username, usernameLower: strings.ToLower(username)}, nil
}

func parseIPOrEmpty(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (s *Server) setUserBanned(target *resolvedUserTarget, banned bool) int {
	if target == nil {
		return 0
	}

	s.mutex.Lock()
	if banned {
		if target.userID != "" {
			s.bannedUsers[target.userID] = true
		}
		if target.username != "" {
			s.bannedUsers[target.username] = true
		}
		if target.usernameLower != "" {
			s.bannedUsers[target.usernameLower] = true
		}
	} else {
		if target.userID != "" {
			delete(s.bannedUsers, target.userID)
		}
		if target.username != "" {
			delete(s.bannedUsers, target.username)
		}
		if target.usernameLower != "" {
			delete(s.bannedUsers, target.usernameLower)
		}
	}
	s.mutex.Unlock()

	s.saveBannedUsers()

	affected := 0
	for _, u := range s.snapshotUsers() {
		if target.userID != "" && u.userID != target.userID {
			continue
		}
		if target.userID == "" && target.usernameLower != "" && strings.ToLower(u.name) != target.usernameLower {
			continue
		}
		u.isBanned = banned
		affected++
		if banned {
			u.sendSystem("You have been banned.")
			u.socket.Close()
		} else {
			u.sendSystem("You have been unbanned.")
		}
	}
	return affected
}

func (s *Server) setUserMuted(target *resolvedUserTarget, muted bool) int {
	if target == nil {
		return 0
	}

	s.mutex.Lock()
	if muted {
		if target.userID != "" {
			s.mutedUsers[target.userID] = true
		}
		if target.username != "" {
			s.mutedUsers[target.username] = true
		}
		if target.usernameLower != "" {
			s.mutedUsers[target.usernameLower] = true
		}
	} else {
		if target.userID != "" {
			delete(s.mutedUsers, target.userID)
		}
		if target.username != "" {
			delete(s.mutedUsers, target.username)
		}
		if target.usernameLower != "" {
			delete(s.mutedUsers, target.usernameLower)
		}
	}
	s.mutex.Unlock()

	s.saveMutedUsers()

	affected := 0
	for _, u := range s.snapshotUsers() {
		if target.userID != "" && u.userID != target.userID {
			continue
		}
		if target.userID == "" && target.usernameLower != "" && strings.ToLower(u.name) != target.usernameLower {
			continue
		}
		u.isMuted = muted
		affected++
		if muted {
			u.sendSystem("You have been muted.")
		} else {
			u.sendSystem("You have been unmuted.")
		}
	}
	return affected
}

func (s *Server) setIPBanned(ip string, banned bool) int {
	ip = parseIPOrEmpty(ip)
	if ip == "" {
		return 0
	}

	s.mutex.Lock()
	if banned {
		s.bannedIPs[ip] = true
	} else {
		delete(s.bannedIPs, ip)
	}
	s.mutex.Unlock()

	s.saveBannedIPs()

	affected := 0
	for _, u := range s.snapshotUsers() {
		if u.ip != ip {
			continue
		}
		u.isBanned = banned
		affected++
		if banned {
			u.sendSystem("Your IP has been banned.")
			u.socket.Close()
		}
	}
	return affected
}

func (s *Server) setIPMuted(ip string, muted bool) int {
	ip = parseIPOrEmpty(ip)
	if ip == "" {
		return 0
	}

	s.mutex.Lock()
	if muted {
		s.mutedIPs[ip] = true
	} else {
		delete(s.mutedIPs, ip)
	}
	s.mutex.Unlock()

	s.saveMutedIPs()

	affected := 0
	for _, u := range s.snapshotUsers() {
		if u.ip != ip {
			continue
		}
		u.isMuted = muted
		affected++
		if muted {
			u.sendSystem("Your IP has been muted.")
		} else {
			u.sendSystem("Your IP has been unmuted.")
		}
	}
	return affected
}

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
		users := s.snapshotUsers()
		totalCount := len(users)
		guestCount := 0
		for _, u := range users {
			if isGuest(u) {
				guestCount++
			}
		}

		if guestCount > 0 {
			user.sendSystem(fmt.Sprintf("Channel info: %d users online (%d guests)", totalCount, guestCount))
		} else {
			user.sendSystem(fmt.Sprintf("Channel info: %d users online", totalCount))
		}
		return true
	case "@who", "@list":
		users := s.snapshotUsers()
		var usersList []string
		var guestsList []string
		for _, u := range users {
			displayName := userDisplayName(u)
			if isGuest(u) {
				guestsList = append(guestsList, displayName)
			} else {
				usersList = append(usersList, displayName)
			}
		}

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
		commandPrefix := commandPrefixFor(user)

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
			targetUser := s.findUserByID(targetUserID)
			if targetUser == nil {
				user.sendSystem("Guest not found online.")
				return true
			}
			info := fmt.Sprintf("Guest Profile:\nName: %s\nID: %s\nIP: %s\nConnected: Yes", targetUser.name, targetUser.userID, targetUser.ip)
			user.sendSystem(info)
			return true
		}

		var targetIP string
		if u := s.findUserByID(targetUserID); u != nil {
			targetIP = u.ip
		}

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
	if len(parts) == 0 {
		return false
	}

	cmd := strings.ToLower(parts[0])
	if !strings.HasPrefix(cmd, "@") {
		return false
	}
	action := cmd[1:]

	if action != "sysmsg" && len(parts) < 2 {
		user.sendSystem("ERROR: Admin command requires a target")
		return true
	}

	if !s.authenticateAdmin(user.token) {
		user.sendSystem("ERROR: You are not authorized")
		return true
	}

	switch action {
	case "ban":
		target, err := s.resolveUserTarget(parts[1])
		if err != nil {
			user.sendSystem("ERROR: " + err.Error())
			return true
		}
		affected := s.setUserBanned(target, true)
		if target.userID != "" {
			user.sendSystem(fmt.Sprintf("Banned %s (affected %d connections)", target.userID, affected))
		} else {
			user.sendSystem(fmt.Sprintf("Banned name '%s' (affected %d connections)", target.usernameLower, affected))
		}
		return true
	case "unban":
		target, err := s.resolveUserTarget(parts[1])
		if err != nil {
			user.sendSystem("ERROR: " + err.Error())
			return true
		}
		affected := s.setUserBanned(target, false)
		if target.userID != "" {
			user.sendSystem(fmt.Sprintf("Unbanned %s (affected %d connections)", target.userID, affected))
		} else {
			user.sendSystem(fmt.Sprintf("Unbanned name '%s' (affected %d connections)", target.usernameLower, affected))
		}
		return true
	case "banip":
		ip := parseIPOrEmpty(parts[1])
		if ip == "" {
			target, err := s.resolveUserTarget(parts[1])
			if err != nil {
				user.sendSystem("ERROR: " + err.Error())
				return true
			}
			ip = target.ip
		}
		if ip == "" {
			user.sendSystem("ERROR: provide an IP or an online user")
			return true
		}
		affected := s.setIPBanned(ip, true)
		user.sendSystem(fmt.Sprintf("Banned IP %s (affected %d connections)", ip, affected))
		return true
	case "unbanip":
		ip := parseIPOrEmpty(parts[1])
		if ip == "" {
			user.sendSystem("ERROR: invalid IP")
			return true
		}
		affected := s.setIPBanned(ip, false)
		user.sendSystem(fmt.Sprintf("Unbanned IP %s (affected %d connections)", ip, affected))
		return true
	case "mute":
		target, err := s.resolveUserTarget(parts[1])
		if err != nil {
			user.sendSystem("ERROR: " + err.Error())
			return true
		}
		affected := s.setUserMuted(target, true)
		if target.userID != "" {
			user.sendSystem(fmt.Sprintf("Muted %s (affected %d connections)", target.userID, affected))
		} else {
			user.sendSystem(fmt.Sprintf("Muted name '%s' (affected %d connections)", target.usernameLower, affected))
		}
		return true
	case "unmute":
		target, err := s.resolveUserTarget(parts[1])
		if err != nil {
			user.sendSystem("ERROR: " + err.Error())
			return true
		}
		affected := s.setUserMuted(target, false)
		if target.userID != "" {
			user.sendSystem(fmt.Sprintf("Unmuted %s (affected %d connections)", target.userID, affected))
		} else {
			user.sendSystem(fmt.Sprintf("Unmuted name '%s' (affected %d connections)", target.usernameLower, affected))
		}
		return true
	case "muteip":
		ip := parseIPOrEmpty(parts[1])
		if ip == "" {
			target, err := s.resolveUserTarget(parts[1])
			if err != nil {
				user.sendSystem("ERROR: " + err.Error())
				return true
			}
			ip = target.ip
		}
		if ip == "" {
			user.sendSystem("ERROR: provide an IP or an online user")
			return true
		}
		affected := s.setIPMuted(ip, true)
		user.sendSystem(fmt.Sprintf("Muted IP %s (affected %d connections)", ip, affected))
		return true
	case "unmuteip":
		ip := parseIPOrEmpty(parts[1])
		if ip == "" {
			user.sendSystem("ERROR: invalid IP")
			return true
		}
		affected := s.setIPMuted(ip, false)
		user.sendSystem(fmt.Sprintf("Unmuted IP %s (affected %d connections)", ip, affected))
		return true
	case "sysmsg":
		role := strings.ToLower(strings.TrimSpace(user.role))
		if role != "admin" && role != "developer" && role != "owner" {
			user.sendSystem("Permission denied")
			return true
		}
		if len(parts) < 2 {
			user.sendSystem("Usage: @sysmsg <message>")
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
	if user.isMuted {
		user.sendSystem("You are muted.")
		return
	}

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
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, u := range matches {
			names = append(names, u.name)
		}
		user.sendSystem(fmt.Sprintf("Multiple users match '%s': %s. Be more specific.", targetName, strings.Join(names, ", ")))
		return
	}

	targetUser := matches[0]
	if targetUser.userID == user.userID {
		user.sendSystem("You cannot send a message to yourself")
		return
	}

	user.lastPrivatePartner = targetUser.name
	targetUser.lastPrivatePartner = user.name

	targetUser.sendPacket(OutgoingPacket{
		Type:    "private",
		Content: fmt.Sprintf("[PM from %s]: %s", formatNameWithRole(user), privateMessage),
	})
	user.sendPacket(OutgoingPacket{
		Type:    "private",
		Content: fmt.Sprintf("[PM to %s]: %s", formatNameWithRole(targetUser), privateMessage),
	})
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
