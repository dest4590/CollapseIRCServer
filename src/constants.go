package main

import (
	"regexp"
	"time"
)

const (
	cooldown         = 1 * time.Second
	adminTimeout     = 10 * time.Second
	bannedUsersFile  = "banned_users.txt"
	bannedIPsFile    = "banned_ips.txt"
	mutedUsersFile   = "muted_users.txt"
	mutedIPsFile     = "muted_ips.txt"
	maxUsernameChars = 32
	maxMessageChars  = 256
	tokenMaskLength  = 8
	historyLimit     = 50
	atlasBaseURLEnv  = "ATLAS_BASE_URL"
	defaultAtlasURL  = "https://atlas.collapseloader.org"
	atlasInfoPath    = "/api/v1/users/me"
	atlasUserPath    = "/api/v1/users/%s"

	guestMessagesPerSecond = 1
	guestMessagesPerMinute = 30
	guestBurstSize         = 2

	userMessagesPerSecond = 2
	userMessagesPerMinute = 60
	userBurstSize         = 3

	violationThreshold    = 5
	violationResetTime    = 2 * time.Minute
	tempMuteDuration      = 5 * time.Minute
	rateLimitWindowSecond = 1 * time.Second
	rateLimitWindowMinute = 1 * time.Minute
)

var (
	usernamePattern   = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§<>\?{}\[\]"';]{1,256}$`)
	messagePattern    = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}§<>\?{}\[\]"';]{1,256}$`)
	invalidMCColorRe  = regexp.MustCompile(`§[^0-9a-fklmnor]`)
	multiSpaceRe      = regexp.MustCompile(`\s+`)
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0E|\x0F`),
		regexp.MustCompile(`\\x[0-9a-fA-F]{2}`),
	}
)

var roleColorMap = map[string]string{
	"user":      "f",
	"tester":    "a",
	"admin":     "c",
	"developer": "6",
	"owner":     "d",
}

var displayRoleMap = map[string]string{
	"user":      "User",
	"tester":    "Tester",
	"admin":     "Admin",
	"developer": "Developer",
	"owner":     "Owner",
}
