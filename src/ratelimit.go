package main

import (
	"fmt"
	"time"
)

type RateLimitConfig struct {
	MessagesPerSecond int
	MessagesPerMinute int
	BurstSize         int
}

func getRateLimitConfig(role string) RateLimitConfig {
	switch role {
	case "guest":
		return RateLimitConfig{
			MessagesPerSecond: guestMessagesPerSecond,
			MessagesPerMinute: guestMessagesPerMinute,
			BurstSize:         guestBurstSize,
		}
	default:
		return RateLimitConfig{
			MessagesPerSecond: userMessagesPerSecond,
			MessagesPerMinute: userMessagesPerMinute,
			BurstSize:         userBurstSize,
		}
	}
}

func (u *User) checkRateLimit() (bool, string) {
	if u.isAdminOrOwner() {
		return true, ""
	}

	now := time.Now()

	if !u.tempMutedUntil.IsZero() && now.Before(u.tempMutedUntil) {
		remaining := u.tempMutedUntil.Sub(now)
		return false, fmt.Sprintf("You are temporarily muted for %d more seconds due to spam.", int(remaining.Seconds()))
	}
	if !u.tempMutedUntil.IsZero() && now.After(u.tempMutedUntil) {
		u.tempMutedUntil = time.Time{}
		u.rateLimitViolations = 0
	}

	if !u.lastViolationTime.IsZero() && now.Sub(u.lastViolationTime) > violationResetTime {
		u.rateLimitViolations = 0
	}

	config := getRateLimitConfig(u.role)

	cutoffMinute := now.Add(-rateLimitWindowMinute)
	validTimestamps := make([]time.Time, 0, len(u.messageTimestamps))
	for _, ts := range u.messageTimestamps {
		if ts.After(cutoffMinute) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	u.messageTimestamps = validTimestamps

	cutoffSecond := now.Add(-rateLimitWindowSecond)
	messagesInLastSecond := 0
	for _, ts := range u.messageTimestamps {
		if ts.After(cutoffSecond) {
			messagesInLastSecond++
		}
	}

	messagesInLastMinute := len(u.messageTimestamps)

	if messagesInLastSecond >= config.MessagesPerSecond {
		u.recordViolation()
		return false, fmt.Sprintf("Rate limit: Maximum %d messages per second. Slow down!", config.MessagesPerSecond)
	}
	if messagesInLastMinute >= config.MessagesPerMinute {
		u.recordViolation()
		return false, fmt.Sprintf("Rate limit: Maximum %d messages per minute. Take a break!", config.MessagesPerMinute)
	}
	cutoffBurst := now.Add(-3 * time.Second)
	messagesInBurst := 0
	for _, ts := range u.messageTimestamps {
		if ts.After(cutoffBurst) {
			messagesInBurst++
		}
	}

	if messagesInBurst >= config.BurstSize {
		u.recordViolation()
		return false, fmt.Sprintf("Rate limit: Maximum %d messages in quick succession. Slow down!", config.BurstSize)
	}
	u.messageTimestamps = append(u.messageTimestamps, now)
	return true, ""
}

func (u *User) recordViolation() {
	u.rateLimitViolations++
	u.lastViolationTime = time.Now()

	if u.rateLimitViolations >= violationThreshold {
		u.tempMutedUntil = time.Now().Add(tempMuteDuration)
		u.rateLimitViolations = 0
	}
}

func (u *User) getRateLimitStatus() string {
	if u.isAdminOrOwner() {
		return "Rate limiting: Disabled (privileged user)"
	}

	config := getRateLimitConfig(u.role)
	now := time.Now()

	cutoffSecond := now.Add(-rateLimitWindowSecond)
	cutoffMinute := now.Add(-rateLimitWindowMinute)

	messagesInLastSecond := 0
	messagesInLastMinute := 0

	for _, ts := range u.messageTimestamps {
		if ts.After(cutoffSecond) {
			messagesInLastSecond++
		}
		if ts.After(cutoffMinute) {
			messagesInLastMinute++
		}
	}

	status := fmt.Sprintf("Rate limit status:\n")
	status += fmt.Sprintf("  Last second: %d/%d messages\n", messagesInLastSecond, config.MessagesPerSecond)
	status += fmt.Sprintf("  Last minute: %d/%d messages\n", messagesInLastMinute, config.MessagesPerMinute)
	status += fmt.Sprintf("  Violations: %d/%d\n", u.rateLimitViolations, violationThreshold)

	if !u.tempMutedUntil.IsZero() && now.Before(u.tempMutedUntil) {
		remaining := u.tempMutedUntil.Sub(now)
		status += fmt.Sprintf("  Temporarily muted for: %d seconds\n", int(remaining.Seconds()))
	}

	return status
}
