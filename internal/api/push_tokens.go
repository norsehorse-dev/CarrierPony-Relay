package api

import (
	"context"
	"log"
	"net/http"
)

// lowerASCII lowercases A to Z and leaves every other byte alone.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// ownDevice checks the device_id of a request and finds the device under the
// logged-in identity. It returns the device's row id, or the refusal to send.
func (s *Server) ownDevice(ctx context.Context, where, fpr string, in input) (int64, *result) {
	deviceID := in.text("device_id")
	if !reHex32.MatchString(deviceID) {
		res := fail(http.StatusBadRequest, "bad_device_id")
		return 0, &res
	}
	device, found, err := s.deviceOf(ctx, fpr, deviceID)
	if err != nil {
		log.Printf("carrierpony: %s: %v", where, err)
		res := serverError()
		return 0, &res
	}
	if !found {
		res := fail(http.StatusForbidden, "unknown_device")
		return 0, &res
	}
	return device, nil
}

// registerPush stores the token this relay pushes a device with, and which
// service it belongs to. A request without a platform is from an iPhone: every
// app that predates the field is one.
func (s *Server) registerPush(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("device_id", "push_token"); name != "" {
		return missing(name)
	}
	if !reHex32.MatchString(in.text("device_id")) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	token := cutBytes(in.text("push_token"), 255)
	platform := "apns"
	if in["platform"] != nil {
		platform = lowerASCII(in.text("platform"))
	}
	if platform != "apns" && platform != "fcm" {
		return fail(http.StatusBadRequest, "bad_platform")
	}
	device, refusal := s.ownDevice(ctx, "register-push", fpr, in)
	if refusal != nil {
		return *refusal
	}
	if _, err := s.store.DB.ExecContext(ctx, "UPDATE devices SET push_token = ?, platform = ? WHERE id = ?", token, platform, device); err != nil {
		log.Printf("carrierpony: register-push: %v", err)
		return serverError()
	}
	return ok(field{"ok", true})
}

// registerWake stores or clears the token the push gateway knows a device by.
// The app sends it when a user on a self-hosted relay opts in to gateway push.
// An empty or absent token opts out. The relay never sees the push token
// itself, only this opaque one it hands back to the gateway.
func (s *Server) registerWake(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("device_id"); name != "" {
		return missing(name)
	}
	if !reHex32.MatchString(in.text("device_id")) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	wake := in.text("wake_token")
	if wake != "" && !reHex64.MatchString(wake) {
		return fail(http.StatusBadRequest, "bad_wake_token")
	}
	device, refusal := s.ownDevice(ctx, "register-wake", fpr, in)
	if refusal != nil {
		return *refusal
	}
	var stored any
	if wake != "" {
		stored = wake
	}
	if _, err := s.store.DB.ExecContext(ctx, "UPDATE devices SET wake_token = ? WHERE id = ?", stored, device); err != nil {
		log.Printf("carrierpony: register-wake: %v", err)
		return serverError()
	}
	return ok(field{"ok", true})
}
