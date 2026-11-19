package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mauropm/wadjet/internal/auth"
)

// registrationOpen controls whether /auth/register accepts new accounts.
// Self-hosted single-tenant: only the bootstrap admin exists initially, and
// further registration requires an existing admin session to invite.
// For simplicity v1 allows open registration only while zero users exist.

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, token, err := s.auth.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.audit.LogRequest(r, nil, "auth.login_failed", "user", body.Email, nil)
			WriteError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		WriteError(w, http.StatusInternalServerError, "authentication failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "wadjet_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   72 * 3600,
		Secure:   !s.cfg.IsDevelopment(),
	})
	s.audit.LogRequest(r, &user.ID, "auth.login", "user", user.ID.String(), nil)
	WriteJSON(w, http.StatusOK, map[string]any{"user": user, "token": token})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, err := s.auth.CreateUser(r.Context(), body.Email, body.Name, body.Password, "user")
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailTaken):
			WriteError(w, http.StatusConflict, err.Error())
		case errors.Is(err, auth.ErrWeakPassword):
			WriteError(w, http.StatusBadRequest, err.Error())
		default:
			WriteError(w, http.StatusInternalServerError, "registration failed")
		}
		return
	}
	s.audit.LogRequest(r, &user.ID, "auth.register", "user", user.ID.String(), nil)
	WriteJSON(w, http.StatusCreated, user)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if t := TokenFromRequest(r); t != "" {
		_ = s.auth.Logout(r.Context(), t)
	}
	http.SetCookie(w, &http.Cookie{Name: "wadjet_session", Value: "", Path: "/", MaxAge: -1})
	WriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, UserFromContext(r.Context()))
}

// handleAudit exposes the audit trail (authenticated).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	logs, err := s.audit.List(r.Context(), limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to load audit log")
		return
	}
	WriteList(w, logs, len(logs))
}

// handleEvents streams all server events as Server-Sent Events.
// Clients filter by the "event:" field (topic).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, cancel := s.bus.Subscribe()
	defer cancel()

	// Initial comment so the client sees the stream open immediately.
	fmt.Fprint(w, ": wadjet events\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev.Payload)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Topic, data)
			flusher.Flush()
		}
	}
}
