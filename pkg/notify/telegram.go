package notify

// Package notify isolates notification delivery so transports can change later.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"chicha-pulse/pkg/alert"
)

// Sender hides the destination so the pipeline can evolve without changing the caller.
type Sender interface {
	Send(ctx context.Context, message string) error
	Validate() error
}

// TelegramSender ships notifications to a Telegram channel using basic HTTP calls.
type TelegramSender struct {
	token  string
	chatID string
	client *http.Client
}

// NewTelegram returns a sender with a shared HTTP client to reuse connections.
func NewTelegram(token, chatID string) *TelegramSender {
	return &TelegramSender{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Validate ensures we have enough configuration before running a pipeline.
func (sender *TelegramSender) Validate() error {
	if sender.token == "" || sender.chatID == "" {
		return errors.New("telegram-token and telegram-chat-id are required")
	}
	return nil
}

// Send posts a message to Telegram without extra dependencies.
func (sender *TelegramSender) Send(ctx context.Context, message string) error {
	payload := map[string]string{
		"chat_id": sender.chatID,
		"text":    message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := sender.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("telegram returned %s", response.Status)
	}
	return nil
}

func (sender *TelegramSender) endpoint() string {
	return fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", sender.token)
}

// ---- Notification pipeline ----

// Start listens for alert events and delivers them asynchronously using channels.
func Start(ctx context.Context, sender Sender, alerts <-chan alert.Event) error {
	if sender == nil {
		return errors.New("sender is required")
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-alerts:
				if !ok {
					return
				}
				message := formatMessage(event)
				_ = sender.Send(ctx, message)
			}
		}
	}()
	return nil
}

func formatMessage(event alert.Event) string {
	statusLabel := "OK"
	if event.Status != 0 {
		statusLabel = fmt.Sprintf("FAIL (%d)", event.Status)
	}
	return fmt.Sprintf("%s on %s: %s", statusLabel, event.HostName, event.Output)
}
