package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SendMail sends one plain-text message through the owner's SMTP account.
// With "starttls" and "tls" the server's certificate is checked; with
// "none" no password is sent (Go's SMTP client refuses to send one over a
// plain connection to anything but this device).
func SendMail(ctx context.Context, e Email, subject, body string) error {
	address := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if e.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("reach the mail server: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("the mail server: %w", err)
	}
	defer client.Close()
	if err := client.Hello("sgc.localdomain"); err != nil {
		return err
	}
	if e.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the mail server does not offer STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if e.Username != "" && e.Security != "none" {
		if err := client.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("the mail server did not accept the username and password: %w", err)
		}
	}
	if err := client.Mail(e.From); err != nil {
		return fmt.Errorf("the sender was refused: %w", err)
	}
	if err := client.Rcpt(e.To); err != nil {
		return fmt.Errorf("the recipient was refused: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(Message(e.From, e.To, subject, body, time.Now()))); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// Message writes a mail: headers (the subject encoded where it is not
// plain ASCII), then the body with every line ending in CRLF.
func Message(from, to, subject, body string, at time.Time) string {
	id := make([]byte, 12)
	rand.Read(id)
	host := from[strings.LastIndexByte(from, '@')+1:]
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", oneLine(subject)) + "\r\n")
	b.WriteString("Date: " + at.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + hex.EncodeToString(id) + "@" + host + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	// The SMTP client's writer turns line ends into CRLF and doubles a
	// leading dot, which would otherwise end the message.
	b.WriteString(strings.ReplaceAll(body, "\r\n", "\n"))
	b.WriteString("\n")
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
