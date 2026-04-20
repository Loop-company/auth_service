package email

import (
	"fmt"
	"log"
	"time"

	"github.com/go-mail/mail/v2"
)

type SMTPClient struct {
	dialer *mail.Dialer
	from   string
}

type LoggingClient struct{}

func NewSMTPClient(host string, port int, username, password, from string) *SMTPClient {
	dialer := mail.NewDialer(host, port, username, password)
	dialer.Timeout = 30 * time.Second

	if port == 587 {
		dialer.StartTLSPolicy = mail.MandatoryStartTLS
	} else if port == 465 {
		dialer.SSL = true
		dialer.StartTLSPolicy = mail.NoStartTLS
	} else {
		dialer.StartTLSPolicy = mail.OpportunisticStartTLS
	}

	return &SMTPClient{
		dialer: dialer,
		from:   from,
	}
}

func NewLoggingClient() *LoggingClient {
	return &LoggingClient{}
}

func (c *LoggingClient) SendVerificationCode(to, code string) error {
	log.Printf("SMTP is disabled, verification code for %s: %s", to, code)
	return nil
}

func (s *SMTPClient) SendVerificationCode(to, code string) error {
	msg := mail.NewMessage()
	msg.SetHeader("From", s.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", "Verification code")
	msg.SetHeader("X-Priority", "1")
	msg.SetBody("text/plain", fmt.Sprintf("Your verification code: %s\nValid for 10 minutes.", code))
	msg.AddAlternative("text/html", fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<style>
				body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; }
				.code { font-size: 32px; font-weight: bold; color: #2563eb; text-align: center; margin: 20px 0; padding: 15px; background: #f3f4f6; border-radius: 8px; }
				.container { max-width: 600px; margin: 0 auto; padding: 20px; }
				.footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
				.header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
				.content { background: #ffffff; padding: 20px; border-radius: 0 0 8px 8px; border: 1px solid #e5e7eb; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h1>Verification code</h1>
				</div>
				<div class="content">
					<p>Use the following code to continue registration:</p>
					<div class="code">%s</div>
					<p><strong>The code is valid for 10 minutes.</strong></p>
				</div>
				<div class="footer">
					<p>Authentication service</p>
				</div>
			</div>
		</body>
		</html>
	`, code))

	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		err = s.dialer.DialAndSend(msg)
		if err == nil {
			return nil
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("failed to send email after 3 attempts: %w", err)
}
