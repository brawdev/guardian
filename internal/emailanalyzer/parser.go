package emailanalyzer

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
)

type ParsedEmail struct {
	From             string
	FromDomain       string
	ReplyTo          string
	Subject          string
	DKIMHeaders      []string // todos los DKIM-Signature headers
	AuthResults      string   // Authentication-Results header
	RawHeaders       mail.Header
	TextBody         string
	HTMLBody         string
	HeadersAvailable bool // false cuando el input es texto plano sin cabeceras
}

func ParseFile(path string) (ParsedEmail, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return ParsedEmail{}, err
		}
		defer f.Close()
		r = f
	}
	return Parse(r)
}

func Parse(r io.Reader) (ParsedEmail, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return ParsedEmail{}, err
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		// Sin cabeceras válidas: tratar como texto plano del cuerpo
		return ParsedEmail{
			TextBody:         string(raw),
			HeadersAvailable: false,
		}, nil
	}

	pe := ParsedEmail{
		HeadersAvailable: true,
		RawHeaders:       msg.Header,
		From:             msg.Header.Get("From"),
		ReplyTo:          msg.Header.Get("Reply-To"),
		Subject:          decodeSubject(msg.Header.Get("Subject")),
		AuthResults:      msg.Header.Get("Authentication-Results"),
	}

	pe.DKIMHeaders = msg.Header["Dkim-Signature"]
	pe.FromDomain = extractFromDomain(pe.From)
	pe.TextBody, pe.HTMLBody = extractBodies(msg)

	return pe, nil
}

func extractFromDomain(from string) string {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		// intento simple
		if at := strings.LastIndex(from, "@"); at != -1 {
			return strings.Trim(from[at+1:], "> ")
		}
		return ""
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

func decodeSubject(s string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func extractBodies(msg *mail.Message) (text, html string) {
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		b, _ := io.ReadAll(msg.Body)
		return string(b), ""
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			partCT := part.Header.Get("Content-Type")
			body, _ := io.ReadAll(part)
			bodyStr := string(body)

			if strings.Contains(partCT, "text/plain") && text == "" {
				text = bodyStr
			} else if strings.Contains(partCT, "text/html") && html == "" {
				html = bodyStr
			} else if strings.Contains(partCT, "multipart/") {
				// nested multipart — extraer recursivamente del texto plano
				if strings.Contains(bodyStr, "<html") {
					html = bodyStr
				} else {
					text = bodyStr
				}
			}
		}
	} else {
		b, _ := io.ReadAll(msg.Body)
		if strings.Contains(mediaType, "html") {
			html = string(b)
		} else {
			text = string(b)
		}
	}
	return text, html
}
