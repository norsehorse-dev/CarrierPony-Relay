package api

import (
	"context"
	"log"
	"net/http"
)

var reportCategories = map[string]bool{"spam": true, "harassment": true, "illegal": true, "csam": true, "other": true}

// optionalText returns a field cut to n characters, or nil when it was not sent.
func (in input) optionalText(name string, n int) any {
	if in[name] == nil {
		return nil
	}
	return cutChars(in.text(name), n)
}

// report stores a user's report about another identity. What the reporter
// chooses to attach is the only content the relay ever holds in the clear.
func (s *Server) report(ctx context.Context, reporter string, in input) result {
	if name := in.firstMissing("reported_fpr", "category"); name != "" {
		return missing(name)
	}
	reported, valid := in.fingerprint("reported_fpr")
	if !valid {
		return fail(http.StatusBadRequest, "bad_reported_fpr")
	}
	category := lowerASCII(in.text("category"))
	if !reportCategories[category] {
		return fail(http.StatusBadRequest, "bad_category")
	}
	_, err := s.store.DB.ExecContext(ctx,
		`INSERT INTO reports (reporter_fpr, reported_fpr, category, description, content, attachment_meta, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		reporter, reported, category, in.optionalText("description", 4000), in.optionalText("content", 20000),
		in.optionalText("attachment_meta", 4000), s.stamp())
	if err != nil {
		log.Printf("carrierpony: report: %v", err)
		return serverError()
	}
	return ok(field{"ok", true})
}
