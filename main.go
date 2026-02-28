package main

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/* static/*
var content embed.FS

// SSE client management
var (
	clients   = make(map[chan string]bool)
	clientMux sync.Mutex
)

type Entry struct {
	ID       string
	Content  string
	Type     string
	Filename string
	Size     int64
	ModTime  time.Time
	Category string
	LinkTitle string
	LinkURL   string
	LinkStored string
}

type Category struct {
	Name       string
	FileCount  int
	TextCount  int
	LinkCount  int
	TotalCount int
}

type HomePageData struct {
	Categories []Category
}

type CategoryPageData struct {
	Category string
	Entries  []Entry
	Texts    []Entry
	Files    []Entry
	Links    []Entry
}

type LoginPageData struct {
	Error string
}

type AuthConfig struct {
	Username          string
	Password          string
	SecretKey         string
	SessionExpiryDays int
}

type ExpirationTracker struct {
	Expirations map[string]time.Time `json:"expirations"`
	mu          sync.Mutex           // mutex for thread safety
}

var expirationTracker *ExpirationTracker
var expirationOptions = []string{"Never", "1 hour", "4 hours", "1 day", "Custom"}
var validCategoryName = regexp.MustCompile(`^[\p{L}\p{N}\-_]+$`)
var reservedNames = map[string]bool{"notepad": true, "files": true, "text": true}

const authCookieName = "lcs_auth_token"

func loadAuthConfig() (*AuthConfig, error) {
	username := strings.TrimSpace(os.Getenv("LCS_USERNAME"))
	password := os.Getenv("LCS_PASSWORD")
	secretKey := os.Getenv("LCS_SECRET_KEY")
	if username == "" || password == "" || secretKey == "" {
		return nil, fmt.Errorf("missing auth env vars: LCS_USERNAME, LCS_PASSWORD, and LCS_SECRET_KEY must be set")
	}

	sessionExpiryDays := 30
	sessionExpiryRaw := strings.TrimSpace(os.Getenv("LCS_SESSION_EXPIRY_DAYS"))
	if sessionExpiryRaw != "" {
		parsed, err := strconv.Atoi(sessionExpiryRaw)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("invalid LCS_SESSION_EXPIRY_DAYS value %q: expected a positive integer", sessionExpiryRaw)
		}
		sessionExpiryDays = parsed
	}

	return &AuthConfig{
		Username:          username,
		Password:          password,
		SecretKey:         secretKey,
		SessionExpiryDays: sessionExpiryDays,
	}, nil
}

func (a *AuthConfig) credentialsMatch(username, password string) bool {
	usernameOK := subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(strings.TrimSpace(username))),
		[]byte(strings.ToLower(a.Username)),
	) == 1
	passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.Password)) == 1
	return usernameOK && passwordOK
}

func (a *AuthConfig) signPayload(payload string) string {
	mac := hmac.New(sha256.New, []byte(a.SecretKey))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *AuthConfig) createSessionToken() (string, time.Time, error) {
	nonce := make([]byte, 16)
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}

	expiry := time.Now().Add(time.Duration(a.SessionExpiryDays) * 24 * time.Hour).UTC()
	payload := fmt.Sprintf("%s|%d|%s",
		strings.ToLower(a.Username),
		expiry.Unix(),
		base64.RawURLEncoding.EncodeToString(nonce),
	)
	signature := a.signPayload(payload)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signature
	return token, expiry, nil
}

func (a *AuthConfig) isSessionTokenValid(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(payloadRaw)
	expectedSignature := a.signPayload(payload)
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSignature)) != 1 {
		return false
	}

	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(fields[0]), []byte(strings.ToLower(a.Username))) != 1 {
		return false
	}

	expiryUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(time.Unix(expiryUnix, 0).UTC())
}

func setAuthCookie(w http.ResponseWriter, r *http.Request, token string, expiry time.Time) {
	secureCookie := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie,
	})
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func isPublicRoute(path string) bool {
	if path == "/login" || path == "/favicon.ico" || path == "/manifest.json" || path == "/icon-192.png" || path == "/icon-512.png" {
		return true
	}
	return strings.HasPrefix(path, "/static/")
}

func withAuth(authConfig *AuthConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(authCookieName)
		if err != nil || !authConfig.isSessionTokenValid(cookie.Value) {
			clearAuthCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func initExpirationTracker() *ExpirationTracker {
	tracker := &ExpirationTracker{
		Expirations: make(map[string]time.Time),
	}
	// Load existing expirations from file
	expirationFile := filepath.Join("data", "expirations.json")
	if _, err := os.Stat(expirationFile); err == nil {
		data, err := os.ReadFile(expirationFile)
		if err == nil {
			var storedTracker ExpirationTracker
			if err := json.Unmarshal(data, &storedTracker); err == nil {
				tracker.Expirations = storedTracker.Expirations
			}
		}
	}
	return tracker
}

func parseCustomDuration(customExpiry string) time.Duration {
	customExpiry = strings.TrimSpace(customExpiry)
	// Regex to match the format like 1h, 30m, 2d, etc.
	re := regexp.MustCompile(`^(\d+)([hmMdwy])$`)
	matches := re.FindStringSubmatch(customExpiry)
	if len(matches) < 2 { // bad value
		return 5 * time.Minute
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 5 * time.Minute
	}
	unit := strings.ToLower(matches[2])
	switch unit {
	case "m": // minutes
		if value < 5 {
			return 5 * time.Minute
		}
		return time.Duration(value) * time.Minute
	case "h": // hours
		return time.Duration(value) * time.Hour
	case "d": // days
		return time.Duration(value) * 24 * time.Hour
	case "w": // weeks
		return time.Duration(value) * 7 * 24 * time.Hour
	case "M": // months
		return time.Duration(value) * 30 * 24 * time.Hour
	case "y": // years
		return time.Duration(value) * 365 * 24 * time.Hour
	default:
		return 5 * time.Minute
	}
}

func (t *ExpirationTracker) SetExpiration(fileID, expiryOption string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if expiryOption == "Never" {
		delete(t.Expirations, fileID)
	} else {
		var duration time.Duration
		switch expiryOption {
		case "1 hour":
			duration = 1 * time.Hour
		case "4 hours":
			duration = 4 * time.Hour
		case "1 day":
			duration = 24 * time.Hour
		case "Custom":
			// Should not happen anymore.
			return
		default:
			if len(expiryOption) > 0 {
				duration = parseCustomDuration(expiryOption)
			} else {
				delete(t.Expirations, fileID)
				return
			}
		}
		t.Expirations[fileID] = time.Now().Add(duration)
	}
	t.saveToFile()
}

func (t *ExpirationTracker) saveToFile() {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		log.Printf("Error marshaling expirations: %v", err)
		return
	}
	expirationFile := filepath.Join("data", "expirations.json")
	if err := os.WriteFile(expirationFile, data, 0644); err != nil {
		log.Printf("Error saving expirations: %v", err)
	}
}

func (t *ExpirationTracker) CleanupExpired() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	var expiredFiles []string
	// Find expired files
	for fileID, expiryTime := range t.Expirations {
		if now.After(expiryTime) {
			expiredFiles = append(expiredFiles, fileID)
		}
	}
	// Delete expired files
	for _, fileID := range expiredFiles {
		err := os.Remove(filepath.Join("data", fileID))
		if err != nil && !os.IsNotExist(err) {
			log.Printf("Error removing expired file %s: %v", fileID, err)
		} else {
			log.Printf("Removed expired file: %s", fileID)
		}
		delete(t.Expirations, fileID)
	}
	if len(expiredFiles) > 0 {
		t.saveToFile()
		notifyContentChange()
	}
	return expiredFiles
}

var listenAddress = flag.String("listen", ":8080", "host:port in which the server will listen")

// Placeholder content for notepad files
const mdPlaceholder = `# Welcome to Markdown Notepad

Start typing your markdown here...

## Features

- **Bold** and *italic* text
- [Links](https://example.com)
- Lists (ordered and unordered)
- Code blocks
- And more!

` + "```" + `
function example() {
  console.log("Hello, Markdown!");
}
` + "```"

func generateUniqueFilename(baseDir, baseName string) string {
	baseName = strings.TrimSpace(baseName)
	// Sanitize: allow only letters (+unicode), numbers, space, dot, hyphen, underscore, () and []
	reg := regexp.MustCompile(`[^\p{L}\p{N}\p{M}\s\.\-_()\[\]]`)
	sanitizedName := reg.ReplaceAllString(baseName, "-")
	log.Printf("Sanitized name %s TO %s\n", baseName, sanitizedName)
	// First try without random prefix
	if _, err := os.Stat(filepath.Join(baseDir, sanitizedName)); os.IsNotExist(err) {
		return sanitizedName
	}
	// If file exists, add random prefix until we find a unique name
	for {
		randChars := fmt.Sprintf("%04d", rand.Intn(10000))
		newName := fmt.Sprintf("%s-%s", randChars, sanitizedName)
		if _, err := os.Stat(filepath.Join(baseDir, newName)); os.IsNotExist(err) {
			return newName
		}
	}
}

func sanitizeSingleLine(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return strings.TrimSpace(value)
}

func isInvalidCategoryPathSegment(category string) bool {
	return category == "" || strings.Contains(category, "/") || strings.Contains(category, "\\") || reservedNames[category]
}

// resolveCategoryName returns the canonical category directory name.
// It first tries exact match, then falls back to case-insensitive matching.
func resolveCategoryName(category string) (string, bool, error) {
	catPath := filepath.Join("data", category)
	info, err := os.Stat(catPath)
	if err == nil {
		return category, info.IsDir(), nil
	}
	if !os.IsNotExist(err) {
		return "", false, err
	}

	entries, err := os.ReadDir("data")
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if !e.IsDir() || reservedNames[e.Name()] {
			continue
		}
		if strings.EqualFold(e.Name(), category) {
			return e.Name(), true, nil
		}
	}
	return "", false, nil
}

func parseStoredLink(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}

	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		return line, line
	}

	title := strings.TrimSpace(parts[0])
	linkURL := strings.TrimSpace(parts[1])
	if linkURL == "" {
		linkURL = title
	}
	if title == "" {
		title = linkURL
	}
	return title, linkURL
}

func scanCategories() ([]Category, error) {
	entries, err := os.ReadDir("data")
	if err != nil {
		return nil, err
	}

	var categories []Category
	for _, e := range entries {
		if !e.IsDir() || reservedNames[e.Name()] {
			continue
		}

		cat := Category{Name: e.Name()}

		textFiles, _ := os.ReadDir(filepath.Join("data", e.Name(), "text"))
		for _, f := range textFiles {
			if !f.IsDir() {
				cat.TextCount++
			}
		}

		files, _ := os.ReadDir(filepath.Join("data", e.Name(), "files"))
		for _, f := range files {
			if !f.IsDir() {
				cat.FileCount++
			}
		}

		linkData, err := os.ReadFile(filepath.Join("data", e.Name(), "links.file"))
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(linkData)), "\n") {
				if strings.TrimSpace(line) != "" {
					cat.LinkCount++
				}
			}
		}

		cat.TotalCount = cat.FileCount + cat.TextCount + cat.LinkCount
		categories = append(categories, cat)
	}

	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return categories, nil
}

func loadCategoryEntries(category string) []Entry {
	var entries []Entry

	textFiles, _ := os.ReadDir(filepath.Join("data", category, "text"))
	for _, file := range textFiles {
		if file.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join("data", category, "text", file.Name()))
		if err != nil {
			continue
		}

		info, err := file.Info()
		if err != nil {
			info = nil
		}

		var modTime time.Time
		var size int64
		if info != nil {
			modTime = info.ModTime()
			size = info.Size()
		}

		entries = append(entries, Entry{
			ID:       filepath.Join(category, "text", file.Name()),
			Type:     "text",
			Content:  string(data),
			Filename: file.Name(),
			ModTime:  modTime,
			Size:     size,
			Category: category,
		})
	}

	files, _ := os.ReadDir(filepath.Join("data", category, "files"))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		info, err := file.Info()
		if err != nil {
			info = nil
		}

		var modTime time.Time
		var size int64
		if info != nil {
			modTime = info.ModTime()
			size = info.Size()
		}

		entries = append(entries, Entry{
			ID:       filepath.Join(category, "files", file.Name()),
			Type:     "file",
			Filename: file.Name(),
			ModTime:  modTime,
			Size:     size,
			Category: category,
		})
	}

	linkData, err := os.ReadFile(filepath.Join("data", category, "links.file"))
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(linkData)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			title, linkURL := parseStoredLink(line)
			entries = append(entries, Entry{
				ID:       category + "/link/" + url.PathEscape(line),
				Type:     "link",
				Content:  linkURL,
				Filename: title,
				Category: category,
				LinkTitle: title,
				LinkURL:   linkURL,
				LinkStored: line,
			})
		}
	}

	return entries
}

func handleContentUpdates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	messageChan := make(chan string)
	clientMux.Lock()
	clients[messageChan] = true
	clientMux.Unlock()

	defer func() {
		clientMux.Lock()
		delete(clients, messageChan)
		clientMux.Unlock()
		close(messageChan)
	}()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	// Send an initial message
	fmt.Fprintf(w, "data: %s\n\n", "connected")
	w.(http.Flusher).Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-messageChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			w.(http.Flusher).Flush()
		case <-ticker.C: // send keep-alive msg
			fmt.Fprintf(w, ": keep-alive\n\n")
			w.(http.Flusher).Flush()
		}
	}
}

func notifyContentChange() {
	clientMux.Lock()
	defer clientMux.Unlock()
	for client := range clients {
		select {
		case client <- "content_updated":
		default:
		}
	}
}

func main() {
	flag.Parse()

	authConfig, err := loadAuthConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join("data", "notepad"), 0755); err != nil {
		log.Fatal(err)
	}
	log.Println("Data directory created/reused without errors.")
	createFileIfNotExists("notepad/md.file", mdPlaceholder)

	// Initialize the expiration tracker
	expirationTracker = initExpirationTracker()
	customExpiry := os.Getenv("DEFAULT_EXPIRY")
	if customExpiry != "" {
		switch customExpiry {
		case "1d":
			expirationOptions = []string{"1 day", "Never", "1 hour", "4 hours", "Custom"}
		case "4h":
			expirationOptions = []string{"4 hours", "Never", "1 hour", "1 day", "Custom"}
		case "1h":
			expirationOptions = []string{"1 hour", "Never", "4 hours", "1 day", "Custom"}
		default:
			expirationOptions = append([]string{customExpiry}, expirationOptions...)
		}
	}

	// Goroutine to periodically expire files
	go func() {
		ticker := time.NewTicker(3 * time.Minute) // 3 minutes is sparse enough, load is extremely minimal as the operation is fast (in memory tracker)
		defer ticker.Stop()
		for range ticker.C {
			expirationTracker.CleanupExpired()
		}
	}()

	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"pathEscape": url.PathEscape,
	}).ParseFS(content, "templates/*.html"))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet:
			cookie, err := r.Cookie(authCookieName)
			if err == nil && authConfig.isSessionTokenValid(cookie.Value) {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			_ = tmpl.ExecuteTemplate(w, "login.html", LoginPageData{})
		case http.MethodPost:
			username := r.FormValue("username")
			password := r.FormValue("password")
			if !authConfig.credentialsMatch(username, password) {
				w.WriteHeader(http.StatusUnauthorized)
				_ = tmpl.ExecuteTemplate(w, "login.html", LoginPageData{Error: "Invalid username or password"})
				return
			}

			token, expiry, err := authConfig.createSessionToken()
			if err != nil {
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}
			setAuthCookie(w, r, token, expiry)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clearAuthCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		expirationTracker.CleanupExpired()
		categories, err := scanCategories()
		if err != nil {
			http.Error(w, "Failed to scan categories", http.StatusInternalServerError)
			return
		}
		tmpl.ExecuteTemplate(w, "index.html", HomePageData{Categories: categories})
	})

	http.HandleFunc("/c/", func(w http.ResponseWriter, r *http.Request) {
		category := strings.TrimPrefix(r.URL.Path, "/c/")
		if isInvalidCategoryPathSegment(category) {
			http.Error(w, "Invalid category", http.StatusBadRequest)
			return
		}
		resolvedCategory, found, err := resolveCategoryName(category)
		if err != nil {
			http.Error(w, "Failed to resolve category", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Category not found", http.StatusNotFound)
			return
		}
		if resolvedCategory != category {
			http.Redirect(w, r, "/c/"+url.PathEscape(resolvedCategory), http.StatusSeeOther)
			return
		}

		expirationTracker.CleanupExpired()
		entries := loadCategoryEntries(category)
		var texts []Entry
		var files []Entry
		var links []Entry
		for _, entry := range entries {
			switch entry.Type {
			case "text":
				texts = append(texts, entry)
			case "file":
				files = append(files, entry)
			case "link":
				links = append(links, entry)
			}
		}

		tmpl.ExecuteTemplate(w, "category.html", CategoryPageData{
			Category: category,
			Entries:  entries,
			Texts:    texts,
			Files:    files,
			Links:    links,
		})
	})

	http.HandleFunc("/category/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" || !validCategoryName.MatchString(name) || reservedNames[name] {
			http.Error(w, "Invalid category name", http.StatusBadRequest)
			return
		}
		if _, found, err := resolveCategoryName(name); err != nil {
			http.Error(w, "Failed to resolve category", http.StatusInternalServerError)
			return
		} else if found {
			http.Error(w, "Category already exists", http.StatusConflict)
			return
		}
		catPath := filepath.Join("data", name)
		if err := os.MkdirAll(filepath.Join(catPath, "files"), 0755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.MkdirAll(filepath.Join(catPath, "text"), 0755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		notifyContentChange()
		http.Redirect(w, r, "/c/"+url.PathEscape(name), http.StatusSeeOther)
	})

	http.HandleFunc("/category/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if isInvalidCategoryPathSegment(name) {
			http.Error(w, "Invalid category name", http.StatusBadRequest)
			return
		}
		resolvedName, found, err := resolveCategoryName(name)
		if err != nil {
			http.Error(w, "Failed to resolve category", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Category not found", http.StatusNotFound)
			return
		}
		name = resolvedName
		catPath := filepath.Join("data", name)

		expirationTracker.mu.Lock()
		for key := range expirationTracker.Expirations {
			if strings.HasPrefix(key, name+"/") {
				delete(expirationTracker.Expirations, key)
			}
		}
		expirationTracker.saveToFile()
		expirationTracker.mu.Unlock()

		if err := os.RemoveAll(catPath); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		notifyContentChange()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.HandleFunc("/md", func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "md.html", nil)
	})

	// Retrieve custom expiration options
	http.HandleFunc("/getExpiryOptions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expirationOptions)
	})

	// Serve static files from embedded filesystem
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		log.Fatalf("Failed to create static sub-filesystem: %v", err)
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("style.css")
		if err != nil {
			http.Error(w, "Style not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "text/css")
		io.Copy(w, file)
	})

	http.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("manifest.json")
		if err != nil {
			http.Error(w, "Manifest not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, file)
	})

	http.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("sw.js")
		if err != nil {
			http.Error(w, "Service worker not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/javascript")
		io.Copy(w, file)
	})

	http.HandleFunc("/md.js", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("md.js")
		if err != nil {
			http.Error(w, "JavaScript not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/javascript")
		io.Copy(w, file)
	})

	// Handle favicon and icons
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("favicon.ico")
		if err != nil {
			http.Error(w, "Favicon not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "image/x-icon")
		io.Copy(w, file)
	})

	http.HandleFunc("/icon-192.png", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("icon-192.png")
		if err != nil {
			http.Error(w, "Icon not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "image/png")
		io.Copy(w, file)
	})

	http.HandleFunc("/icon-512.png", func(w http.ResponseWriter, r *http.Request) {
		file, err := staticFS.Open("icon-512.png")
		if err != nil {
			http.Error(w, "Icon not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "image/png")
		io.Copy(w, file)
	})

	// API endpoint to load notepad content
	http.HandleFunc("/notepad/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			filename := strings.TrimPrefix(r.URL.Path, "/notepad/")
			if filename != "md.file" { // && filename != "rtext.file" {
				http.Error(w, "Invalid notepad file", http.StatusBadRequest)
				return
			}
			content, err := os.ReadFile(filepath.Join("data", "notepad", filename))
			if err != nil {
				http.Error(w, "Error reading notepad file", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Write(content)
			return
		case "POST":
			filename := strings.TrimPrefix(r.URL.Path, "/notepad/")
			if filename != "md.file" { // && filename != "rtext.file" {
				http.Error(w, "Invalid notepad file", http.StatusBadRequest)
				return
			}
			content, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading request body", http.StatusInternalServerError)
				return
			}
			err = os.WriteFile(filepath.Join("data", "notepad", filename), content, 0644)
			if err != nil {
				http.Error(w, "Error saving notepad file", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Saved"))
			log.Printf("Saved notepad content to %s\n", filename)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(100 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		category := strings.TrimSpace(r.FormValue("category"))
		if isInvalidCategoryPathSegment(category) {
			http.Error(w, "Invalid category", http.StatusBadRequest)
			return
		}
		resolvedCategory, found, err := resolveCategoryName(category)
		if err != nil {
			http.Error(w, "Failed to resolve category", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Category not found", http.StatusBadRequest)
			return
		}
		category = resolvedCategory
		entryType := r.FormValue("type")
		expiryOption := r.FormValue("expiry")
		content := strings.TrimSpace(r.FormValue("content"))
		name := r.FormValue("name")
		if entryType == "link" {
			// Handle link submission
			if content == "" {
				http.Error(w, "URL content cannot be empty", http.StatusBadRequest)
				return
			}
			linkTitle := sanitizeSingleLine(r.FormValue("title"))
			u, err := url.ParseRequestURI(content)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				http.Error(w, "Invalid URL format. Must start with http:// or https://", http.StatusBadRequest)
				return
			}
			if linkTitle == "" {
				linkTitle = content
			}
			linksFilePath := filepath.Join("data", category, "links.file")
			f, err := os.OpenFile(linksFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer f.Close()
			storedLine := fmt.Sprintf("%s\t%s", linkTitle, content)
			if _, err := f.WriteString(storedLine + "\n"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("Saved link %s (%s)\n", linkTitle, content)
		} else {
			// Handle file and text submission
			files := r.MultipartForm.File["file-upload"]
			if len(files) > 0 {
				// File submission
				for _, fileHeader := range files {
					err := func() error {
						file, err := fileHeader.Open()
						if err != nil {
							return err
						}
						defer file.Close()
						fileName := name
						if fileName == "" {
							fileName = fileHeader.Filename
						}
						filesDir := filepath.Join("data", category, "files")
						uniqueFileName := generateUniqueFilename(filesDir, fileName)
						f, err := os.Create(filepath.Join(filesDir, uniqueFileName))
						if err != nil {
							return err
						}
						defer f.Close()
						if _, err := io.Copy(f, file); err != nil {
							return err
						}
						if expiryOption != "Never" {
							fileID := filepath.Join(category, "files", uniqueFileName)
							expirationTracker.SetExpiration(fileID, expiryOption)
						}
						log.Printf("Saved file %s with expiry %s\n", uniqueFileName, expiryOption)
						return nil
					}()
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}
			} else if content != "" {
				// Text snippet submission
				filename := name
				if filename == "" {
					filename = time.Now().Format("Jan-02 15-04-05")
				}
				textDir := filepath.Join("data", category, "text")
				uniqueFileName := generateUniqueFilename(textDir, filename)
				err := os.WriteFile(filepath.Join(textDir, uniqueFileName), []byte(content), 0644)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if expiryOption != "Never" {
					fileID := filepath.Join(category, "text", uniqueFileName)
					expirationTracker.SetExpiration(fileID, expiryOption)
				}
				log.Printf("Saved text snippet %s with expiry %s\n", uniqueFileName, expiryOption)
			}
		}
		notifyContentChange()
		// Send succes for AJAX
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
			return
		}
		http.Redirect(w, r, "/c/"+url.PathEscape(category), http.StatusSeeOther)
	})

	http.HandleFunc("/link/edit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		category := strings.TrimSpace(r.FormValue("category"))
		if isInvalidCategoryPathSegment(category) {
			http.Error(w, "Invalid category", http.StatusBadRequest)
			return
		}
		resolvedCategory, found, err := resolveCategoryName(category)
		if err != nil {
			http.Error(w, "Failed to resolve category", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Category not found", http.StatusBadRequest)
			return
		}
		category = resolvedCategory
		oldLine := strings.TrimSpace(r.FormValue("old_line"))
		if oldLine == "" {
			http.Error(w, "Missing original link", http.StatusBadRequest)
			return
		}

		linkTitle := sanitizeSingleLine(r.FormValue("title"))
		linkURL := strings.TrimSpace(r.FormValue("url"))
		if linkURL == "" {
			http.Error(w, "URL cannot be empty", http.StatusBadRequest)
			return
		}
		u, err := url.ParseRequestURI(linkURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "Invalid URL format. Must start with http:// or https://", http.StatusBadRequest)
			return
		}
		if linkTitle == "" {
			linkTitle = linkURL
		}
		newLine := fmt.Sprintf("%s\t%s", linkTitle, linkURL)

		linksFilePath := filepath.Join("data", category, "links.file")
		data, err := os.ReadFile(linksFilePath)
		if err != nil {
			http.Error(w, "Failed to read links file", http.StatusInternalServerError)
			return
		}
		lines := strings.Split(string(data), "\n")
		var outLines []string
		var replaced bool
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if trimmed == oldLine && !replaced {
				outLines = append(outLines, newLine)
				replaced = true
				continue
			}
			outLines = append(outLines, line)
		}
		if !replaced {
			http.Error(w, "Link not found", http.StatusNotFound)
			return
		}
		output := strings.Join(outLines, "\n")
		if output != "" {
			output += "\n"
		}
		if err := os.WriteFile(linksFilePath, []byte(output), 0644); err != nil {
			http.Error(w, "Failed to update links file", http.StatusInternalServerError)
			return
		}
		notifyContentChange()
		http.Redirect(w, r, "/c/"+url.PathEscape(category), http.StatusSeeOther)
	})

	http.HandleFunc("/rename/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		oldPath := strings.TrimPrefix(r.URL.Path, "/rename/")
		newName := r.FormValue("newname")
		if newName == "" {
			http.Error(w, "New name cannot be empty", http.StatusBadRequest)
			return
		}
		baseDir := filepath.Dir(filepath.Join("data", oldPath))
		newName = generateUniqueFilename(baseDir, newName)

		// Get the new full path
		newPath := filepath.Join(baseDir, newName)
		oldFullPath := filepath.Join("data", oldPath)
		// Check if there's an expiration for this file
		expirationTracker.mu.Lock()
		expiryTime, hasExpiry := expirationTracker.Expirations[oldPath]
		if hasExpiry {
			// Remove old entry and add new one
			delete(expirationTracker.Expirations, oldPath)
			relNewPath := strings.TrimPrefix(newPath, "data/")
			relNewPath = strings.ReplaceAll(relNewPath, "\\", "/") // Ensure cross-platform path separators
			expirationTracker.Expirations[relNewPath] = expiryTime
			expirationTracker.saveToFile()
		}
		expirationTracker.mu.Unlock()
		// Rename the file
		err := os.Rename(oldFullPath, newPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		notifyContentChange()
		parts := strings.SplitN(oldPath, "/", 2)
		redirectTarget := "/"
		if len(parts) > 0 && parts[0] != "" {
			redirectTarget = "/c/" + parts[0]
		}
		http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
		log.Printf("Renamed %s to %s\n", oldPath, newName)
	})

	http.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/raw/")
		parts := strings.SplitN(id, "/", 3)
		if len(parts) != 3 || parts[1] != "text" {
			http.Error(w, "Only text files can be accessed", http.StatusBadRequest)
			return
		}
		content, err := os.ReadFile(filepath.Join("data", id))
		if err != nil {
			http.Error(w, "File not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(content)
	})

	http.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		filename := strings.TrimPrefix(r.URL.Path, "/download/")
		filePath := filepath.Join("data", filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Brute force method to determine content type
		ext := strings.ToLower(filepath.Ext(filename))
		var contentType string
		switch ext {
		case ".pdf":
			contentType = "application/pdf"
		case ".jpg", ".jpeg":
			contentType = "image/jpeg"
		case ".png":
			contentType = "image/png"
		case ".gif":
			contentType = "image/gif"
		case ".svg":
			contentType = "image/svg+xml"
		default:
			buffer := make([]byte, 512)
			_, err = file.Read(buffer)
			if err != nil && err != io.EOF {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			contentType = http.DetectContentType(buffer)
			_, err = file.Seek(0, 0)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		baseFilename := filepath.Base(filename)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", baseFilename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Served %s for download\n", filename)
	})

	http.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		filename := strings.TrimPrefix(r.URL.Path, "/view/")
		http.ServeFile(w, r, filepath.Join("data", filename))
		log.Printf("Served %s for viewing\n", filename)
	})

	http.HandleFunc("/delete/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rawPath := r.URL.RawPath
		if rawPath == "" {
			rawPath = r.URL.Path
		}
		id := strings.TrimPrefix(rawPath, "/delete/")
		if linkIdx := strings.Index(id, "/link/"); linkIdx != -1 {
			category := id[:linkIdx]
			linkToDelete, err := url.PathUnescape(id[linkIdx+len("/link/"):])
			if err != nil {
				http.Error(w, "Invalid link identifier", http.StatusBadRequest)
				return
			}
			linksFilePath := filepath.Join("data", category, "links.file")
			data, err := os.ReadFile(linksFilePath)
			if err != nil {
				http.Error(w, "Failed to read links file for deletion", http.StatusInternalServerError)
				return
			}
			lines := strings.Split(string(data), "\n")
			var newLines []string
			var found bool
			for _, line := range lines {
				if strings.TrimSpace(line) == strings.TrimSpace(linkToDelete) && !found {
					found = true
					continue
				}
				if strings.TrimSpace(line) != "" {
					newLines = append(newLines, line)
				}
			}
			output := strings.Join(newLines, "\n")
			if output != "" {
				output += "\n"
			}
			err = os.WriteFile(linksFilePath, []byte(output), 0644)
			if err != nil {
				http.Error(w, "Failed to write links file after deletion", http.StatusInternalServerError)
				return
			}
			notifyContentChange()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			log.Printf("Deleted link %s\n", linkToDelete)
			return
		}

		id, err := url.PathUnescape(id)
		if err != nil {
			http.Error(w, "Invalid item identifier", http.StatusBadRequest)
			return
		}
		err = os.Remove(filepath.Join("data", id))
		if err != nil {
			log.Printf("Failed to delete %s: %v", id, err)
			http.Error(w, "Failed to delete file", http.StatusInternalServerError)
			return
		}
		expirationTracker.mu.Lock()
		delete(expirationTracker.Expirations, id)
		expirationTracker.saveToFile()
		expirationTracker.mu.Unlock()
		notifyContentChange()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		log.Printf("Deleted %s\n", id)
	})

	http.HandleFunc("/edit/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/edit/")
		parts := strings.SplitN(id, "/", 3)
		if len(parts) != 3 || parts[1] != "text" {
			http.Error(w, "Can only edit text snippets", http.StatusBadRequest)
			return
		}
		content := r.FormValue("content")
		if content == "" {
			http.Error(w, "Content cannot be empty", http.StatusBadRequest)
			return
		}
		err := os.WriteFile(filepath.Join("data", id), []byte(content), 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		notifyContentChange()
		http.Redirect(w, r, "/c/"+parts[0], http.StatusSeeOther)
		log.Printf("Edited %s\n", id)
	})

	// SSE Updates for content refresh
	http.HandleFunc("/api/updates", handleContentUpdates)

	// Start server
	log.Fatal(http.ListenAndServe(*listenAddress, withAuth(authConfig, http.DefaultServeMux)))
}

// Helper function to create files if they don't exist
func createFileIfNotExists(filename string, defaultContent string) {
	dir := filepath.Dir(filepath.Join("data", filename))
	if dir != "." && dir != "data" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("Error creating directory %s: %v\n", dir, err)
		}
	}
	filePath := filepath.Join("data", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err := os.WriteFile(filePath, []byte(defaultContent), 0644)
		if err != nil {
			log.Printf("Error creating file %s: %v\n", filename, err)
		} else {
			log.Printf("Created file %s with default content\n", filename)
		}
	}
}
