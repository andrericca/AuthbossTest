package main

import (
	"authboss/remember"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-chi/chi"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/justinas/nosurf"
	"github.com/volatiletech/authboss"
	_ "github.com/volatiletech/authboss/auth"
	_ "github.com/volatiletech/authboss/logout"
	_ "github.com/volatiletech/authboss/recover"
	_ "github.com/volatiletech/authboss/register"
)

var router = mux.NewRouter()
var (
	ab = authboss.New()
)

func debugln(args ...interface{}) {

}

func debugf(format string, args ...interface{}) {
}

type MemStorer struct {
	Users  map[string]User
	Tokens map[string][]string
}

// PutArbitrary into user
func (u *User) PutArbitrary(values map[string]string) {
	if n, ok := values["name"]; ok {
		u.Name = n
	}
}

// GetPID from user
func (u User) GetPID() string { return u.Email }

// GetPassword from user
func (u User) GetPassword() string { return u.Password }

// GetEmail from user
func (u User) GetEmail() string { return u.Email }

// GetConfirmed from user
func (u User) GetConfirmed() bool { return u.Confirmed }

// GetConfirmSelector from user
func (u User) GetConfirmSelector() string { return u.ConfirmSelector }

// GetConfirmVerifier from user
func (u User) GetConfirmVerifier() string { return u.ConfirmVerifier }

// GetLocked from user
func (u User) GetLocked() time.Time { return u.Locked }

// GetAttemptCount from user
func (u User) GetAttemptCount() int { return u.AttemptCount }

// GetLastAttempt from user
func (u User) GetLastAttempt() time.Time { return u.LastAttempt }

// GetRecoverSelector from user
func (u User) GetRecoverSelector() string { return u.RecoverSelector }

// GetRecoverVerifier from user
func (u User) GetRecoverVerifier() string { return u.RecoverVerifier }

// GetRecoverExpiry from user
func (u User) GetRecoverExpiry() time.Time { return u.RecoverTokenExpiry }

// GetArbitrary from user
func (u User) GetArbitrary() map[string]string {
	return map[string]string{
		"name": u.Name,
	}
}

func NewMemStorer() *MemStorer {
	return &MemStorer{
		Users: map[string]User{
			"rick@councilofricks.com": User{
				ID:        1,
				Name:      "Rick",
				Password:  "$2a$10$XtW/BrS5HeYIuOCXYe8DFuInetDMdaarMUJEOg/VA/JAIDgw3l4aG", // pass = 1234
				Email:     "rick@councilofricks.com",
				Confirmed: true,
			},
		},
		Tokens: make(map[string][]string),
	}
}

func (m MemStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	m.Users[u.Email] = *u

	debugln("Saved user:", u.Name)
	return nil
}

func (m MemStorer) Load(ctx context.Context, key string) (user authboss.User, err error) {

	u, ok := m.Users[key]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	debugln("Loaded user:", u.Name)
	return &u, nil
}

func (m MemStorer) New(ctx context.Context) authboss.User {
	return &User{}
}

func (m MemStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*User)

	if _, ok := m.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}

	debugln("Created new user:", u.Name)
	m.Users[u.Email] = *u
	return nil
}

func (m MemStorer) LoadByConfirmSelector(ctx context.Context, selector string) (user authboss.ConfirmableUser, err error) {
	for _, v := range m.Users {
		if v.ConfirmSelector == selector {
			debugln("Loaded user by confirm selector:", selector, v.Name)
			return &v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

func (m MemStorer) LoadByRecoverSelector(ctx context.Context, selector string) (user authboss.RecoverableUser, err error) {
	for _, v := range m.Users {
		if v.RecoverSelector == selector {
			debugln("Loaded user by recover selector:", selector, v.Name)
			return &v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

func (m MemStorer) AddRememberToken(ctx context.Context, pid, token string) error {
	m.Tokens[pid] = append(m.Tokens[pid], token)
	debugf("Adding rm token to %s: %s\n", pid, token)
	spew.Dump(m.Tokens)
	return nil
}

func (m MemStorer) DelRememberTokens(ctx context.Context, pid string) error {
	delete(m.Tokens, pid)
	debugln("Deleting rm tokens from:", pid)
	spew.Dump(m.Tokens)
	return nil
}

func (m MemStorer) UseRememberToken(ctx context.Context, pid, token string) error {
	tokens, ok := m.Tokens[pid]
	if !ok {
		debugln("Failed to find rm tokens for:", pid)
		return authboss.ErrTokenNotFound
	}

	for i, tok := range tokens {
		if tok == token {
			tokens[len(tokens)-1] = tokens[i]
			m.Tokens[pid] = tokens[:len(tokens)-1]
			debugf("Used remember for %s: %s\n", pid, token)
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}

type User struct {
	ID int

	// Non-authboss related field
	Name string

	// Auth
	Email    string
	Password string

	// Confirm
	ConfirmSelector string
	ConfirmVerifier string
	Confirmed       bool

	// Lock
	AttemptCount int
	LastAttempt  time.Time
	Locked       time.Time

	// Recover
	RecoverSelector    string
	RecoverVerifier    string
	RecoverTokenExpiry time.Time
}

var (
	assertUser   = &User{}
	assertStorer = &MemStorer{}

	_ authboss.User            = assertUser
	_ authboss.AuthableUser    = assertUser
	_ authboss.ConfirmableUser = assertUser
	_ authboss.LockableUser    = assertUser
	_ authboss.RecoverableUser = assertUser
	_ authboss.ArbitraryUser   = assertUser

	_ authboss.CreatingServerStorer    = assertStorer
	_ authboss.ConfirmingServerStorer  = assertStorer
	_ authboss.RecoveringServerStorer  = assertStorer
	_ authboss.RememberingServerStorer = assertStorer
)

// PutPID into user
func (u *User) PutPID(pid string) { u.Email = pid }

// PutPassword into user
func (u *User) PutPassword(password string) { u.Password = password }

// PutEmail into user
func (u *User) PutEmail(email string) { u.Email = email }

// PutConfirmed into user
func (u *User) PutConfirmed(confirmed bool) { u.Confirmed = confirmed }

// PutConfirmSelector into user
func (u *User) PutConfirmSelector(confirmSelector string) { u.ConfirmSelector = confirmSelector }

// PutConfirmVerifier into user
func (u *User) PutConfirmVerifier(confirmVerifier string) { u.ConfirmVerifier = confirmVerifier }

// PutLocked into user
func (u *User) PutLocked(locked time.Time) { u.Locked = locked }

// PutAttemptCount into user
func (u *User) PutAttemptCount(attempts int) { u.AttemptCount = attempts }

// PutLastAttempt into user
func (u *User) PutLastAttempt(last time.Time) { u.LastAttempt = last }

// PutRecoverSelector into user
func (u *User) PutRecoverSelector(token string) { u.RecoverSelector = token }

// PutRecoverVerifier into user
func (u *User) PutRecoverVerifier(token string) { u.RecoverVerifier = token }

// PutRecoverExpiry into user
func (u *User) PutRecoverExpiry(expiry time.Time) { u.RecoverTokenExpiry = expiry }

func setupAuthboss() {
	ab.Config.Paths.RootURL = "http://localhost:8080"
	// ab.Config.Storage.Server = database
	// ab.Config.Storage.SessionState = sessionStore
	// ab.Config.Storage.CookieState = cookieStore

	// passwordRule := defaults.Rules{
	// 	FieldName: "password", Required: true,
	// 	MinLength: 4,
	// }
	// nameRule := defaults.Rules{
	// 	FieldName: "name", Required: true,
	// 	MinLength: 2,
	// }

}

func dataInjector(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := layoutData(w, &r)
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		handler.ServeHTTP(w, r)
	})
}

func layoutData(w http.ResponseWriter, r **http.Request) authboss.HTMLData {
	currentUserName := ""
	userInter, err := ab.LoadCurrentUser(r)
	if userInter != nil && err == nil {
		currentUserName = userInter.(*User).Name
	}
	return authboss.HTMLData{
		"loggedin":          userInter != nil,
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}

func nosurfing(h http.Handler) http.Handler {
	surfing := nosurf.New(h)
	surfing.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Failed to validate CSRF token:", nosurf.Reason(r))
		w.WriteHeader(http.StatusBadRequest)
	}))
	return surfing
}

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n%s %s %s\n", r.Method, r.URL.Path, r.Proto)

		// if *flagDebug {
		// 	session, err := sessionStore.Get(r, sessionCookieName)
		// 	if err == nil {
		// 		fmt.Print("Session: ")
		// 		first := true
		// 		for k, v := range session.Values {
		// 			if first {
		// 				first = false
		// 			} else {
		// 				fmt.Print(", ")
		// 			}
		// 			fmt.Printf("%s = %v", k, v)
		// 		}
		// 		fmt.Println()
		// 	}
		// }

		// if *flagDebugDB {
		// 	fmt.Println("Database:")
		// 	for _, u := range database.Users {
		// 		fmt.Printf("! %#v\n", u)
		// 	}
		// }

		// if *flagDebugCTX {
		// 	if val := r.Context().Value(authboss.CTXKeyData); val != nil {
		// 		fmt.Printf("CTX Data: %s", spew.Sdump(val))
		// 	}
		// 	if val := r.Context().Value(authboss.CTXKeyValues); val != nil {
		// 		fmt.Printf("CTX Values: %s", spew.Sdump(val))
		// 	}
		// }

		h.ServeHTTP(w, r)
	})
}

func main() {

	setupAuthboss()
	mux := chi.NewRouter()
	mux.Use(logger, nosurfing, ab.LoadClientStateMiddleware, remember.Middleware(ab), dataInjector)
	mux.Group(func(mux chi.Router) {
		router.HandleFunc("/", LoginPageHandler) // GET

		router.HandleFunc("/index", IndexPageHandler) // GET
		router.HandleFunc("/login", LoginPageHandler).Methods("GET")
		router.HandleFunc("/login", LoginHandler).Methods("POST")

		router.HandleFunc("/register", RegisterPageHandler).Methods("GET")
		router.HandleFunc("/register", RegisterHandler).Methods("POST")

		router.HandleFunc("/logout", LogoutHandler)

		http.Handle("/", router)
	})
	// http.ListenAndServe(":8080", nil)

	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.ModuleListMiddleware(ab))
		mux.Mount("/auth", http.StripPrefix("/auth", ab.Config.Core.Router))
	})
	// mux.Get("/blogs", index)
	// mux.Get("/", index)

	// routes := []string{"login", "logout", "recover", "recover/end", "register"}
	// mux.MethodFunc("OPTIONS", "/*", optionsHandler)
	// for _, r := range routes {
	// 	mux.MethodFunc("OPTIONS", "/auth/"+r, optionsHandler)
	// }
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
		// http.ListenAndServe(":8080", nil)

	}
	log.Printf("Listening on localhost: %s", port)
	log.Println(http.ListenAndServe(":"+port, router))
}

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

// Handlers

// for GET
func LoginPageHandler(response http.ResponseWriter, request *http.Request) {
	var body, _ = LoadFile("views/login.html.tpl")
	fmt.Fprintf(response, body)
}

// for POST
func LoginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
	redirectTarget := "/"
	if !IsEmpty(name) && !IsEmpty(pass) {
		// Database check for user data!
		_userIsValid := UserIsValid(name, pass)

		if _userIsValid {
			SetCookie(name, response)
			redirectTarget = "/index"
		} else {
			redirectTarget = "/register"
		}
	}
	http.Redirect(response, request, redirectTarget, 302)
}

// for GET
func RegisterPageHandler(response http.ResponseWriter, request *http.Request) {
	var body, _ = LoadFile("templates/register.html")
	fmt.Fprintf(response, body)
}

// for POST
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	fmt.Println("a")
	uName := r.FormValue("username")
	email := r.FormValue("email")
	pwd := r.FormValue("password")
	confirmPwd := r.FormValue("confirmpassword")

	fmt.Println(uName, email, pwd, confirmPwd)

	_uName, _email, _pwd, _confirmPwd := false, false, false, false
	_uName = !IsEmpty(uName)
	_email = !IsEmpty(email)
	_pwd = !IsEmpty(pwd)
	_confirmPwd = !IsEmpty(confirmPwd)

	if _uName && _email && _pwd && _confirmPwd {
		fmt.Fprintln(w, "Username for Register : ", uName)
		fmt.Fprintln(w, "Email for Register : ", email)
		fmt.Fprintln(w, "Password for Register : ", pwd)
		fmt.Fprintln(w, "ConfirmPassword for Register : ", confirmPwd)
	} else {
		fmt.Fprintln(w, "This fields can not be blank!")
	}
}

// for GET
func IndexPageHandler(response http.ResponseWriter, request *http.Request) {
	userName := GetUserName(request)
	fmt.Println(userName)
	if !IsEmpty(userName) {
		var indexBody, _ = LoadFile("views/index.html.tpl")
		fmt.Fprintf(response, indexBody, userName)
	} else {
		http.Redirect(response, request, "/", 302)
	}
}

// for POST
func LogoutHandler(response http.ResponseWriter, request *http.Request) {
	ClearCookie(response)
	http.Redirect(response, request, "/", 302)
}

// Cookie

func SetCookie(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("cookie", value); err == nil {
		cookie := &http.Cookie{
			Name:  "cookie",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func ClearCookie(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "cookie",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

func GetUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("cookie"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("cookie", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}

func LoadFile(fileName string) (string, error) {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func IsEmpty(data string) bool {
	if len(data) <= 0 {
		return true
	} else {
		return false
	}
}

func UserIsValid(uName, pwd string) bool {
	// DB simulation
	_uName, _pwd, _isValid := "andre", "123", false

	if uName == _uName && pwd == _pwd {
		_isValid = true
	} else {
		_isValid = false
	}

	return _isValid
}
