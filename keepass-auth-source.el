;;; keepass-auth-source.el --- auth-source for KeePass -*- lexical-binding: t -*-

;; Author: Mark Faldborg
;; Maintainer: Mark Faldborg
;; Version: 1.0.3
;; Package-Requires: ()
;; Homepage: https://github.com/fishbacon/keepass-auth-source
;; Keywords: keepass auth-source passwords


;; This file is not part of GNU Emacs

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.


;;; Commentary:

;; Adds KeePass support to auth-source.

;; This package can talk to a KeePass database using one of two command
;; line backends:
;;
;;   - `kpscript'     KeePass's KPScript.exe.  This is the *Windows-only*
;;                    scripting plugin that drives an installed KeePass.
;;   - `keepassxc'    keepassxc-cli, KeePassXC's cross-platform command
;;                    line client.  Works on GNU/Linux, macOS and Windows.
;;
;; The backend is chosen automatically by `keepass-auth-source-enable',
;; preferring keepassxc-cli when it is available.  The active backend can
;; be forced via `keepass-auth-source-cli', and the path to each external
;; program can be customized with `keepass-auth-source-*-program'.

;;; Code:
(require 'auth-source)
(require 'cl-lib)
(require 'password-cache)
(require 'seq)
(require 'simple)

;;; Portability helpers (previously provided by dash.el / s.el, kept local
;;; so this package can run with zero external dependencies).

(defun keepass-auth-source-s-contains-p (needle haystack &optional ignore-case)
  "Return t if NEEDLE is contained in HAYSTACK, else nil.
When IGNORE-CASE is non-nil, comparison is case-insensitive."
  (let ((case-fold-search (if ignore-case t case-fold-search)))
    (and (string-match-p (regexp-quote needle) haystack) t)))

;;;###autoload
(defcustom keepass-auth-source-cache-expiry 7200
  "How many seconds the KeePass database password is cached,
or nil to disable expiry."
  :type '(choice (const :tag "Never" nil)
          (const :tag "All Day" 86400)
          (const :tag "2 Hours" 7200)
          (const :tag "30 Minutes" 1800)
          (integer :tag "Seconds"))
  :group 'keepass-auth-source)

(defcustom keepass-auth-match-title t
  "If the `title' argument passed to `auth-source-search' should select an entry.
Entries matching `title' are selected if one and only one entry matches on
`url'.  If no entries match but several are found, prompt the user to pick."
  :type 'boolean
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-cli 'auto
  "Which external KeePass client backend to use.

`auto'     Pick a backend based on which executables are available
           (preferring `keepassxc' over `kpscript').
`keepassxc' Use keepassxc-cli (cross-platform).
`kpscript' Use KeePass's KPScript.exe (Windows-only)."
  :type '(choice (const :tag "Auto-detect" auto)
                 (const :tag "keepassxc-cli" keepassxc)
                 (const :tag "KPScript (KeePass, Windows)" kpscript))
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-keepassxc-cli-program "keepassxc-cli"
  "The keepassxc-cli executable, or path to it.
If a bare name it is looked up on `exec-path'."
  :type 'string
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-kpscript-program "kpscript"
  "The KPScript executable (KeePass scripting plugin, Windows).
If a bare name it is looked up on `exec-path'."
  :type 'string
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-keepass-program "keepass"
  "The KeePass executable (Windows, required by KPScript).
If a bare name it is looked up on `exec-path'."
  :type 'string
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-verbose nil
  "If non-nil, log each keepassxc-cli invocation to the *Messages* buffer.
Useful for debugging why a lookup narrows the way it does."
  :type 'boolean
  :group 'keepass-auth-source)

(defcustom keepass-auth-source-suppress-negative-cache t
  "Whether to keep `auth-source' from caching failed lookups.

`auth-source' normally remembers every search result -- including an empty
one -- for `auth-source-cache-expiry' seconds.  A single failure (the
database is locked, the password was wrong, keepassxc-cli was momentarily
unavailable) therefore keeps every later lookup returning nil long after
the cause is gone, and makes configuration changes look as if they had no
effect.

When non-nil (the default), only non-empty results are cached; a miss is
never remembered, so the next lookup always really queries the database."
  :type 'boolean
  :group 'keepass-auth-source)

;; The backend actually in use (resolved from `keepass-auth-source-cli').
(defvar keepass-auth-source--active-cli nil)

(defun keepass-auth-source--parse-auth (auth-string port)
  (save-match-data
    (with-temp-buffer
      (insert auth-string)
      (goto-char (point-min))
      (let ((result `(:port ,port))
            (mappings '(:url :host
                        :username :user
                        :password :secret)))
        (while (search-forward-regexp "^S: \\(.*\\) = \\(.*\\)$" nil t)
          (let* ((key (intern (concat ":" (downcase (match-string 1)))))
                 (key (or (plist-get mappings key) key))
                 (value (match-string 2))
                 (value (if (eq :secret key) `(lambda () ,value) value)))
            (setq result (plist-put result key value))))
        result))))

(defun keepass-auth-source--parse (output port)
  (let* ((results (split-string output "\n\n"))
         (status (car results))
         (auths (mapcar (lambda (it) (keepass-auth-source--parse-auth it port))
                        (butlast results))))
    `(,auths ,status)))

(defun keepass-auth-source--resolve-cli ()
  "Resolve the backend to use.
Returns `kpscript' or `keepassxc' by honoring `keepass-auth-source-cli'.
For the `auto' value, keepassxc-cli is preferred when available, falling
back to KPScript.  Returns nil if no suitable backend is found."
  (pcase keepass-auth-source-cli
    ('auto
     (cond ((executable-find keepass-auth-source-keepassxc-cli-program) 'keepassxc)
           ((and (executable-find keepass-auth-source-keepass-program)
                 (executable-find keepass-auth-source-kpscript-program)) 'kpscript)
           (t nil)))
    (other other)))

;;; KPScript backend (Windows)

(defun keepass-auth-source--kpscript-command (entity user url password)
  "Return the KPScript list-entries command for ENTITY filtered by USER and URL."
  (mapconcat #'identity
             (list
              (shell-quote-argument keepass-auth-source-kpscript-program)
              "-C:ListEntries"
              (format "\"%s\"" (expand-file-name entity))
              (format "-ref-Username:\"%s\"" (or user ""))
              (format "-ref-URL:\"//%s//\"" url)
              (format "-pw:\"%s\"" password))
             " "))

;;; keepassxc-cli backend (cross-platform)

(defun keepass-auth-source--keepassxc-executable ()
  "Return the resolved path to keepassxc-cli, else its configured name."
  (or (executable-find keepass-auth-source-keepassxc-cli-program)
      keepass-auth-source-keepassxc-cli-program))

(defun keepass-auth-source--keepassxc-parse (show-output port)
  "Parse a single `keepassxc-cli show' summary into an auth plist.
The `Key: value' lines are turned into the same `S: Key = value' shape
produced by KPScript so `keepass-auth-source--parse-auth' can map them
identically (URL -> :host, UserName -> :user, Password -> :secret, ...).
A password line reading literally \"PROTECTED\" means keepassxc-cli did
not reveal the secret, so it is dropped rather than stored as the actual
password."
  (keepass-auth-source--parse-auth
   (mapconcat #'identity
              (mapcar
               (lambda (line)
                 (when (and (string-match "^\\([^:]+\\)[[:space:]]*:[[:space:]]*\\(.*\\)$" line)
                            (not (and (string-equal "Password" (string-trim (match-string 1 line)))
                                      (string-equal "PROTECTED" (string-trim (match-string 2 line))))))
                   (format "S: %s = %s" (string-trim (match-string 1 line))
                           (match-string 2 line))))
               (split-string show-output "\n"))
              "\n")
   port))

(defun keepass-auth-source--normalize-db (spec)
  "Normalize a database SPEC to (PATH KEYFILE PASSWORD).

SPEC is one `auth-sources' entry (or `keepass-browse-database').  It is
either a string -- the database path, with no key file and an
interactively-requested password -- or a list:

  (PATH [KEYFILE] [PASSWORD])

PATH is the database file name.  KEYFILE, if present and non-nil, is
either a string (the key file's name) or a function of no arguments
returning the file name; nil means no key file.

PASSWORD distinguishes three cases:
  absent (list has no third element)   -> prompt the user (the default)
  nil (the third element is literally nil) -> the database has NO password
  a string or no-argument function     -> that password

Returns (PATH KEYFILE PASSWORD) where KEYFILE is a file-name string or
nil, and PASSWORD is a string, a function, the symbol `:prompt' (meaning
ask the user), or nil (meaning no password)."
  (let ((path spec) keyfile password has-password)
    (when (consp spec)
      (setq path (nth 0 spec)
            keyfile (nth 1 spec)
            has-password (> (length spec) 2)
            password (nth 2 spec)))
    (list path keyfile
          (cond ((not (consp spec)) :prompt)      ; plain string -> prompt
                ((not has-password) :prompt)
                (t password)))))

(defun keepass-auth-source--no-password (db)
  "Return whether DB has no master password, honouring a cached answer.
A database created with `--no-password' has no master password; the
password cache keyed by DB records a yes-or-no answer."
  (let ((password-cache-expiry (or keepass-auth-source-cache-expiry nil)))
    (and (password-in-cache-p db)            ; cached at all
         (not (car (password-read-from-cache db))))))

(defun keepass-auth-source--resolve-password (password-spec db &optional expiry)
  "Return the master password for DB from PASSWORD-SPEC.
Returns a string (the password), or the symbol `:no-password' meaning the
database has no master password and `--no-password' must be passed to
keepassxc-cli.  The cases:
  `keepass-auth-source--normalize-db''s `:prompt'  -> ask the user (and
      cache) as usual, returning the typed string;
  a string     -> used as-is;
  a function   -> called to obtain its result;
  nil          -> the database has no master password; return `:no-password'."
  (pcase password-spec
    ((pred stringp) password-spec)
    ((pred functionp) (let ((v (funcall password-spec)))
                        (if v v :no-password)))
    (:prompt (keepass-auth-source--read-password db expiry))
    (_ :no-password)))

(defun keepass-auth-source--resolve-keyfile (keyfile)
  "Resolve a key file specification KEYFILE to a file name, or nil.
A string is the file name; a function is called to obtain it; anything
else (including nil) means no key file."
  (pcase keyfile
    ((pred stringp) keyfile)
    ((pred functionp) (funcall keyfile))
    (_ nil)))

(defun keepass-auth-source--read-password (db &optional expiry)
  "Read the master password for database DB, caching it for reuse.
The cache entry is keyed by DB, so multiple databases each keep their own
master password.  EXPIRY defaults to `keepass-auth-source-cache-expiry'.
Returns the password."
  (let* ((prompt (format "Keepass password (%s): " db))
         (password-cache-expiry (or expiry keepass-auth-source-cache-expiry))
         (password (cond
                    ((password-read-from-cache db))
                    ((password-read prompt db)))))
    (password-cache-add db password)
    password))

(defun keepass-auth-source--keyfile-args (keyfile)
  "Return the keepassxc-cli arguments for key file KEYFILE.
KEYFILE is a file-name string, a no-argument function returning one, or
nil for no key file.  Returns (\"--key-file\" FILE) or nil, with FILE
expanded so a leading \"~\" works."
  (when-let* ((file (keepass-auth-source--resolve-keyfile keyfile)))
    (list "--key-file" (expand-file-name file))))

(defun keepass-auth-source--log (format-string &rest args)
  "Append a line to the *keepass-auth-source-log* buffer (read-only).
The buffer is never displayed automatically and nothing is echoed to
*Messages*; the user can open it with \\[switch-to-buffer] when curious."
  (let ((line (apply #'format format-string args)))
    (with-current-buffer (get-buffer-create "*keepass-auth-source-log*")
      (setq buffer-read-only t)
      (let ((inhibit-read-only t))
        (goto-char (point-max))
        (insert line "\n")))))

(defun keepass-auth-source--no-password-flag (password)
  "Return the keepassxc-cli global option for a password-less database, or nil.
PASSWORD is the resolved master password; the symbol `:no-password' means
the database has no master password and keepassxc-cli must be told so with
its `--no-password' option instead of reading stdin."
  (if (eq password :no-password) (list "--no-password") nil))

(defun keepass-auth-source--keepassxc-run (password &rest args)
  (when keepass-auth-source-verbose
    (keepass-auth-source--log "keepassxc-cli %s"
                              (mapconcat #'identity args " ")))
  (let* ((prog (keepass-auth-source--keepassxc-executable))
         (out-buf (generate-new-buffer " *keepass-auth-source-out*")))
    (unwind-protect
        (with-temp-buffer
          ;; Feed PASSWORD (plus a terminating newline, as interactive
          ;; keepassxc-cli reads input line-by-line) to the child's stdin,
          ;; unless the database has no password at all.
          (unless (eq password :no-password)
            (insert (or password "") "\n"))
          (let ((exit (apply #'call-process-region
                             (point-min) (point-max)
                             prog t (list out-buf) nil
                             args)))
            ;; Output was appended into OUT-BUF; return it with the exit code.
            (cons (with-current-buffer out-buf (buffer-string)) exit)))
      (kill-buffer out-buf))))

(defun keepass-auth-source--keepassxc-run-stdin (stdin &rest args)
  "Run keepassxc-cli ARGS feeding STDIN (a string) on standard input.
Like `keepass-auth-source--keepassxc-run', for commands that need more on
standard input than the database password alone (e.g. `add'/`edit' with
the new entry's password).  Returns (OUTPUT . EXIT)."
  (let* ((prog (keepass-auth-source--keepassxc-executable))
         (out-buf (generate-new-buffer " *keepass-auth-source-out*")))
    (unwind-protect
        (with-temp-buffer
          (when keepass-auth-source-verbose
            (keepass-auth-source--log "keepassxc-cli %s"
                                      (mapconcat #'identity args " ")))
          (insert stdin)
          (let ((exit (apply #'call-process-region
                             (point-min) (point-max)
                             prog t (list out-buf) nil
                             args)))
            (cons (with-current-buffer out-buf (buffer-string)) exit)))
      (kill-buffer out-buf))))

(defun keepass-auth-source--error (output &optional db)
  "Signal an error describing a failed keepassxc-cli run (OUTPUT).
DB, when given, is the database whose cached master password should be
dropped when the credentials were wrong."
  (let ((msg (string-trim output)))
    (cond
     ((string-match-p "Invalid credentials were provided" msg)
      (when db (password-cache-remove db))
      (user-error "Incorrect master password"))
     (t (user-error "keepassxc-cli failed: %s"
                    (if (> (length msg) 0) msg "unknown error"))))))

(defun keepass-auth-source-keepassxc-term (spec)
  "Return the keepassxc-cli `search' query for SPEC, or nil.

keepassxc-cli's `search' accepts multiple space-separated terms ANDed
together, each scoped to one of the five canonical fields (title, user,
password, url, notes) with a \\='field:keyword\\=' prefix, matched as a
substring.  This is a deliberate lossless pre-filter: it returns a small
candidate set without assuming which combination of keys the caller passed;
the candidate set is then filtered precisely against every present key.

Each auth-source key maps to one canonical field:
  host     -> url:HOST
  user     -> user:USER
  title    -> title:TITLE
  password -> password:PASSWORD
  notes    -> notes:NOTES

The port is deliberately NOT folded into the url term: many entries store a
bare host or a scheme://host URL, and a \"host:port\" substring would
exclude them before the precise matcher ever runs.  The matcher enforces
port semantics instead.

All present keys are joined with spaces, so a search for \"host=A, user=B\"
runs the single command: A-AND-B in one keepassxc-cli call."
  (let* ((host (plist-get spec :host))
         (user (plist-get spec :user))
         (title (plist-get spec :title))
         (password (plist-get spec :password))
         (notes (plist-get spec :notes))
         (terms
          (delq nil
                (list
                 (and host (not (string-blank-p host))
                      (format "url:%s" host))
                 (and user (not (string-blank-p user))
                      (format "user:%s" user))
                 (and title (not (string-blank-p title))
                      (format "title:%s" title))
                 (and password (not (string-blank-p password))
                      (format "password:%s" password))
                 (and notes (not (string-blank-p notes))
                      (format "notes:%s" notes))))))
    (when terms
      (mapconcat #'identity terms " "))))

(defun keepass-auth-source--strip-scheme (url)
  "Return URL without a leading \\='scheme://\\=' (or \\='scheme:\\='), lowercased.
Only a full scheme (ending in \"://\") is stripped; a bare \"host:port\" is
left intact, since \"smtp.gmail.com\" is not a scheme."
  (let ((u (downcase (or url ""))))
    (if (string-match "\\`[a-z][a-z0-9+.-]*://" u)
        (substring u (match-end 0))
      u)))

(defun keepass-auth-source-keepassxc-spec-matcher (spec)
  "Return a predicate matching an entry plist against SPEC.

Applies host/user/port to the canonical KeePass fields:
  host        -> the URL's host (scheme/path stripped) contains \"host\"
  host+port   -> additionally, an explicit \"host:port\" in the URL must
                 match the requested port (a URL that spells no port is
                 also accepted)
  user        -> UserName equals \"user\"
  title, password, notes -> their canonical KeePass fields."
  (let ((host (plist-get spec :host))
        (port (plist-get spec :port))
        (user (plist-get spec :user))
        (title (plist-get spec :title))
        (password (plist-get spec :password))
        (notes (plist-get spec :notes)))
    (lambda (entry)
      (let* ((e-raw (or (plist-get entry :host) ""))
             (e-host (keepass-auth-source--strip-scheme e-raw))
             (e-user (or (plist-get entry :user) ""))
             (e-password (or (plist-get entry :secret) ""))
             (e-title (or (plist-get entry :title) ""))
             (e-notes (or (plist-get entry :notes) "")))
        (and
         (or (string-blank-p (or host ""))
             ;; The entry's URL must contain the requested host (covers bare
             ;; "host", "host:port" and full "scheme://host.../path" URLs).
             (let ((h (keepass-auth-source--strip-scheme host)))
               (and (keepass-auth-source-s-contains-p h e-host t)
                    (or (null port)
                        (string-blank-p (format "%s" port))
                        ;; A requested port must be honored.
                        (keepass-auth-source-s-contains-p
                         (format "%s:%s" h port) e-host t)
                        ;; ...or the URL spells no explicit port at all (a
                        ;; bare host), which we accept for a portless record.
                        (not (string-match-p ":" e-host))))))
         (or (string-blank-p (or user ""))     ; user matches UserName
             (string-equal user e-user))
         (or (string-blank-p (or password "")) ; password matches
             (and (functionp e-password)
                  (string-equal password (funcall e-password))))
         (or (string-blank-p (or title ""))    ; title matches
             (keepass-auth-source-s-contains-p title e-title t))
         (or (string-blank-p (or notes ""))    ; notes matches
             (keepass-auth-source-s-contains-p notes e-notes t)))))))

(defun keepass-auth-source--keepassxc-narrow (entity password term &optional keyfile)
  "Return the entry paths in ENTITY whose any field contains TERM.
Uses the server-side `search' command so only a handful of candidates
are returned, instead of every entry in the database.  KEYFILE, when
non-nil, is the database's key file (see
`keepass-auth-source--keyfile-args')."
  (let* ((run (apply #'keepass-auth-source--keepassxc-run
                     password
                     (append (list "search" "--quiet")
                             (keepass-auth-source--no-password-flag password)
                             (keepass-auth-source--keyfile-args keyfile)
                             (list entity term))))
         (output (car run))
         (exit (cdr run)))
    (when (eq exit 0)
      (seq-filter (lambda (s) (not (string-blank-p s)))
        (split-string output "\n" t)))))

(defun keepass-auth-source--keepassxc-locked-p (status)
  "Return non-nil if STATUS indicates a wrong master password.
STATUS is either the sentinel `:locked' or a raw output string."
  (or (eq status :locked)
      (and (stringp status)
           (string-match-p
            "Invalid credentials were provided\\|Error while reading the database\\|Failed to open"
            status))))

(defun keepass-auth-source--keepassxc-list-entries (spec password)
  "Collect entries matching SPEC, using keepassxc-cli.
SPEC is the raw `auth-source-search' plist (host/user/port/title/...).
Uses the server-side `search' command (aliased: host->URL, host+port->
URL \"host:port\", user->UserName) to narrow down the database to a small
candidate set, then `show's only those candidates and filters them against
the full SPEC.  Returns (ENTRIES . STATUS)."
  (let* ((status nil)
         (db (plist-get spec :db))
         (keyfile (plist-get spec :keyfile))
         (term (keepass-auth-source-keepassxc-term spec))
         (open (apply #'keepass-auth-source--keepassxc-run
                      password
                      (append (list "ls" "--quiet")
                              (keepass-auth-source--no-password-flag password)
                              (keepass-auth-source--keyfile-args keyfile)
                              (list db))))
         (locked-p (not (eq (cdr open) 0)))
         (paths (and (not locked-p) term
                     (keepass-auth-source--keepassxc-narrow
                      db password term keyfile)))
         (matcher (keepass-auth-source-keepassxc-spec-matcher spec))
         (entries
         (and paths
               (let* ((shows (mapcar
                              (lambda (path)
                                (car (apply #'keepass-auth-source--keepassxc-run
                                            password
                                            (append
                                             (list "show" "--quiet" "--show-protected")
                                             (keepass-auth-source--no-password-flag password)
                                             (keepass-auth-source--keyfile-args keyfile)
                                             (list db path)))))
                              paths))
                      (entries (mapcar (lambda (show) (keepass-auth-source--keepassxc-parse
                                                       show (plist-get spec :port)))
                                       shows)))
                 (seq-filter matcher entries)))))
    `(,entries ,(if locked-p :locked status))))

(defun keepass-auth-source--list-entries (entity spec password)
  "Return (ENTRIES . STATUS) for ENTITY matching the auth-source SPEC.
Dispatches to the active backend.  ENTRES is a list of auth plists (each
carrying PORT); STATUS is raw backend output for error reporting and is
nil for backends that do not emit one."
  (pcase keepass-auth-source--active-cli
    ('kpscript
     ;; KPScript refs match the canonical fields directly (as the original
     ;; package did): Username -> -ref-Username, host+path -> -ref-URL.
     (let* ((url (concat (plist-get spec :host)
                         (plist-get spec :path)))
            (cmd (keepass-auth-source--kpscript-command
                  entity
                  (plist-get spec :user)
                  url
                  password))
            (output (shell-command-to-string cmd)))
       (keepass-auth-source--parse output (plist-get spec :port))))
    ('keepassxc
     (keepass-auth-source--keepassxc-list-entries spec password))
    (_ (user-error "No usable keepass backend (keepass-auth-source-cli = %S)"
                   keepass-auth-source-cli))))

(cl-defun keepass-auth-source-search (&rest spec
                                      &key backend type host user port max title
                                        &allow-other-keys)
  "Find password for a request, if several passwords are available prompt user to select an entry."
  (let* ((db-info (keepass-auth-source--normalize-db
                   (slot-value backend 'source)))
         (entity (nth 0 db-info))
         (keyfile (or (plist-get (slot-value backend 'data) :keyfile)
                      (nth 1 db-info)))
         (password-spec (or (plist-get (slot-value backend 'data) :password-spec)
                            ;; backend built with a plain string :source has
                            ;; no :data; default to :prompt (ask user), never
                            ;; to nil (which would mean "no password").
                            (nth 2 db-info))))
    (when (file-exists-p entity)
      (when keepass-auth-source-verbose
        (message "keepass-auth-source-search spec: host=%S user=%S port=%S title=%S"
                 host user port title))
      (let* ((url (url-generic-parse-url host))
             (url (if (url-fullness url)
                      url
                    (url-generic-parse-url (concat "//" host))))
             (host (or (url-host url) ""))
             (max (or max 1))
             (path (or (car (url-path-and-query url)) ""))
             (password (keepass-auth-source--resolve-password
                        password-spec entity keepass-auth-source-cache-expiry))
             (spec `(:host ,host :user ,user :port ,port :title ,title
                        :path ,path :db ,entity
                        :keyfile ,keyfile))
             (parsed (keepass-auth-source--list-entries entity spec password))
             (result (nth 0 parsed))
             (status (nth 1 parsed)))
        (cond
         ;; Wrong master password (backend-specific marker).
         ((and (eq keepass-auth-source--active-cli 'keepassxc)
               (keepass-auth-source--keepassxc-locked-p status))
          (password-cache-remove entity)
          (user-error "Incorrect password for %s" entity))
         ((and (eq keepass-auth-source--active-cli 'kpscript)
               (with-temp-buffer
                 (insert status)
                 (goto-char 0)
                 (search-forward-regexp "^Unhandled Exception:" nil t)))
          (password-cache-remove entity)
          (user-error
           "An exception was thrown by KeePass.exe (your KPScript is likely out of date)\n %s"
           status))
         ((and (eq keepass-auth-source--active-cli 'kpscript)
               (with-temp-buffer
                 (insert status)
                 (goto-char 0)
                 (search-forward-regexp "^E:" nil t)))
          (cond
           ((string-match-p "The master key is invalid" status)
            (password-cache-remove entity)
            (user-error "Incorrect password for %s" entity))
           (t (user-error "Something went wrong in keepass: %s" status))))
         (t (let* ((rc (when (and keepass-auth-match-title
                                 title
                                 (not (string-blank-p title)))
                           (seq-filter
                            (lambda (it)
                              (keepass-auth-source-s-contains-p
                               title (plist-get it :title) t))
                            result)))
                   (used (if (= 1 (length rc)) rc result)))
              (cond
               ((= 0 (length used)) nil)
               (t
                (when (and keepass-auth-source-verbose
                           (> (length used) 1))
                  (message (concat "keepass-auth-source: %d matching entries "
                                   "for %S; returning up to %d")
                           (length used) host max))
                (seq-take used max))))))))))

(defun keepass-auth-source-backend-parser (entry)
  "Provides keepass backend for files with the .kdbx extension.
ENTRY may be a plain database file name, or a list
\(PATH [KEYFILE] [PASSWORD]) -- see `keepass-auth-source--normalize-db'.
For the list form the key file and password specifications are carried on
the backend's `data' slot so the search can honour them."
  (let* ((db (keepass-auth-source--normalize-db entry))
         (path (nth 0 db)))
    (when (and (stringp path)
               (string-equal "kdbx" (file-name-extension path)))
      (auth-source-backend :type 'keepass
                           :source path
                           :search-function #'keepass-auth-source-search
                           ;; Stash the key file and password specs for the
                           ;; search function; auth-source's own parameter
                           ;; parsing ignores unknown list entries.
                           :data (list :keyfile (nth 1 db)
                                       :password-spec (nth 2 db))))))

(defun keepass-auth-source--remember-advice (fn spec found)
  "Call auth-source-remember FN unless FOUND is empty.
Suppresses negative caching: a lookup that finds nothing is not remembered,
so a transient failure does not mask later queries.  See
`keepass-auth-source-suppress-negative-cache'."
  (if (and keepass-auth-source-suppress-negative-cache (null found))
      nil
    (funcall fn spec found)))

;;;###autoload
(defun keepass-auth-source-enable ()
  "Enable keepass auth source.
Chooses a backend from `keepass-auth-source-cli'; by default
keepassxc-cli is used when available, otherwise KeePass/KPScript.
Also installs advice suppressing `auth-source' negative caching when
`keepass-auth-source-suppress-negative-cache' is non-nil."
  (interactive)
  (let ((cli (keepass-auth-source--resolve-cli)))
    (if cli
        (progn
          (setq keepass-auth-source--active-cli cli)
          (auth-source-forget-all-cached)
          ;; Make `auth-source-remember' skip empty results, unless already
          ;; installed (idempotent across repeated calls to `enable').
          (unless (memq #'keepass-auth-source--remember-advice
                        (advice-member-p #'keepass-auth-source--remember-advice
                                         'auth-source-remember))
            (advice-add 'auth-source-remember :around
                        #'keepass-auth-source--remember-advice))
          (if (boundp 'auth-source-backend-parser-functions)
              (add-hook 'auth-source-backend-parser-functions #'keepass-auth-source-backend-parser)
            (advice-add 'auth-source-backend-parse :before-until #'keepass-auth-source-backend-parser)))
      (error "No usable keepass backend found. Install keepassxc-cli, or KeePass with KPScript, and add them to `exec-path'."))))

;;;###autoload
(defun keepass-auth-source-forget-cached ()
  "Forget the cached KeePass database master password.

The master password is otherwise reused for
`keepass-auth-source-cache-expiry' seconds, so this makes the next lookup
re-prompt for it.  Run this after changing the master password.

This only touches keepass-auth-source's own cache; it does not clear
`auth-source' search results (use `auth-source-forget-all-cached' for
those)."
  (interactive)
  (maphash (lambda (key _pwd)
             (when (and (stringp key)
                        (string-suffix-p ".kdbx" key))
               (password-cache-remove key)))
           password-data)
  (message "keepass-auth-source master-password cache cleared."))

(provide 'keepass-auth-source)
;;; keepass-auth-source.el ends here
