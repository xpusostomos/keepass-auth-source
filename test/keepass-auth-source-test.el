;;; keepass-auth-source-test.el --- Tests for keepass-auth-source -*- lexical-binding: t -*-

;;; Commentary:

;; Run with:
;;   emacs -Q --batch -l ert -l keepass-auth-source.el \
;;         -l keepass-auth-source-test.el -f ert-run-tests-batch-and-exit

;;; Code:
(require 'ert)
(require 'keepass-auth-source)

(defmacro keepass-auth-source--with-cli (cli &rest body)
  "Bind the active backend to CLI while running BODY."
  `(let ((keepass-auth-source-cache-expiry nil)
         keepass-auth-source--active-cli)
     (setq keepass-auth-source--active-cli ,cli)
     ,@body))

;;;; Parse helpers

(ert-deftest keepass-auth-source-parse-auth-maps-fields ()
  "KPScript `S: key = value' lines map to the auth-source plist shape."
  (let ((a (keepass-auth-source--parse-auth
            "S: UserName = foo\nS: Password = secret\nS: Title = My\nS: URL = https://x"
            587)))
    (should (equal 587 (plist-get a :port)))
    (should (equal "foo" (plist-get a :user)))
    (should (equal "My" (plist-get a :title)))
    (should (equal "https://x" (plist-get a :host)))
    ;; secret is wrapped in a thunk
    (should (equal "secret" (funcall (plist-get a :secret))))))

(ert-deftest keepass-auth-source-parse-handles-empty ()
  (let ((r (keepass-auth-source--parse "Status line\n\n" nil)))
    (should (listp (car r)))
    (should (stringp (nth 1 r)))))

;;;; keepassxc-cli parsing (pure, mocked input)

(ert-deftest keepass-auth-source-keepassxc-parse-summary ()
  "A `keepassxc-cli show' summary should parse into the S: shape and a plist."
  (let ((plist (keepass-auth-source--keepassxc-parse
                "Title: aws\nUserName: c@e.com\nPassword: real\nURL: https://host/a\nNotes: \nTags: \n"
                443)))
    (should (equal 443 (plist-get plist :port)))
    (should (equal "aws" (plist-get plist :title)))
    (should (equal "c@e.com" (plist-get plist :user)))
    (should (equal "real" (funcall (plist-get plist :secret))))
    (should (equal "https://host/a" (plist-get plist :host)))
    (should (eq nil (plist-get plist :url)))
    ;; A value containing a colon must not be swallowed by a greedy key match.
    (should (equal "https://host/a" (plist-get plist :host)))))

(ert-deftest keepass-auth-source-keepassxc-parse-protected-password ()
  "A Password: PROTECTED line means the secret was not revealed, so no
`:secret' is produced rather than storing the literal \"PROTECTED\"."
  (let ((plist (keepass-auth-source--keepassxc-parse
                "Title: x\nUserName: u\nPassword: PROTECTED\n" nil)))
    (should (null (plist-get plist :secret)))))

;;;; Command builders

(ert-deftest keepass-auth-source-kpscript-command-uses-custom-program ()
  (let ((keepass-auth-source-kpscript-program "my-kpscript"))
    (should (string-match-p
             (regexp-quote "my-kpscript -C:ListEntries")
             (keepass-auth-source--kpscript-command
              "/tmp/db.kdbx" "u" "x.y/p" "pw")))))

(ert-deftest keepass-auth-source-kpscript-command-includes-refs ()
  (let ((cmd (keepass-auth-source--kpscript-command
              "/tmp/db.kdbx" "user1" "host.example.com" "pass")))
    (should (string-match-p "-ref-Username:\"user1\"" cmd))
    (should (string-match-p "-ref-URL:\"//host.example.com//\"" cmd))
    (should (string-match-p "-pw:\"pass\"" cmd))))

;;;; Backend resolution

(ert-deftest keepass-auth-source-resolve-forced ()
  (let ((keepass-auth-source-cli 'keepassxc))
    (should (eq 'keepassxc (keepass-auth-source--resolve-cli))))
  (let ((keepass-auth-source-cli 'kpscript))
    (should (eq 'kpscript (keepass-auth-source--resolve-cli)))))

(ert-deftest keepass-auth-source-resolve-auto-prefers-keepassxc ()
  (let ((keepass-auth-source-cli 'auto)
        (keepass-auth-source-keepassxc-cli-program "keepassxc-cli"))
    ;; On a machine with keepassxc-cli on PATH this resolves to keepassxc.
    (if (executable-find "keepassxc-cli")
        (should (eq 'keepassxc (keepass-auth-source--resolve-cli)))
      (should (memq (keepass-auth-source--resolve-cli) '(nil kpscript))))))

;;;; Locked detection

(ert-deftest keepass-auth-source-locked-p ()
  (should (keepass-auth-source--keepassxc-locked-p :locked))
  (should (keepass-auth-source--keepassxc-locked-p
           "Error while reading the database: Invalid credentials were provided, please try again.
If this reoccurs, then your database file may be corrupt."))
  (should-not (keepass-auth-source--keepassxc-locked-p ""))
  (should-not (keepass-auth-source--keepassxc-locked-p nil)))

;;;; Integration: full search against a real keepassxc-cli (optional)

(defcustom keepass-auth-source-test-program
  (or (executable-find "keepassxc-cli") "")
  "keepassxc-cli executable for the optional integration test.")

(defun keepass-auth-source-test-run (cmd)
  "Run shell command CMD via /bin/sh, returning its stdout."
  (with-temp-buffer
    (call-process "sh" nil t nil "-c" cmd)
    (buffer-string)))

(defun keepass-auth-source-test-add (cli db title user url)
  "Add an entry TITLE with USER and URL to DB via keepassxc-cli CLI."
  (keepass-auth-source-test-run
   (format "printf 'PASS\\n' | %s add -q %s %s -u %s -g --url %s"
           cli (shell-quote-argument db) (shell-quote-argument title)
           (shell-quote-argument user) (shell-quote-argument url))))

(defun keepass-auth-source-test-make-db ()
  "Create a fresh throwaway kdbx with the target entry plus decoys.
The real SMTP-style entry is 'target' (host x.example.com, user alice, port
443 in the URL).  The decoys deliberately mismatch one credential each, so a
correct search must reject all of them."
  (let* ((dir (make-temp-file "kpa-test-" t))
         (db (expand-file-name "t.kdbx" dir))
         (cli (shell-quote-argument keepass-auth-source-test-program))
         (qdb (shell-quote-argument db)))
    (keepass-auth-source-test-run
     (format "printf 'PASS\\nPASS\\n' | %s db-create -q %s --set-password" cli qdb))
    ;; The target entry: right host:port, right user.
    (keepass-auth-source-test-add cli qdb "target" "alice" "x.example.com:443")
    ;; Decoys -- each is close but wrong in one way.
    (keepass-auth-source-test-add cli qdb "wrong-user"   "bob"     "x.example.com:443")
    (keepass-auth-source-test-add cli qdb "wrong-host"   "alice"   "y.example.com:443")
    (keepass-auth-source-test-add cli qdb "wrong-port"   "alice"   "x.example.com:465")
    (keepass-auth-source-test-add cli qdb "same-user-only" "alice" "https://z.example.com")
    (keepass-auth-source-test-add cli qdb "same-host-only" "carol" "https://x.example.com/path")
    (keepass-auth-source-test-add cli qdb "bare-host"    "alice"   "x.example.com")
    db))

(defun keepass-auth-source-test-search (db spec)
  "Search DB with SPEC (a plist), returning the matching entries.
Runs inside the keepassxc backend with PASS as the master password."
  (save-window-excursion
    (keepass-auth-source--with-cli 'keepassxc
      (let ((password-cache-expiry nil))
        (password-cache-add db "PASS"))
      (let ((backend (auth-source-backend :type 'keepass :source db
                                          :search-function #'keepass-auth-source-search)))
        (apply #'keepass-auth-source-search :backend backend :max 5 (append spec nil))))))

(ert-deftest keepass-auth-source-integration-via-keepassxc ()
  (skip-unless keepass-auth-source-test-program)
  (let* ((db (keepass-auth-source-test-make-db))
         (backend (auth-source-backend :type 'keepass :source db
                                       :search-function #'keepass-auth-source-search)))
    (unwind-protect
        (progn
          (keepass-auth-source--with-cli 'keepassxc
            (let ((password-cache-expiry nil))
              (password-cache-add db "PASS"))
            (let ((res (keepass-auth-source-search
                        :backend backend :host "x.example.com" :user "alice" :port 443 :max 1)))
              (should (= 1 (length res)))
              (let* ((en (car res))
                     (pw (funcall (plist-get en :secret))))
                (should (stringp pw))
                (should (= 443 (plist-get en :port)))))))
      (delete-file db))))

(ert-deftest keepass-auth-source-integration-host-user-port ()
  "Host+user+port search selects the target plus the portless record
(bare-host), rejecting wrong-user, wrong-host and wrong-port decoys."
  (skip-unless keepass-auth-source-test-program)
  (let ((db (keepass-auth-source-test-make-db)))
    (unwind-protect
        (let ((res (keepass-auth-source-test-search
                    db '(:host "x.example.com" :user "alice" :port 443))))
          ;; Lenient port rule: an entry whose URL spells no port still
          ;; matches a port-requesting search, so both target (:443) and
          ;; bare-host (no port) are returned; wrong-port (:465) is not.
          (let ((titles (mapcar (lambda (e) (plist-get e :title)) res)))
            (should (member "target" titles))
            (should (member "bare-host" titles))
            (should-not (member "wrong-port" titles))
            (should-not (member "wrong-user" titles))
            (should-not (member "wrong-host" titles))))
      (delete-file db))))

(ert-deftest keepass-auth-source-integration-host-user ()
  "Host+user search (no port) matches both a bare-host and host:port entry."
  (skip-unless keepass-auth-source-test-program)
  (let ((db (keepass-auth-source-test-make-db)))
    (unwind-protect
        (let ((res (keepass-auth-source-test-search
                    db '(:host "x.example.com" :user "alice"))))
          ;; Substring narrow: url:x.example.com matches both 'bare-host'
          ;; (URL "x.example.com") and 'target' (URL "x.example.com:443").
          ;; Wrong user/host must be rejected.  'same-host-only' has user carol.
          (let ((titles (mapcar (lambda (e) (plist-get e :title)) res)))
            (should (member "target" titles))
            (should (member "bare-host" titles))
            (should-not (member "wrong-user" titles))
            (should-not (member "wrong-host" titles))
            (should-not (member "same-host-only" titles))))
      (delete-file db))))

(ert-deftest keepass-auth-source-integration-title-finds-entry ()
  "Searching by title alone returns exactly that entry."
  (skip-unless keepass-auth-source-test-program)
  (let ((db (keepass-auth-source-test-make-db)))
    (unwind-protect
        (let ((res (keepass-auth-source-test-search
                    db '(:title "target"))))
          (should (= 1 (length res)))
          (should (string-equal "target" (plist-get (car res) :title))))
      (delete-file db))))

(defun keepass-auth-source-test-titles (db spec)
  "Return the sorted entry titles returned by searching DB with SPEC."
  (sort (mapcar (lambda (e) (plist-get e :title))
                (keepass-auth-source-test-search db spec))
        #'string<))

(defun keepass-auth-source-test-assert (db spec &rest expected)
  "Assert searching DB with SPEC returns exactly the EXPECTED title set.
Each entry in the decoy DB takes one canonical role:
  target         x.example.com:443 / alice
  wrong-user     x.example.com:443 / bob
  wrong-host     y.example.com:443 / alice
  wrong-port     x.example.com:465 / alice
  same-user-only https://z.example.com / alice
  same-host-only https://x.example.com/path / carol
  bare-host      x.example.com / alice
A search must return all entries that match *every* key given, and only them."
  (let ((got (keepass-auth-source-test-titles db `(,@spec :max 5))))
    (should (equal (sort (copy-sequence (append expected nil)) #'string<) got))))

(ert-deftest keepass-auth-source-integration-matrix ()
  "A broad host/user/port matrix returns the exact right entries."
  (skip-unless keepass-auth-source-test-program)
  (let ((db (keepass-auth-source-test-make-db)))
    (unwind-protect
        (progn
          ;; Host alone: everything whose URL contains the host (incl. host:port
          ;; and full-URL entries with a different user -- the user is a
          ;; separate key).
          (keepass-auth-source-test-assert
           db '(:host "x.example.com")
           "target" "wrong-user" "wrong-port" "bare-host" "same-host-only")
          (keepass-auth-source-test-assert
           db '(:host "y.example.com") "wrong-host")
          ;; Host + port: entries whose URL embeds host:port match, and
          ;; portless-URL entries are accepted for any requested port.
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :port 443)
           "target" "wrong-user" "bare-host" "same-host-only")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :port 465)
           "wrong-port" "bare-host" "same-host-only")
          ;; Host + user.
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "alice")
           "target" "wrong-port" "bare-host")
          (keepass-auth-source-test-assert
           db '(:host "y.example.com" :user "alice")
           "wrong-host")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "bob")
           "wrong-user")
          ;; Host + user + port.
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "alice" :port 443)
           "target" "bare-host")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "bob" :port 443)
           "wrong-user")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "alice" :port 465)
           "wrong-port" "bare-host")
          ;; User alone.
          (keepass-auth-source-test-assert
           db '(:user "alice")
           "target" "wrong-host" "wrong-port" "same-user-only" "bare-host")
          ;; User + title.
          (keepass-auth-source-test-assert
           db '(:user "alice" :title "wrong")
           "wrong-host" "wrong-port")
          ;; Title alone: substring match on the title field.
          (keepass-auth-source-test-assert
           db '(:title "host") "bare-host" "wrong-host" "same-host-only")
          ;; A port alone (no host) is not a realistic auth-source shape;
          ;; it matches nothing.
          (keepass-auth-source-test-assert db '(:port 443)))
      (delete-file db))))

(ert-deftest keepass-auth-source-integration-wrong-password-signals ()
  "A wrong master password is reported, not silently empty."
  (skip-unless keepass-auth-source-test-program)
  (let* ((db (keepass-auth-source-test-make-db))
         (backend (auth-source-backend :type 'keepass :source db
                                       :search-function #'keepass-auth-source-search)))
    (unwind-protect
        (keepass-auth-source--with-cli 'keepassxc
          (let ((password-cache-expiry nil))
            (password-cache-add db "WRONG"))
          (should-error (keepass-auth-source-search
                         :backend backend :host "x.example.com" :user "alice" :port 443 :max 1)
                        :type 'user-error))
      (delete-file db))))

;;;; Search-term builder: aliases map onto the 5 canonical fields

(ert-deftest keepass-auth-source-term-aliases ()
  "The search term maps host/user/port onto canonical field prefixes, ANDed."
  (let ((keepass-auth-source-cache-expiry nil))
    (should (equal "url:h.example.com"
                   (keepass-auth-source-keepassxc-term
                    '(:host "h.example.com"))))
    ;; The port is deliberately NOT folded into the url term: entries often
    ;; store a bare host, and a "host:port" substring would exclude them
    ;; before the matcher can apply its port rules.
    (should (equal "url:h.example.com"
                   (keepass-auth-source-keepassxc-term
                    '(:host "h.example.com" :port 443))))
    (should (equal "user:alice@example.com"
                   (keepass-auth-source-keepassxc-term
                    '(:user "alice@example.com"))))
    (should (equal "title:My Title"
                   (keepass-auth-source-keepassxc-term
                    '(:title "My Title"))))
    (should (equal "password:s3cret"
                   (keepass-auth-source-keepassxc-term
                    '(:password "s3cret"))))
    (should (equal "notes:meeting"
                   (keepass-auth-source-keepassxc-term
                    '(:notes "meeting"))))
    ;; A port without a host yields no term (port-only lookups are not a
    ;; realistic auth-source pattern and keepassxc can't scope a bare port).
    (should-not (keepass-auth-source-keepassxc-term '(:port 443)))
    ;; Terms for all present keys are ANDed with a space, in a fixed order.
    (should (equal "url:h.example.com user:u@x.com title:T"
                   (keepass-auth-source-keepassxc-term
                    '(:host "h.example.com" :user "u@x.com" :title "T"))))
    (should-not (keepass-auth-source-keepassxc-term '()))))

;;;; Pure spec-matcher tests (no subprocess, all 5 canonical attributes)

(ert-deftest keepass-auth-source-matcher-canonical-attributes ()
  "The matcher reads every canonical KeePass attribute from an entry plist."
  (let* ((spec '(:host "h.example.com" :user "u@e.com" :port 443
                        :title "T" :password "pw" :notes "N"))
         (entry '(:host "h.example.com:443" :user "u@e.com" :title "T"
                         :secret (lambda () "pw") :notes "N"))
         (m (keepass-auth-source-keepassxc-spec-matcher spec)))
    (should (funcall m entry))
    ;; Each attribute on its own satisfied; vary one and it fails.
    (should-not (funcall (keepass-auth-source-keepassxc-spec-matcher
                          (plist-put (copy-sequence spec) :host "other.example.com"))
                         entry))
    (should-not (funcall (keepass-auth-source-keepassxc-spec-matcher
                          (plist-put (copy-sequence spec) :user "other@e.com"))
                         entry))
    (should-not (funcall (keepass-auth-source-keepassxc-spec-matcher
                          (plist-put (copy-sequence spec) :title "Other"))
                         entry))
    (should-not (funcall (keepass-auth-source-keepassxc-spec-matcher
                          (plist-put (copy-sequence spec) :password "nope"))
                         entry))
    (should-not (funcall (keepass-auth-source-keepassxc-spec-matcher
                          (plist-put (copy-sequence spec) :notes "Nope"))
                         entry))))

(ert-deftest keepass-auth-source-matcher-port-and-scheme ()
  "Host/port matching is general across bare host, host:port and scheme URLs."
  ;; Requesting host+port: an entry with host:port matches; a differing
  ;; explicit port is rejected; a bare host (no port) still matches.
  (let ((m (keepass-auth-source-keepassxc-spec-matcher
            '(:host "smtp.gmail.com" :user "x" :port "465"))))
    (should (funcall m '(:host "smtp.gmail.com:465" :user "x")))
    (should-not (funcall m '(:host "smtp.gmail.com:995" :user "x")))
    (should (funcall m '(:host "smtp.gmail.com" :user "x")))
    (should (funcall m '(:host "https://smtp.gmail.com:465/" :user "x"))))
  ;; Requesting host only: a host:port or a scheme://host... URL both match.
  (let ((m (keepass-auth-source-keepassxc-spec-matcher
            '(:host "smtp.gmail.com" :user "x"))))
    (should (funcall m '(:host "smtp.gmail.com" :user "x")))
    (should (funcall m '(:host "smtp.gmail.com:465" :user "x")))
    (should (funcall m '(:host "https://smtp.gmail.com/some/path" :user "x")))
    (should-not (funcall m '(:host "other.example" :user "x")))))

;;;; DB spec: constructor, accessors, predicate, normalization

(ert-deftest keepass-make-db-spec-constructor ()
  "`keepass-make-db-spec' builds a canonical keyword plist.
An omitted `:password' is NOT an explicit nil: the latter means a
database with no master password, while omission means `:prompt'."
  ;; All fields given; canonical key order is :file :keyfile :password :yubi.
  (should (equal '(:file "db.kdbx" :keyfile "k.txt" :password "pw" :yubi "1:7370001")
                 (keepass-make-db-spec :password "pw" :yubi "1:7370001"
                                       :file "db.kdbx" :keyfile "k.txt")))
  ;; Password omitted -> :prompt.
  (should (equal :prompt
                 (plist-get (keepass-make-db-spec :file "db.kdbx") :password)))
  ;; Password explicitly nil -> nil (genuinely no master password).
  (should (eq nil (plist-get (keepass-make-db-spec :file "db.kdbx" :password nil)
                             :password)))
  ;; Keyfile and yubi default to nil.
  (should-not (plist-get (keepass-make-db-spec :file "db.kdbx") :keyfile))
  (should-not (plist-get (keepass-make-db-spec :file "db.kdbx") :yubi))
  ;; Unknown keywords are rejected up front.
  (should-error (keepass-make-db-spec :file "db" :bogus 1))
  ;; A spec must spell out a :file.
  (should-error (keepass-make-db-spec :password "pw")))

(ert-deftest keepass-db-spec-predicate ()
  "`keepass-db-spec-p' recognizes spec plists, not strings/lists/garbage."
  (should (keepass-db-spec-p
           (keepass-make-db-spec :file "db.kdbx" :password nil)))
  (should (keepass-db-spec-p '(:file "db.kdbx")))
  ;; A positional list, a string, and a plist with an unknown keyword aren't.
  (should-not (keepass-db-spec-p "db.kdbx"))
  (should-not (keepass-db-spec-p '("db.kdbx" "k.txt")))
  (should-not (keepass-db-spec-p '(:file "db.kdbx" :bogus 1)))
  ;; A spec without :file is incomplete.
  (should-not (keepass-db-spec-p '(:keyfile "k.txt"))))

(ert-deftest keepass-db-spec-accessors ()
  "The `keepass-db-spec-*' accessors read the canonical fields."
  (let* ((kf (lambda () "k.txt"))
         (ps (lambda () "pw"))
         (spec (keepass-make-db-spec :file "db.kdbx" :keyfile kf
                                     :password ps :yubi "1:7")))
    (should (equal "db.kdbx" (keepass-db-spec-file spec)))
    (should (eq kf (keepass-db-spec-keyfile spec)))
    (should (eq ps (keepass-db-spec-password spec)))
    (should (equal "1:7" (keepass-db-spec-yubi spec)))))

(ert-deftest keepass-db-spec-normalize ()
  "A string, positional list or spec plist normalizes to the canonical plist."
  ;; Plain string: canonical plist, password = :prompt.
  (should (equal '(:file "db.kdbx" :keyfile nil :password :prompt :yubi nil)
                 (keepass-db-spec-normalize "db.kdbx")))
  ;; (PATH KEYFILE PASSWORD): all present.
  (should (equal '(:file "db.kdbx" :keyfile "k.txt" :password "pw" :yubi nil)
                 (keepass-db-spec-normalize '("db.kdbx" "k.txt" "pw"))))
  ;; (PATH KEYFILE): password absent = :prompt.
  (should (equal '(:file "db.kdbx" :keyfile "k.txt" :password :prompt :yubi nil)
                 (keepass-db-spec-normalize '("db.kdbx" "k.txt"))))
  ;; (PATH KEYFILE nil): password present-but-nil = no password.
  (should (equal '(:file "db.kdbx" :keyfile "k.txt" :password nil :yubi nil)
                 (keepass-db-spec-normalize '("db.kdbx" "k.txt" nil))))
  ;; Key file and password may be functions, retained as-is.
  (let ((kf (lambda () "k.txt")) (ps (lambda () "pw")))
    (should (equal (list :file "db.kdbx" :keyfile kf :password ps :yubi nil)
                   (keepass-db-spec-normalize (list "db.kdbx" kf ps)))))
  ;; A spec plist carries its fields through, re-canonicalized.
  (should (equal '(:file "d.kdbx" :keyfile nil :password nil :yubi "1:7")
                 (keepass-db-spec-normalize (keepass-make-db-spec
                                             :file "d.kdbx" :password nil
                                             :yubi "1:7"))))
  ;; Garbage is rejected.
  (should-error (keepass-db-spec-normalize 42)))

(ert-deftest keepass-auth-source-resolve-keyfile-password ()
  "Key file and password specs accept strings, functions, :prompt and nil."
  ;; Key file: string stays, function is called, nil is nil.
  (should (equal "k.txt" (keepass-auth-source--resolve-keyfile "k.txt")))
  (should (equal "k.txt" (keepass-auth-source--resolve-keyfile (lambda () "k.txt"))))
  (should-not (keepass-auth-source--resolve-keyfile nil))
  ;; Password: string stays, function is called.
  (should (equal "pw" (keepass-auth-source--resolve-password "pw" "db")))
  (should (equal "pw" (keepass-auth-source--resolve-password (lambda () "pw") "db")))
  ;; nil means NO password, reported as the `:no-password' sentinel.
  (should (eq :no-password
              (keepass-auth-source--resolve-password nil "nopwdb"))))

;;;; YubiKey argument generation

(ert-deftest keepass-auth-source-yubi-args ()
  "`--yubikey' arguments are built from a string, a function, or nil."
  (should (equal '("--yubikey" "1:7370001")
                 (keepass-auth-source--yubi-args "1:7370001")))
  (should (equal '("--yubikey" "2")
                 (keepass-auth-source--yubi-args (lambda () "2"))))
  (should-not (keepass-auth-source--yubi-args nil))
  (should-not (keepass-auth-source--yubi-args 42))
  ;; The shared string-or-function resolver backs keyfile and yubi on the same
  ;; rules.
  (should (equal "s" (keepass-auth-source--resolve-string "s")))
  (should (equal "s" (keepass-auth-source--resolve-string (lambda () "s"))))
  (should-not (keepass-auth-source--resolve-string nil)))

;;;; Negative-cache suppression

(ert-deftest keepass-auth-source-suppress-negative-cache ()
  "`auth-source-remember' is a no-op for empty results when suppression is on."
  (let ((keepass-auth-source-suppress-negative-cache t)
        (called nil))
    (unwind-protect
        (progn
          (advice-add 'auth-source-remember :around
                      #'keepass-auth-source--remember-advice)
          ;; An empty FOUND must not be remembered.
          (keepass-auth-source--remember-advice
           (lambda (_ _) (setq called t)) '(:host "x") nil)
          (should-not called)
          ;; A non-empty FOUND passes through.
          (let ((result))
            (setq result
                  (keepass-auth-source--remember-advice
                   (lambda (_ found) found) '(:host "x") '(:secret "s")))
            (should (equal '(:secret "s") result))))
      (advice-remove 'auth-source-remember
                     #'keepass-auth-source--remember-advice))))

(ert-deftest keepass-auth-source-multi-db-separate-caches ()
  "Multiple databases each answer their own queries, each master
password is cached separately, and entries with portless URLs are found
by searches that request a port."
  (let* ((keepass-auth-source-cache-expiry nil)
        (keepass-auth-source--active-cli 'keepassxc)
        (dir (make-temp-file "kpa-multi-" t))
        (db1 (concat (file-name-as-directory (make-temp-file "one-" t)) "one.kdbx"))
        (db2 (concat (file-name-as-directory (make-temp-file "two-" t)) "two.kdbx"))
        (auth-sources (list db1 db2)))
    ;; Register the backend parser, as `keepass-auth-source-enable' would:
    ;; without it auth-source parses the .kdbx entries with its default
    ;; (netrc) parser and the search finds no usable backend.
    (add-hook 'auth-source-backend-parser-functions
              #'keepass-auth-source-backend-parser)
    (unless (executable-find "keepassxc-cli")
      (ert-skip "keepassxc-cli not available"))
    (unwind-protect
        (progn
          (with-temp-buffer
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'PASSONE\\nPASSONE\\n' | keepassxc-cli db-create -q "
                                  (shell-quote-argument db1) " --set-password"))
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'PASSONE\\n' | keepassxc-cli add -q "
                                  (shell-quote-argument db1)
                                  " smtp -u me@one --url smtp.one.example"))
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'PASSTWO\\nPASSTWO\\n' | keepassxc-cli db-create -q "
                                  (shell-quote-argument db2) " --set-password"))
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'PASSTWO\\n' | keepassxc-cli add -q "
                                  (shell-quote-argument db2)
                                  " smtp -u me@two --url smtp.two.example")))
          (should (file-exists-p db1))
          (should (file-exists-p db2))
          (let ((password-cache-expiry nil))
            (password-cache-add db1 "PASSONE")
            (password-cache-add db2 "PASSTWO")
            (let* ((r1 (auth-source-search :host "smtp.one.example" :user "me@one"
                                           :port "465" :require '(:secret)))
                   (r2 (auth-source-search :host "smtp.two.example" :user "me@two"
                                           :port "465" :require '(:secret))))
              (should (= 1 (length r1)))
              (should (equal "me@one" (plist-get (car r1) :user)))
              (should (= 1 (length r2)))
              (should (equal "me@two" (plist-get (car r2) :user)))))
          (should (equal "PASSONE" (password-read-from-cache db1)))
          (should (equal "PASSTWO" (password-read-from-cache db2))))
      (ignore-errors (delete-file db1))
      (ignore-errors (delete-file db2)))))

(ert-deftest keepass-auth-source-keyfile-honoured ()
  "A database secured by both a master password and a key file is found
when the auth-sources entry lists the key file.  The password may come
from a string or from a function in the spec."
  (let* ((keepass-auth-source-cache-expiry nil)
        (keepass-auth-source--active-cli 'keepassxc)
        (dir (make-temp-file "kpa-kf-" t))
        (db (concat (file-name-as-directory (make-temp-file "kf-db-" t)) "db.kdbx"))
        (keyfile (concat (file-name-as-directory dir) "key.txt")))
    (unless (executable-find "keepassxc-cli")
      (ert-skip "keepassxc-cli not available"))
    (with-temp-file keyfile (insert "STANDARD-KEY-FILE-SECRET"))
    (add-hook 'auth-source-backend-parser-functions
              #'keepass-auth-source-backend-parser)
    (unwind-protect
        (progn
          (with-temp-buffer
            ;; Create a DB that requires both the key file and the password.
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'KEYPW\\nKEYPW\\n' | keepassxc-cli db-create -q "
                                  (shell-quote-argument db)
                                  " --set-key-file " (shell-quote-argument keyfile)
                                  " --set-password"))
            (call-process "sh" nil t nil "-c"
                          (concat "printf 'KEYPW\\n' | keepassxc-cli add -q "
                                  "--key-file " (shell-quote-argument keyfile) " "
                                  (shell-quote-argument db)
                                  " kf -u me@kf --url kf.example")))
          (should (file-exists-p db))
          (let ((password-cache-expiry nil))
            ;; Password as a string in the spec: no user prompt, key file
            ;; passed on every CLI call.
            (let ((auth-sources (list (list db keyfile "KEYPW"))))
              (let ((res (auth-source-search :host "kf.example" :user "me@kf"
                                             :port "465" :require '(:secret))))
                (should (= 1 (length res)))
                (should (equal "me@kf" (plist-get (car res) :user)))
                (should (stringp (funcall (plist-get (car res) :secret))))))
            ;; Password as a function; same search still works.
            (let ((auth-sources (list (list db keyfile (lambda () "KEYPW")))))
              (let ((res (auth-source-search :host "kf.example" :user "me@kf"
                                             :port "465" :require '(:secret))))
                (should (= 1 (length res))))))
          ;; A wrong key file means keepassxc-cli cannot open the DB: the failed
          ;; open is treated as a wrong credential, so the lookup raises
          ;; `user-error'.  (A distinct host avoids the auth-source success
          ;; cache from the earlier searches masking the failure.)
          (let ((auth-sources (list (list db "/nonexistent-key.txt" "KEYPW"))))
            (let ((password-cache-expiry nil))
              (should-error (auth-source-search :host "other.example" :user "me@kf"
                                                :port "465" :require '(:secret))
                            :type 'user-error))))
      (ignore-errors (delete-file db))
      (ignore-errors (delete-file keyfile))
      (ignore-errors (delete-directory dir)))))

(ert-deftest keepass-auth-source-plist-spec-integration ()
  "A keyword spec plist in `auth-sources' drives a working search.
Exercises `keepass-make-db-spec' through the backend parser and the full
search path (password supplied as a string in the spec)."
  (let* ((keepass-auth-source-cache-expiry nil)
         (keepass-auth-source--active-cli 'keepassxc)
         (dir (make-temp-file "kpa-spec-" t))
         (db (concat (file-name-as-directory (make-temp-file "spec-db-" t)) "db.kdbx")))
    (unless (executable-find "keepassxc-cli")
      (ert-skip "keepassxc-cli not available"))
    (with-temp-buffer
      (call-process "sh" nil t nil "-c"
                    (concat "printf 'SPECPW\\nSPECPW\\n' | keepassxc-cli db-create -q "
                            (shell-quote-argument db) " --set-password"))
      (call-process "sh" nil t nil "-c"
                    (concat "printf 'SPECPW\\n' | keepassxc-cli add -q "
                            (shell-quote-argument db)
                            " spec -u me@spec --url spec.example")))
    (add-hook 'auth-source-backend-parser-functions
              #'keepass-auth-source-backend-parser)
    (unwind-protect
        (let ((password-cache-expiry nil)
              (auth-sources (list (keepass-make-db-spec :file db :password "SPECPW"))))
          (let ((res (auth-source-search :host "spec.example" :user "me@spec"
                                         :port "465" :require '(:secret))))
            (should (= 1 (length res)))
            (should (equal "me@spec" (plist-get (car res) :user)))
            (should (stringp (funcall (plist-get (car res) :secret))))))
      (ignore-errors (delete-file db)))))

(provide 'keepass-auth-source-test)
;;; keepass-auth-source-test.el ends here