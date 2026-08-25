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
  "Host+user+port must select exactly the target, rejecting all decoys."
  (skip-unless keepass-auth-source-test-program)
  (let ((db (keepass-auth-source-test-make-db)))
    (unwind-protect
        (let ((res (keepass-auth-source-test-search
                    db '(:host "x.example.com" :user "alice" :port 443))))
          (should (= 1 (length res)))
          (should (string-equal "target" (plist-get (car res) :title))))
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
          ;; Host + port: URL must contain host:port.
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :port 443)
           "target" "wrong-user")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :port 465)
           "wrong-port")
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
           "target")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "bob" :port 443)
           "wrong-user")
          (keepass-auth-source-test-assert
           db '(:host "x.example.com" :user "alice" :port 465)
           "wrong-port")
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
    (should (equal "url:h.example.com:443"
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

(provide 'keepass-auth-source-test)
;;; keepass-auth-source-test.el ends here