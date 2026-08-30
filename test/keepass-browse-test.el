;;; keepass-browse-test.el --- Tests for keepass-browse -*- lexical-binding: t -*-

;;; Commentary:

;; Run with:
;;   emacs -Q --batch -l ert -l keepass-browse.el \
;;         -l keepass-browse-test.el -f ert-run-tests-batch-and-exit
;;
;; Integration tests build a throwaway KeePassXC database via
;; `keepassxc-cli' and are skipped when the binary is absent.

;;; Code:
(require 'ert)
(require 'keepass-browse)

(defcustom keepass-browse-test-program
  (or (executable-find "keepassxc-cli") "")
  "keepassxc-cli executable for the optional integration test."
  :type 'string
  :group 'keepass-browse)

(defun keepass-browse-test-run (cmd)
  "Run shell command CMD via /bin/sh, returning its stdout."
  (with-temp-buffer
    (call-process "sh" nil t nil "-c" cmd)
    (buffer-string)))

(defun keepass-browse-test-add (cli db title user url)
  "Add entry TITLE/USER/URL to DB via keepassxc-cli CLI."
  (keepass-browse-test-run
   (format "printf 'PASS\\n' | %s add -q %s %s -u %s -g --url %s"
           cli (shell-quote-argument db) (shell-quote-argument title)
           (shell-quote-argument user) (shell-quote-argument url))))

(defun keepass-browse-test-make-db ()
  "Create a fresh throwaway kdbx with a root entry and a group entry."
  (let* ((dir (make-temp-file "kb-test-" t))
         (db (expand-file-name "t.kdbx" dir))
         (cli (shell-quote-argument keepass-browse-test-program))
         (qdb (shell-quote-argument db)))
    (keepass-browse-test-run
     (format "printf 'PASS\\nPASS\\n' | %s db-create -q %s --set-password" cli qdb))
    (keepass-browse-test-run
     (format "printf 'PASS\\n' | %s mkdir -q %s Work" cli qdb))
    (keepass-browse-test-add cli qdb "email" "me@x.com" "smtp.x.com:465")
    (keepass-browse-test-add cli qdb "Work/github" "cbit" "https://github.com")
    db))

(defmacro keepass-browse-test-with-db (&rest body)
  "Bind a fresh test DB and run BODY with it set as the active database."
  `(when keepass-browse-test-program
     (let* ((db (keepass-browse-test-make-db))
            (keepass-browse-database (keepass-make-db-spec :file db))
            (keepass-browse-cache-expiry nil)
            (password-cache-expiry nil))
       (password-cache-add db "PASS")
       (unwind-protect
           (progn ,@body)
         (delete-file db)))))

;;;; Non-subprocess unit tests

(ert-deftest keepass-browse-parse-show ()
  "`parse-show' picks out the standard fields."
  (let ((entry (keepass-browse--parse-show
                "Title: t\nUserName: u@x.com\nPassword: secret\nURL: http://x\nNotes: n\nUuid: {x}\n")))
    (should (equal "t" (cdr (assoc "Title" entry))))
    (should (equal "u@x.com" (cdr (assoc "UserName" entry))))
    (should (equal "secret" (cdr (assoc "Password" entry))))
    (should (equal "http://x" (cdr (assoc "URL" entry))))
    (should (equal "n" (cdr (assoc "Notes" entry))))
    ;; Non-standard fields are ignored.
    (should-not (assoc "Uuid" entry))))

(ert-deftest keepass-browse-parse-entry-buffer ()
  "`parse-entry' reads Field: value lines, including the optional Group."
  (with-temp-buffer
    (insert "Group: /g/\nTitle: /g/t\nUserName: bob\nPassword: pw\nURL: http://x\n")
    (let ((entry (keepass-browse--parse-entry)))
      (should (equal "/g/" (cdr (assoc "Group" entry))))
      (should (equal "/g/t" (cdr (assoc "Title" entry))))
      (should (equal "bob" (cdr (assoc "UserName" entry))))
      (should (equal "pw" (cdr (assoc "Password" entry)))))))

(ert-deftest keepass-browse-parse-entry-group-absent ()
  "A buffer without a Group line still parses; Group is optional."
  (with-temp-buffer
    (insert "Title: t\nUserName: u\nPassword: p\nURL: http://x\n")
    (let ((entry (keepass-browse--parse-entry)))
      (should-not (assoc "Group" entry))
      (should (equal "t" (cdr (assoc "Title" entry)))))))

(ert-deftest keepass-browse-edit-includes-group-line ()
  "`keepass-browse-edit' templates the Group line above Title."
  (let ((entry '(("Title" . "t") ("UserName" . "u") ("Password" . "p")
                 ("URL" . "x") ("Notes" . "n")))
        (box (list nil)))
    ;; Stub entry-get and entry-open to capture the template.
    (cl-letf (((symbol-function 'keepass-browse--entry-get) (lambda (_) entry))
              ((symbol-function 'keepass-browse--entry-open)
               (lambda (_name _action _path template)
                 (setcar box template))))
      (keepass-browse-edit "/g/t"))
    (should (string-match-p "^Group: /g/\n" (car box)))
    (should (string-match-p "\nTitle: t\n" (car box)))))

(ert-deftest keepass-browse-parse-entry-ignores-hint-line ()
  "The `;; Keys:' hint line is not parsed into an entry field."
  (with-temp-buffer
    (insert ";; Keys: C-c C-c commit | C-c C-p select group | C-c C-r regenerate\n"
            ";; C-c C-k cancel\n"
            "Group: /Work/\nTitle: t\nUserName: u\nPassword: p\n")
    (let ((entry (keepass-browse--parse-entry)))
      (should-not (assoc "Keys" entry))
      (should (equal "/Work/" (cdr (assoc "Group" entry))))
      (should (equal "t" (cdr (assoc "Title" entry))))
      (should (equal "u" (cdr (assoc "UserName" entry)))))))

(ert-deftest keepass-browse-spec-label ()
  "A database spec's label is its :name, defaulting to the file name."
  (should (equal "mydb" (keepass-browse--spec-label '(:name "mydb" :file "/p/db.kdbx"))))
  (should (equal "db.kdbx" (keepass-browse--spec-label '(:file "/path/db.kdbx"))))
  (should (equal "db.kdbx" (keepass-browse--spec-label "db.kdbx"))))

(ert-deftest keepass-browse-select-database-by-label ()
  "Selecting a database completes over labels and sets a plist spec."
  (let* ((keepass-browse-databases
          '((:name "work" :file "/a/work.kdbx")
            (:file "/b/personal.kdbx")))
         (keepass-browse-database nil))
    (let ((result
           (cl-letf (((symbol-function 'completing-read)
                      (lambda (_prompt coll &rest _) (car coll))))
             (keepass-browse-select-database))))
      ;; The first label is "work"; the matching entry is the whole plist.
      (should (equal '(:name "work" :file "/a/work.kdbx") result))
      (should (equal result keepass-browse-database)))))

(ert-deftest keepass-browse-add-databases-to-auth-sources-strips-name ()
  "Adding the databases to auth-sources drops the browse-only :name."
  (let* ((keepass-browse-databases
          '((:name "work" :file "/a/work.kdbx" :keyfile "/a/k")))
         (auth-sources nil))
    (keepass-browse-add-databases-to-auth-sources)
    (should (equal 1 (length auth-sources)))
    (should (equal "/a/work.kdbx" (keepass-db-spec-file (car auth-sources))))
    (should-not (keepass-db-spec-name (car auth-sources)))
    (should (equal "/a/k" (keepass-db-spec-keyfile (car auth-sources))))))

(ert-deftest keepass-browse-entry-mode-map-bindings ()
  "The entry-mode keymap binds group-choosing to `C-c C-p'.
Not `C-c C-g': a C-g after a prefix key is treated by Emacs as \"cancel
the prefix\" and can never be dispatched to a binding."
  (should (eq #'keepass-browse--entry-choose-group
              (lookup-key keepass-browse-entry-mode-map (kbd "C-c C-p"))))
  (should (eq #'keepass-browse--entry-commit
              (lookup-key keepass-browse-entry-mode-map (kbd "C-c C-c"))))
  ;; Guard against reintroducing the C-g trap.
  (should-not (lookup-key keepass-browse-entry-mode-map (kbd "C-c C-g"))))

(ert-deftest keepass-browse-entry-open-unmodified ()
  "A freshly opened entry buffer is not marked modified until edited."
  (let ((buf (cl-letf (((symbol-function 'switch-to-buffer) #'ignore))
               (keepass-browse--entry-open "*kb-open-test*" "add" nil))))
    (should-not (buffer-modified-p buf))
    (with-current-buffer buf
      (insert "x"))
    (should (buffer-modified-p buf))
    (kill-buffer buf)))

(ert-deftest keepass-browse-view-shows-group ()
  "The view buffer shows a Group line (the entry's folder) above Title."
  (with-temp-buffer
    (setq-local keepass-browse-view-path "/Internet/Google/mail")
    (cl-letf (((symbol-function 'keepass-browse--entry-get)
               (lambda (_) '(("Title" . "mail") ("UserName" . "u")
                             ("Password" . "p") ("URL" . "x")
                             ("Notes" . "n")))))
      (keepass-browse-view-update nil))
    (goto-char (point-min))
    (should (string-match-p "^Group\\s-+/Internet/Google/\n" (buffer-string)))
    (should (string-match-p "^Group\\s-+.+\nTitle\\s-+mail\n" (buffer-string)))))

(ert-deftest keepass-browse-generate-args ()
  "The option labels expand into full keepassxc-cli commands.
The `:length' placeholder is replaced by the requested length as a string
(since `call-process' takes only strings)."
  (should (equal '("generate" "--upper" "--length" "16")
                 (keepass-browse--generate-args "upper case" 16)))
  (should (equal '("generate" "--lower" "--upper" "--numeric" "--length" "12")
                 (keepass-browse--generate-args "with numeric" 12)))
  ;; The all-printable set is the full !-~ range via --custom.
  (let ((ascii (keepass-browse--generate-args "all printable (!-~)" 8)))
    (should (equal '("generate" "--custom") (seq-take ascii 2)))
    (let* ((set (nth 2 ascii)))
      (should (= 94 (length set)))                 ; ! (0x21) .. ~ (0x7e)
      (should (string-match-p "!" set))
      (should (string-match-p "~" set))
      (should-not (string-match-p " " set))))      ; 0x20 is outside the range
  ;; The diceware option uses --words, not --length.
  (should (equal '("diceware" "--words" "6")
                 (keepass-browse--generate-args "passphrase" 6)))
  ;; A label not in the alist is an error.
  (should-error (keepass-browse--generate-args "bogus" 8)))

(ert-deftest keepass-browse-generate-failure-message ()
  "The keepassxc 'Invalid password generator' error advises a longer length."
  (let ((msg (keepass-browse--generate-failure-message
              "with special"
              "Invalid password generator after applying all options.")))
    (should (string-match-p "longer length" msg))
    (should (string-match-p "with special" msg)))
  ;; Other failures keep a generic message.
  (should (string-match-p "failed"
                          (keepass-browse--generate-failure-message
                           "with special" "some other error"))))

(ert-deftest keepass-browse-read-charset-remembers ()
  "`read-charset' offers the last choice as default, else the first option."
  (let ((keepass-browse--last-generated-charset "mixed case"))
    (cl-letf (((symbol-function 'completing-read)
               (lambda (_p _c _x _r _h _i def)
                 (unless (string= def "mixed case")
                   (ert-fail (format "expected default label, got %S" def)))
                 "upper case")))
      (should (equal "upper case" (keepass-browse--read-charset)))
      (should (equal "upper case"
                     keepass-browse--last-generated-charset))))
  ;; Nothing chosen yet -> the first entry's label is the default.
  (let ((keepass-browse--last-generated-charset nil))
    (cl-letf (((symbol-function 'completing-read)
               (lambda (_p _c _x _r _h _i def)
                 (unless (string= def "all printable (!-~)")
                   (ert-fail (format "expected default label, got %S" def)))
                 def)))
      (should (equal "all printable (!-~)"
                     (keepass-browse--read-charset))))))

(ert-deftest keepass-browse-parse-entry-multiline-notes ()
  "Notes extends to the end of the buffer, preserving multiple lines."
  (with-temp-buffer
    (insert "Title: t\nUserName: u\nPassword: p\nURL: http://x\n"
            "Notes: first line\nsecond line\n\nthird line\n")
    (let ((entry (keepass-browse--parse-entry)))
      (should (equal "first line\nsecond line\n\nthird line"
                     (cdr (assoc "Notes" entry))))
      ;; Other fields still parsed correctly.
      (should (equal "t" (cdr (assoc "Title" entry))))
      (should (equal "u" (cdr (assoc "UserName" entry))))
      (should (equal "p" (cdr (assoc "Password" entry)))))))

(ert-deftest keepass-browse-format-candidate-tags-path ()
  "`format-candidate' tags the line with the entry path."
  (let* ((path "/g/t")
         (entry '(("Title" . "t") ("UserName" . "u") ("URL" . "http://x")))
         (keepass-browse-fields '("Title" "UserName" "URL"))
         (cand (keepass-browse--format-candidate path entry)))
    (should (equal path (keepass-browse--path-of cand)))))

(ert-deftest keepass-browse-valid-field-p ()
  "Only the five standard fields are recognised."
  (should (keepass-browse--valid-field-p "Title"))
  (should (keepass-browse--valid-field-p "Notes"))
  (should-not (keepass-browse--valid-field-p "Uuid"))
  (should-not (keepass-browse--valid-field-p "host")))

;;;; Group navigation helpers

(ert-deftest keepass-browse-entry-directory-basename ()
  "`entry-directory'/'entry-basename' split KeePass paths without TRAMP.
A title like \"Apple:foo:bar\" gives path \"/Apple:foo:bar\", which any
`file-name-*' function would hand to TRAMP (\"Method `Apple' is not
known\").  The pure string helpers must never touch those."
  (should (equal "/" (keepass-browse--entry-directory "/b")))
  (should (equal "/a/" (keepass-browse--entry-directory "/a/b")))
  (should (equal "/" (keepass-browse--entry-directory "/")))
  (should (equal "" (keepass-browse--entry-directory "")))
  (should (equal "/" (keepass-browse--entry-directory "/Apple:foo:bar")))
  (should (equal "Apple:foo:bar" (keepass-browse--entry-basename "/Apple:foo:bar")))
  (should (equal "b" (keepass-browse--entry-basename "/a/b")))
  (should (equal "" (keepass-browse--entry-basename "/"))))

(ert-deftest keepass-browse-group-contents-tramp-safe ()
  "`group-contents' handles entry titles that look like TRAMP remote names."
  (let ((entries '(("/Apple:foo:bar" . nil)
                   ("/Internet/Apple:foo:bar" . nil)
                   ("/Work/g" . nil))))
    (pcase-let* ((`(,groups . ,subs)
                  (keepass-browse--group-contents entries "/")))
      ;; '/Apple:foo:bar' is a direct root entry, not a spurious subgroup.
      (should (equal '("/Internet/" "/Work/") groups))
      (should (equal '("/Apple:foo:bar") (mapcar #'car subs))))))

(ert-deftest keepass-browse-group-contents ()
  "`group-contents' splits entries into child groups and child entries."
  (let ((entries '(("/Internet/Google/a" . nil)
                   ("/Internet/Google/b" . nil)
                   ("/Internet/Yahoo/c" . nil)
                   ("/Work/g" . nil)
                   ("/Root" . nil))))
    ;; Root: subgroups /Internet/ + /Work/, direct entry /Root.
    (pcase-let* ((`(,groups . ,subs)
                  (keepass-browse--group-contents entries "/")))
      (should (equal '("/Internet/" "/Work/") groups))
      (should (equal '("/Root") (mapcar #'car subs))))
    ;; /Internet: subgroups /Internet/Google/ + /Internet/Yahoo/, no direct
    ;; entries.
    (pcase-let* ((`(,groups . ,subs)
                  (keepass-browse--group-contents entries "/Internet/")))
      (should (equal '("/Internet/Google/" "/Internet/Yahoo/") groups))
      (should (null subs)))
    ;; Deepest group: two direct entries, no subgroups; group name without a
    ;; trailing slash is normalized the same way.
    (pcase-let* ((`(,groups . ,subs)
                  (keepass-browse--group-contents entries "/Internet/Google")))
      (should (null groups))
      (should (equal '("/Internet/Google/a" "/Internet/Google/b")
                     (mapcar #'car subs))))))

(ert-deftest keepass-browse-group-choose-drills-down ()
  "`group-choose' descends through subgroups to reach an entry, recursing."
  (let* ((entries '(("/Internet/Google/a" . (("Title" . "a")))))
         (queue (list (keepass-browse--format-group "/Internet/")
                      (keepass-browse--format-candidate
                       "/Internet/Google/a" (cdar entries)))))
    (cl-letf (((symbol-function 'consult--read)
               (lambda (&rest _) (pop queue))))
      (should (equal "/Internet/Google/a"
                     (keepass-browse--group-choose entries "/"))))
    (should (null queue))))

(ert-deftest keepass-browse-group-command-picks-entry ()
  "`keepass-browse-group' drills down and runs the default action on the entry."
  (let* ((entries '(("/A/b" . nil)))
         (queue (list (keepass-browse--format-group "/A/")
                      (keepass-browse--format-candidate "/A/b" nil)))
         (keepass-browse-database (keepass-make-db-spec :file "db.kdbx"))
         (box (list nil))
         (keepass-browse-default-action (lambda (p) (setcar box p))))
    (cl-letf (((symbol-function 'keepass-browse--load-entries)
               (lambda () entries))
              ((symbol-function 'consult--read)
               (lambda (&rest _) (pop queue))))
      (should (equal "/A/b" (keepass-browse-group))))
    (should (equal "/A/b" (car box)))))

(ert-deftest keepass-browse-format-group-tags-path ()
  "`format-group' shows the bare segment plus slash, tagged with the full path."
  (let ((cand (keepass-browse--format-group "/Internet/")))
    (should (equal "Internet/" cand))
    (should (equal "/Internet/" (keepass-browse--path-of cand))))
  ;; A nested group keeps its full path in the tag.
  (should (equal "/Internet/Google/"
                 (keepass-browse--path-of
                  (keepass-browse--format-group "/Internet/Google/")))))

;;;; Integration tests (need keepassxc-cli)

(ert-deftest keepass-browse-list-paths ()
  "Entry and group paths are listed with normalized leading slashes."
  (keepass-browse-test-with-db
    (let ((paths (keepass-browse--entry-paths))
          (groups (keepass-browse--group-paths)))
      (should (member "/email" paths))
      (should (member "/Work/github" paths))
      (should (member "/Work/" groups)))))

(ert-deftest keepass-browse-group-contents-real ()
  "`group-contents' on a real database walks the group tree."
  (keepass-browse-test-with-db
    (let ((entries (keepass-browse--load-entries)))
      ;; Root: the /Work group plus the top-level /email entry.
      (pcase-let* ((`(,groups . ,subs)
                    (keepass-browse--group-contents entries "/")))
        (should (equal '("/Work/") groups))
        (should (equal '("/email") (mapcar #'car subs))))
      ;; /Work: only the nested github entry.
      (pcase-let* ((`(,groups . ,subs)
                    (keepass-browse--group-contents entries "/Work/")))
        (should (null groups))
        (should (equal '("/Work/github") (mapcar #'car subs)))))))

(ert-deftest keepass-browse-entry-get-fields ()
  "`entry-get' returns the real fields for an entry."
  (keepass-browse-test-with-db
    (let ((entry (keepass-browse--entry-get "/email")))
      (should (equal "me@x.com" (cdr (assoc "UserName" entry))))
      (should (equal "smtp.x.com:465" (cdr (assoc "URL" entry)))))))

(ert-deftest keepass-browse-copy-password-to-kill-ring ()
  "Copying puts the real password on the kill ring."
  (keepass-browse-test-with-db
    (keepass-browse-copy-password "/email")
    (let ((entry (keepass-browse--entry-get "/email")))
      (should (equal (cdr (assoc "Password" entry)) (car kill-ring))))))

(ert-deftest keepass-browse-candidates-tagged ()
  "Candidates carry kb-path so Embark can act on the entry under point."
  (keepass-browse-test-with-db
    (let* ((keepass-browse-fields '("Title" "UserName" "URL"))
           (cands (keepass-browse--candidates)))
      (should (= 2 (length cands)))
      (dolist (c cands)
        (should (keepass-browse--path-of c))))))

(ert-deftest keepass-browse-entry-commit-adds ()
  "Committing an add buffer creates the entry in the database."
  (keepass-browse-test-with-db
    (with-temp-buffer
      (insert "Title: /Work/new2\nUserName: carol\nPassword: pw2\nURL: http://x\n")
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action "add")
      (setq-local keepass-browse--entry-original nil)
      (keepass-browse--entry-commit))
    (let ((entry (keepass-browse--entry-get "/Work/new2")))
      (should (equal "carol" (cdr (assoc "UserName" entry)))))))

(ert-deftest keepass-browse-entry-commit-edits ()
  "Committing an edit buffer updates the entry's fields."
  (keepass-browse-test-with-db
    (with-temp-buffer
      (insert "Title: email\nUserName: newuser\nPassword: newpw\nURL: smtp.x.com:465\n")
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action "edit")
      (setq-local keepass-browse--entry-original "/email")
      (keepass-browse--entry-commit))
    (let ((entry (keepass-browse--entry-get "/email")))
      (should (equal "newuser" (cdr (assoc "UserName" entry))))
      (should (equal "newpw" (cdr (assoc "Password" entry)))))))

(ert-deftest keepass-browse-entry-commit-rename-keeps-one ()
  "Renaming via edit -t updates the title in place, keeping one entry."
  (keepass-browse-test-with-db
    (with-temp-buffer
      (insert "Title: github-new\nUserName: cbit\nPassword: x\nURL: https://github.com\n")
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action "edit")
      (setq-local keepass-browse--entry-original "/Work/github")
      (keepass-browse--entry-commit))
    (let ((paths (keepass-browse--entry-paths)))
      (should (member "/Work/github-new" paths))
      (should-not (member "/Work/github" paths)))))

(ert-deftest keepass-browse-entry-commit-moves-group ()
  "Changing the Group field moves the entry into another group (mv).
The move must not delete+re-add: the entry survives in its new group and
the old path is gone."
  (keepass-browse-test-with-db
    (with-temp-buffer
      (insert "Group: /Work/\nTitle: email\nUserName: me@x.com\nPassword: PASS\nURL: smtp.x.com:465\n")
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action "edit")
      (setq-local keepass-browse--entry-original "/email")
      (keepass-browse--entry-commit))
    (let ((paths (keepass-browse--entry-paths)))
      (should (member "/Work/email" paths))
      (should-not (member "/email" paths)))
    ;; The entry's fields survive the move.
    (let ((entry (keepass-browse--entry-get "/Work/email")))
      (should (equal "me@x.com" (cdr (assoc "UserName" entry)))))))

(ert-deftest keepass-browse-delete-removes ()
  "Deleting an entry removes it from the list."
  (keepass-browse-test-with-db
    (keepass-browse--delete-entry "/email")
    (let ((paths (keepass-browse--entry-paths)))
      (should-not (member "/email" paths)))))

(ert-deftest keepass-browse-wrong-password-errors ()
  "A wrong master password raises an error, not a silent empty result."
  (keepass-browse-test-with-db
    ;; The password cache is keyed by the database *path*, so override the
    ;; good entry with a wrong password under that key.
    (let ((password-cache-expiry nil))
      (password-cache-add (keepass-browse--database-path) "WRONG"))
    (should-error (keepass-browse--load-entries) :type 'error)))

(ert-deftest keepass-browse-copy-totp-absent ()
  "Copying TOTP for an entry without one is a clean user-error, not a crash."
  (keepass-browse-test-with-db
    (should-error (keepass-browse-copy-totp "/email") :type 'user-error)))

(provide 'keepass-browse-test)
;;; keepass-browse-test.el ends here