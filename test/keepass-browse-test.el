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
            (keepass-browse-database db)
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
  "`parse-entry' reads Field: value lines."
  (with-temp-buffer
    (insert "Title: /g/t\nUserName: bob\nPassword: pw\nURL: http://x\n")
    (let ((entry (keepass-browse--parse-entry)))
      (should (equal "/g/t" (cdr (assoc "Title" entry))))
      (should (equal "bob" (cdr (assoc "UserName" entry))))
      (should (equal "pw" (cdr (assoc "Password" entry)))))))

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

;;;; Integration tests (need keepassxc-cli)

(ert-deftest keepass-browse-list-paths ()
  "Entry and group paths are listed with normalized leading slashes."
  (keepass-browse-test-with-db
    (let ((paths (keepass-browse--entry-paths))
          (groups (keepass-browse--group-paths)))
      (should (member "/email" paths))
      (should (member "/Work/github" paths))
      (should (member "/Work/" groups)))))

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

(ert-deftest keepass-browse-delete-removes ()
  "Deleting an entry removes it from the list."
  (keepass-browse-test-with-db
    (keepass-browse--delete-entry "/email")
    (let ((paths (keepass-browse--entry-paths)))
      (should-not (member "/email" paths)))))

(ert-deftest keepass-browse-wrong-password-errors ()
  "A wrong master password raises an error, not a silent empty result."
  (keepass-browse-test-with-db
    (let ((password-cache-expiry nil))
      (password-cache-add keepass-browse-database "WRONG"))
    (should-error (keepass-browse--load-entries) :type 'error)))

(ert-deftest keepass-browse-copy-totp-absent ()
  "Copying TOTP for an entry without one is a clean user-error, not a crash."
  (keepass-browse-test-with-db
    (should-error (keepass-browse-copy-totp "/email") :type 'user-error)))

(provide 'keepass-browse-test)
;;; keepass-browse-test.el ends here