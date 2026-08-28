;;; keepass-browse.el --- Browse and edit KeePass entries (consult + embark) -*- lexical-binding: t; -*-

;; Copyright (C) 2026 Chris Bitmead

;; Author: Chris Bitmead <xpusostomos@gmail.com>
;; Maintainer: Chris Bitmead <xpusostomos@gmail.com>
;; Assisted-by: Claude
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1") (consult "0.1") (embark "0.1") (embark-consult "0.1"))
;; Keywords: comm, tools, passwords, keepassxc
;; URL: https://github.com/xpusostomos/keepass-auth-source
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; A richer front-end for KeePass databases on top of `keepassxc-cli',
;; picked with `consult' (works with `vertico') and acted on with `embark'
;; (`embark-consult' provides preview and `embark-act' provides the action
;; menu for the entry under point).
;;
;; This is deliberately separate from `keepass-auth-source', which feeds
;; credentials to `auth-source'.  This package is for *using and editing* a
;; database interactively: list entries with the fields you care about,
;; select one, copy/insert its username, password, URL, notes or TOTP, and
;; view, add, clone, edit or delete entries.
;;
;; Only the five standard KeePass fields (Title, UserName, Password, URL,
;; Notes) plus TOTP are handled, matching what `keepassxc-cli' reliably
;; exposes.  Custom attributes are not yet supported (keepassxc-cli cannot
;; yet create them).
;;
;; Two entry points:
;;   - `keepass-browse'            open the listing buffer (Embark works here)
;;   - `keepass-browse-select'     pick through the minibuffer (consult/vertico)
;;
;; The same actions are available from the Embark action map
;; `keepass-browse-action-map' and as interactive commands.

;;; Code:

(require 'cl-lib)
(require 'consult)
(require 'embark)
(require 'embark-consult)
(require 'password-cache)
(require 'subr-x)

(defgroup keepass-browse nil
  "Browse and edit KeePass entries with consult and embark."
  :group 'tools
  :prefix "keepass-browse-")

(defcustom keepass-browse-binary "keepassxc-cli"
  "The keepassxc-cli executable (or path to it)."
  :type 'string
  :group 'keepass-browse)

(defcustom keepass-browse-database-file nil
  "Path of the KeePass database file to operate on."
  :type '(choice (const :tag "None" nil) file)
  :group 'keepass-browse)

(defcustom keepass-browse-cache-expiry 7200
  "How many seconds to cache the database master password.  Nil disables."
  :type '(choice (const :tag "Never" nil)
                 (const :tag "All Day" 86400)
                 (const :tag "2 Hours" 7200)
                 (const :tag "30 Minutes" 1800)
                 (integer :tag "Seconds"))
  :group 'keepass-browse)

(defcustom keepass-browse-fields '("Title" "UserName" "URL")
  "Fields shown in each candidate line, in order.
Each must be a standard KeePass field name: \"Title\", \"UserName\",
\"Password\", \"URL\" or \"Notes\"."
  :type '(repeat (choice (const "Title") (const "UserName")
                         (const "Password") (const "URL") (const "Notes")))
  :group 'keepass-browse)

(defcustom keepass-browse-clear-clipboard-seconds 0
  "If non-zero, clear the clipboard this many seconds after a copy."
  :type 'integer
  :group 'keepass-browse)

(defcustom keepass-browse-verbose nil
  "If non-nil, log keepassxc-cli invocations to *Messages*."
  :type 'boolean
  :group 'keepass-browse)

(defcustom keepass-browse-default-action #'keepass-browse-view
  "Function run on the selected entry when `keepass-browse' returns.
Called with the entry path.  The default, `keepass-browse-view', shows the
entry; it can be changed to e.g. `keepass-browse-copy-password' to copy the
password directly on RET."
  :type '(choice (function :tag "View entry" keepass-browse-view)
                 (function :tag "Copy password" keepass-browse-copy-password)
                 (function :tag "None (just return the path)" ignore))
  :group 'keepass-browse)

;;; Internal state

(defvar keepass-browse--entries nil
  "Alist of (PATH . FIELDS) for the current database.
FIELDS is an alist of \"Field\" . value parsed from `show'.")

(defvar keepass-browse--last-killed nil
  "The last string copied, so clearing only happens if it is unchanged.")

(defvar keepass-browse--clear-timer nil
  "Timer to clear the clipboard.")

(defvar keepass-browse-history nil
  "History for `keepass-browse-select'.")

;;; Subprocess plumbing

(defun keepass-browse--executable ()
  "Return the keepassxc-cli path, else its configured name."
  (or (executable-find keepass-browse-binary)
      keepass-browse-binary))

(defun keepass-browse--read-password ()
  "Return the database master password, prompting and caching it."
  (let* ((key keepass-browse-database-file)
         (prompt (format "Master password for %s: " key))
         (password-cache-expiry keepass-browse-cache-expiry)
         (password (cond
                    ((password-read-from-cache key))
                    ((password-read prompt key)))))
    (password-cache-add key password)
    password))

(defun keepass-browse--run (password &rest args)
  "Run keepassxc-cli ARGS feeding PASSWORD on standard input.
Returns (OUTPUT . EXIT)."
  (let* ((prog (keepass-browse--executable))
         (out (generate-new-buffer " *keepass-browse-out*")))
    (unwind-protect
        (with-temp-buffer
          (when keepass-browse-verbose
            (let ((display (mapconcat #'shell-quote-argument args " ")))
              (message "keepassxc-cli %s" display)))
          (insert (or password "") "\n")
          (let ((exit (apply #'call-process-region
                             (point-min) (point-max)
                             prog t (list out) nil args)))
            (cons (with-current-buffer out (buffer-string)) exit)))
      (kill-buffer out))))

(defun keepass-browse--run-stdin (stdin &rest args)
  "Run keepassxc-cli ARGS feeding STDIN (a string) on standard input.
Returns (OUTPUT . EXIT)."
  (let* ((prog (keepass-browse--executable))
         (out (generate-new-buffer " *keepass-browse-out*")))
    (unwind-protect
        (with-temp-buffer
          (when keepass-browse-verbose
            (message "keepassxc-cli %s" (mapconcat #'shell-quote-argument args " ")))
          (insert stdin)
          (let ((exit (apply #'call-process-region
                             (point-min) (point-max)
                             prog t (list out) nil args)))
            (cons (with-current-buffer out (buffer-string)) exit)))
      (kill-buffer out))))

(defun keepass-browse--error (output)
  "Signal an error describing a failed keepassxc-cli run (OUTPUT)."
  (let ((msg (string-trim output)))
    (cond
     ((string-match-p "Invalid credentials were provided" msg)
      (password-cache-remove keepass-browse-database-file)
      (user-error "Incorrect master password"))
     (t (user-error "keepassxc-cli failed: %s"
                    (if (> (length msg) 0) msg "unknown error"))))))

(defun keepass-browse--require-db ()
  "Signal an error unless a database file is configured."
  (unless keepass-browse-database-file
    (user-error "Set `keepass-browse-database-file' first")))

;;; Listing and parsing

(defun keepass-browse--valid-field-p (field)
  "Return non-nil if FIELD names a standard KeePass entry field."
  (member field '("Title" "UserName" "Password" "URL" "Notes")))

(defun keepass-browse--parse-show (output)
  "Parse `keepassxc-cli show' OUTPUT into an alist of FIELD . VALUE."
  (let ((result '()))
    (dolist (line (split-string output "\n"))
      (when (string-match "^\\([^:]+\\):[[:space:]]*\\(.*\\)$" line)
        (let ((key (string-trim (match-string 1 line))))
          (when (keepass-browse--valid-field-p key)
            (setq result (cons (cons key (string-trim (match-string 2 line)))
                               result))))))
    result))

(defun keepass-browse--entry-get (path)
  "Return the FIELD . VALUE alist for the entry at PATH.
PATH may be the clean path or the padded display string an action receives
from Embark; it is resolved through `keepass-browse--path-of' first, so the
lookup is robust.  Loads the cache if needed, so lookups never run a fragile
one-off `show' (which could prompt or fail in the minibuffer/Embark)."
  (keepass-browse--load-entries)
  ;; Try the direct path first; only resolve a padded display string (as
  ;; Embark may hand over) when the direct lookup fails.
  (unless (assoc path keepass-browse--entries)
    (setq path (keepass-browse--path-of path)))
  (let ((cached (assoc path keepass-browse--entries)))
    (if cached
        (cdr cached)
      (user-error "No entry for path %s" path))))

(defun keepass-browse--field (entry field)
  "Return the value of FIELD in parsed alist ENTRY, or \"\"."
  (or (cdr (assoc field entry)) ""))

(defun keepass-browse--entry-paths ()
  "Return the list of entry paths (excluding group rows) in the database.
Derives from the cached export when loaded, else a single `ls' call."
  (if keepass-browse--entries
      (mapcar #'car keepass-browse--entries)
    (let ((run (keepass-browse--run (keepass-browse--read-password)
                                    "ls" "-q" "-R" "-f"
                                    keepass-browse-database-file)))
      (unless (eq (cdr run) 0)
        (keepass-browse--error (car run)))
      (let ((paths (seq-filter (lambda (s)
                                 (and (not (string-blank-p s))
                                      (not (string-suffix-p "/" s))))
                               (split-string (car run) "\n" t))))
        (mapcar (lambda (p) (if (string-prefix-p "/" p) p (concat "/" p)))
                paths)))))

(defun keepass-browse--group-paths ()
  "Return the list of group paths (each ending in /) in the database.
Derives from the cached export when loaded, else a single `ls' call."
  (if keepass-browse--entries
      (let (groups)
        (dolist (e keepass-browse--entries (nreverse groups))
          (let ((dir (file-name-directory (car e))))
            (when (and dir (not (member dir groups)))
              (push dir groups)))))
    (let ((run (keepass-browse--run (keepass-browse--read-password)
                                    "ls" "-q" "-R" "-f"
                                    keepass-browse-database-file)))
      (unless (eq (cdr run) 0)
        (keepass-browse--error (car run)))
      (mapcar (lambda (g) (if (string-prefix-p "/" g) g (concat "/" g)))
              (seq-filter (lambda (s) (string-suffix-p "/" s))
                          (split-string (car run) "\n" t))))))

(defun keepass-browse--export ()
  "Return the export XML node tree for the database.
Does ONE `keepassxc-cli export' call so the whole database (all entries,
all fields, passwords included) is fetched up front."
  (let ((run (keepass-browse--run (keepass-browse--read-password)
                                  "export" "-q" keepass-browse-database-file)))
    (unless (eq (cdr run) 0)
      (keepass-browse--error (car run)))
    (with-temp-buffer
      (insert (car run))
      (goto-char (point-min))
      (libxml-parse-xml-region (point-min) (point-max)))))

(defun keepass-browse--xml-children-tag (node tag)
  "Return the XML child nodes of NODE whose tag is TAG."
  (seq-filter (lambda (c) (and (consp c) (eq (car c) tag)))
              (cdr node)))

(defun keepass-browse--xml-tag-text (node tag)
  "Return the text of the first child of NODE with tag TAG, or nil.
libxml nodes are (TAG ATTRIBUTES &rest CHILDREN); the text is the first
string among the children, after the attributes slot."
  (let ((n (car (keepass-browse--xml-children-tag node tag))))
    (when n
      (catch 'found
        (dolist (el (cdr n))
          (when (stringp el) (throw 'found el)))
        ""))))

(defun keepass-browse--entry-fields (entry-node)
  "Return the FIELD . VALUE alist for export XML ENTRY-NODE."
  (let (fields)
    (dolist (str (keepass-browse--xml-children-tag entry-node 'String))
      (let ((key (keepass-browse--xml-tag-text str 'Key)))
        (when (keepass-browse--valid-field-p key)
          (setq fields (cons (cons key (keepass-browse--xml-tag-text str 'Value))
                             fields)))))
    (nreverse fields)))

(defun keepass-browse--collect (node group-path)
  "Return ((PATH . FIELDS) ...) for export XML NODE under GROUP-PATH.
The root group's own name is not part of entries' paths, but nested
groups' names are."
  (let ((acc '()))
    ;; Add each entry in this node.
    (dolist (entry (keepass-browse--xml-children-tag node 'Entry))
      (let* ((fields (keepass-browse--entry-fields entry))
             (title (cdr (assoc "Title" fields)))
             (path (concat group-path "/" title)))
        (setq acc (cons (cons path fields) acc))))
    ;; Recurse into child groups, extending the path with the group name.
    (dolist (subgroup (keepass-browse--xml-children-tag node 'Group))
      (let ((name (keepass-browse--xml-tag-text subgroup 'Name)))
        (setq acc (nconc (keepass-browse--collect
                          subgroup (concat group-path "/" name))
                         acc))))
    acc))

(defun keepass-browse--load-entries (&optional force)
  "Load all entries into `keepass-browse--entries' via ONE export call.
FORCE reloads.  Populates the cache as (PATH . FIELDS) pairs, so listing
and actions never invoke keepassxc-cli again for data already in memory."
  (when (or force (not keepass-browse--entries))
    (let* ((tree (keepass-browse--export))
           (root (car (keepass-browse--xml-children-tag tree 'Root)))
           (entries '()))
      (dolist (g (keepass-browse--xml-children-tag root 'Group))
        (setq entries (append entries (keepass-browse--collect g ""))))
      (setq keepass-browse--entries entries)))
  keepass-browse--entries)

;;; Candidates

(defun keepass-browse--format-candidate (path entry)
  "Return a display string for ENTRY at PATH, tagged with `kb-path'."
  (let ((str (mapconcat
              (lambda (f)
                (truncate-string-to-width (keepass-browse--field entry f)
                                          24 0 ?\s))
              keepass-browse-fields "\t")))
    (put-text-property 0 (length str) 'kb-path path str)
    str))

(defun keepass-browse--candidates ()
  "Return the candidate strings for the current database."
  (mapcar (lambda (c)
            (keepass-browse--format-candidate (car c) (cdr c)))
          (keepass-browse--load-entries)))

(defun keepass-browse--path-of (candidate)
  "Return the entry path stored in CANDIDATE, or nil.
Reads the path purely from CANDIDATE's `kb-path' text property.  The
display text is never parsed back for the path, so a title/username column
that merely looks similar cannot resolve to the wrong entry."
  (get-text-property 0 'kb-path candidate))

;;; Clip and copy

(defun keepass-browse--kill (value &optional msg)
  "Copy VALUE to the kill ring; optionally rearm the clear timer."
  (kill-new value)
  (when (> keepass-browse-clear-clipboard-seconds 0)
    (setq keepass-browse--last-killed value)
    (when keepass-browse--clear-timer
      (cancel-timer keepass-browse--clear-timer))
    (setq keepass-browse--clear-timer
          (run-with-timer keepass-browse-clear-clipboard-seconds nil
                          #'keepass-browse--clear-clipboard)))
  (message "%s" msg))

(defun keepass-browse--clear-clipboard ()
  "Clear the clipboard if it still holds the last value we copied."
  (when (and keepass-browse--last-killed
             (string-equal keepass-browse--last-killed (car kill-ring)))
    (kill-new ""))
  (setq keepass-browse--last-killed nil))

(defun keepass-browse--totp (path)
  "Return the current TOTP for the entry at PATH, or nil."
  (keepass-browse--load-entries)
  (unless (assoc path keepass-browse--entries)
    (setq path (keepass-browse--path-of path))) ; resolve padded Embark target
  (let ((run (keepass-browse--run (keepass-browse--read-password)
                                  "show" "-q" "--totp"
                                  keepass-browse-database-file path)))
    (when (eq (cdr run) 0)
      (string-trim (car run)))))

;;; Actions (each takes an entry path)

(defun keepass-browse-copy-username (path)
  "Copy the username of the entry at PATH."
  (interactive "sEntry path: ")
  (keepass-browse--kill (keepass-browse--field (keepass-browse--entry-get path) "UserName")
                        (format "Username of %s copied" path)))

(defun keepass-browse-copy-password (path)
  "Copy the password of the entry at PATH."
  (interactive "sEntry path: ")
  (keepass-browse--kill (keepass-browse--field (keepass-browse--entry-get path) "Password")
                        "Password copied"))

(defun keepass-browse-copy-url (path)
  "Copy the URL of the entry at PATH."
  (interactive "sEntry path: ")
  (keepass-browse--kill (keepass-browse--field (keepass-browse--entry-get path) "URL")
                        "URL copied"))

(defun keepass-browse-copy-notes (path)
  "Copy the notes of the entry at PATH."
  (interactive "sEntry path: ")
  (keepass-browse--kill (keepass-browse--field (keepass-browse--entry-get path) "Notes")
                        "Notes copied"))

(defun keepass-browse-copy-totp (path)
  "Copy the current TOTP of the entry at PATH."
  (interactive "sEntry path: ")
  (let ((totp (keepass-browse--totp path)))
    (if totp
        (keepass-browse--kill totp "TOTP copied")
      (user-error "No TOTP available for %s" path))))

(defun keepass-browse-insert-password (path)
  "Insert the password of the entry at PATH at point."
  (interactive "sEntry path: ")
  (insert (keepass-browse--field (keepass-browse--entry-get path) "Password")))

(defun keepass-browse-insert-username (path)
  "Insert the username of the entry at PATH at point."
  (interactive "sEntry path: ")
  (insert (keepass-browse--field (keepass-browse--entry-get path) "UserName")))

(defun keepass-browse-reveal-password (path)
  "Copy the password of the entry at PATH to the kill ring, revealing it."
  (interactive "sEntry path: ")
  (when (button-at (point)) (forward-button 1)) ; move off the revealed text
  (let ((entry (keepass-browse--entry-get path)))
    (keepass-browse--kill (keepass-browse--field entry "Password")
                          "Password copied to clipboard")))

(defvar keepass-browse-view-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "r") #'keepass-browse-view-reveal)
    (define-key map (kbd "u") #'keepass-browse-view-copy-username)
    (define-key map (kbd "p") #'keepass-browse-view-copy-password)
    (define-key map (kbd "e") #'keepass-browse-view-edit)
    (define-key map (kbd "q") #'quit-window)
    map)
  "Keymap for `keepass-browse-view-mode'.")

(define-derived-mode keepass-browse-view-mode special-mode "kb-view"
  "Major mode for viewing a KeePass entry.  Password is hidden until
\\[keepass-browse-view-reveal].")

(defvar-local keepass-browse-view-path nil
  "The entry path shown in `keepass-browse-view-mode'.")

(defun keepass-browse--view-menu ()
  "Return the bottom key-menu hint line for the view buffer."
  "\n\n[r] reveal password   [u] copy username   [p] copy password   [e] edit   [q] quit")

(defun keepass-browse-view-update (reveal)
  "Redraw the current view buffer, revealing the password when REVEAL."
  (let* ((entry (keepass-browse--entry-get keepass-browse-view-path))
         (pw (if reveal
                 (keepass-browse--field entry "Password")
               "[hidden - press r]")))
    (let ((inhibit-read-only t))
      (erase-buffer)
      (dolist (f '("Title" "UserName" "URL" "Notes"))
        (insert (format "%-10s %s\n" f (keepass-browse--field entry f))))
      (insert (format "%-10s %s\n" "Password" pw))
      (insert (keepass-browse--view-menu)))
    (goto-char (point-min)))
  (setq buffer-read-only t))

(defun keepass-browse-view-reveal ()
  "Reveal and copy the password of the entry in the view buffer."
  (interactive)
  (keepass-browse--kill (keepass-browse--field
                         (keepass-browse--entry-get keepass-browse-view-path)
                         "Password")
                        "Password copied to clipboard")
  (keepass-browse-view-update t))

(defun keepass-browse-view-copy-username ()
  "Copy the username of the entry in the view buffer."
  (interactive)
  (keepass-browse--kill (keepass-browse--field
                         (keepass-browse--entry-get keepass-browse-view-path)
                         "UserName")
                        "Username copied"))

(defun keepass-browse-view-copy-password ()
  "Copy the password of the entry in the view buffer."
  (interactive)
  (keepass-browse-reveal-password keepass-browse-view-path))

(defun keepass-browse-view-edit ()
  "Edit the entry shown in the view buffer."
  (interactive)
  (keepass-browse-edit keepass-browse-view-path))

(defun keepass-browse-view (path)
  "View the entry at PATH, hiding its password until a key reveals it."
  (interactive "sEntry path: ")
  (let ((buf (get-buffer-create "*keepass-browse-view*")))
    (with-current-buffer buf
      (keepass-browse-view-mode)
      (setq-local keepass-browse-view-path path)
      (keepass-browse-view-update nil))
    (switch-to-buffer buf)))


;;; Entry buffer (add / clone / edit)

(defvar-local keepass-browse--entry-action nil
  "For the entry buffer: the action being performed (add/edit).")
(defvar-local keepass-browse--entry-original nil
  "For the entry buffer: the original path being edited, if any.")

(defvar keepass-browse-entry-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-c C-c") #'keepass-browse--entry-commit)
    (define-key map (kbd "C-c C-k") #'kill-buffer-and-window)
    (define-key map (kbd "C-c C-r") #'keepass-browse--entry-regenerate)
    (define-key map (kbd "TAB") #'keepass-browse--entry-next-field)
    map)
  "Keymap for `keepass-browse-entry-mode'.")

(define-minor-mode keepass-browse-entry-mode
  "Minor mode for editing a KeePass entry as a text buffer."
  :lighter " Kb-Entry"
  :keymap keepass-browse-entry-mode-map)

(defun keepass-browse--entry-next-field ()
  "Move to the next \"Field: value\" line."
  (interactive)
  (if (re-search-forward "^[A-Za-z]+: " nil t)
      (goto-char (match-beginning 0))
    (goto-char (point-min))))

(defun keepass-browse--entry-regenerate ()
  "Insert a generated password into the Password line."
  (interactive)
  (when (re-search-forward "^Password: " nil t)
    (let ((len (read-number "Password length: " 16)))
      (let ((run (keepass-browse--run "" "generate" "-L" (format "%d" len))))
        (if (eq (cdr run) 0)
            (progn
              (delete-region (point) (line-end-position))
              (insert (string-trim (car run))))
          (message "could not generate password")))))
  (goto-char (point-min)))

(defun keepass-browse--entry-open (name action path &optional template)
  "Open an entry buffer NAME for ACTION on PATH (or nil to add).
TEMPLATE is the initial text; defaults to blank standard fields."
  (let ((buf (generate-new-buffer name)))
    (with-current-buffer buf
      (insert (or template
                  (mapconcat (lambda (f) (format "%s: " f))
                             '("Title" "UserName" "Password" "URL") "\n")))
      (goto-char (point-min))
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action action)
      (setq-local keepass-browse--entry-original path))
    (switch-to-buffer buf)))

(defun keepass-browse--parse-entry ()
  "Parse the current entry buffer into a FIELD . VALUE alist."
  (goto-char (point-min))
  (let ((result '()))
    (while (re-search-forward "^\\([A-Za-z]+\\): ?\\(.*\\)$" nil t)
      (let ((key (match-string 1)))
        (when (keepass-browse--valid-field-p key)
          (setq result (cons (cons key (match-string 2)) result)))))
    (nreverse result)))

;;; Add / edit / clone / delete

(defun keepass-browse-add ()
  "Add a new entry.  Choose a group by completion, then a title."
  (interactive)
  (keepass-browse--require-db)
  (let* ((group (keepass-browse--choose-group))
         (title (read-string "Title: "))
         (path (concat group title)))
    (keepass-browse--entry-open "*keepass-browse-add*" "add" nil
                                (format "Title: %s\nUserName: \nPassword: \nURL: \n" path))))

(defun keepass-browse--choose-group ()
  "Choose a KeePass group path by completion (ends in /)."
  (let ((groups (keepass-browse--group-paths)))
    (completing-read "Group: " groups nil nil nil)))

(defun keepass-browse-edit (path)
  "Edit the entry at PATH in an entry buffer.
The Title line holds the bare entry title; the full path is tracked in
`keepass-browse--entry-original', and the commit rebuilds the path from it,
so editing does not become a spurious add/delete."
  (interactive "sEntry path: ")
  (let* ((entry (keepass-browse--entry-get path))
         (title (file-name-nondirectory (directory-file-name path))))
    (keepass-browse--entry-open "*keepass-browse-edit*" "edit" path
                                (format "Title: %s\nUserName: %s\nPassword: %s\nURL: %s\n"
                                        title
                                        (keepass-browse--field entry "UserName")
                                        (keepass-browse--field entry "Password")
                                        (keepass-browse--field entry "URL")))))

(defun keepass-browse-clone (path)
  "Clone the entry at PATH into an entry buffer."
  (interactive "sEntry path: ")
  (let ((entry (keepass-browse--entry-get path)))
    (keepass-browse--entry-open "*keepass-browse-clone*" "add" nil
                                (mapconcat (lambda (f)
                                             (format "%s: %s" f (keepass-browse--field entry f)))
                                           '("Title" "UserName" "Password" "URL")
                                           "\n"))))

(defun keepass-browse--delete-entry (path)
  "Delete the entry at PATH without confirmation."
  ;; Resolve a padded Embark target to a real path; clean paths (leading /)
  ;; are used as-is.
  (unless (string-prefix-p "/" (or path ""))
    (setq path (keepass-browse--path-of path)))
  (let ((run (keepass-browse--run (keepass-browse--read-password)
                                  "rm" "-q" keepass-browse-database-file path)))
    (if (eq (cdr run) 0)
        (progn
          (setq keepass-browse--entries nil) ; invalidate cache
          (message "Deleted %s" path))
      (keepass-browse--error (car run)))))

(defun keepass-browse-delete (path)
  "Delete the entry at PATH, with confirmation."
  (interactive "sEntry path: ")
  (when (yes-or-no-p (format "Delete entry %s? " path))
    (keepass-browse--delete-entry path)))

(defun keepass-browse--entry-commit ()
  "Commit the add/clone/edit in the current entry buffer."
  (interactive)
  (let* ((entry (keepass-browse--parse-entry))
         (action (buffer-local-value 'keepass-browse--entry-action (current-buffer)))
         (original (buffer-local-value 'keepass-browse--entry-original (current-buffer)))
         (title (string-trim (keepass-browse--field entry "Title")))
         (password (keepass-browse--field entry "Password"))
         (delete-old nil)
         (cli-action "add")
         ;; The full path is rebuilt from the original's directory + the
         ;; (possibly renamed) title, so keepassxc-cli gets a real path and a
         ;; same-name edit stays an edit rather than a spurious add/delete.
         (base (if original (file-name-directory original) ""))
         (target (if (string-prefix-p "/" title) title (concat base title))))
    (when (string-empty-p title)
      (user-error "Title may not be empty"))
    (when (and (string= action "edit")
               original
               (not (string= original target)))
      ;; The title (and thus path) changed: add the new path, then delete old.
      (setq delete-old t cli-action "add"))
    (unless delete-old
      (setq cli-action (if (string= action "edit") "edit" "add")))
    (let* ((stdin (concat (keepass-browse--read-password) "\n"
                          password "\n"))
           (run (keepass-browse--run-stdin
                 stdin
                 cli-action keepass-browse-database-file
                 target
                 "-u" (keepass-browse--field entry "UserName")
                 "--url" (keepass-browse--field entry "URL")
                 "-p")))
      (if (eq (cdr run) 0)
          (progn
            (when delete-old
              (keepass-browse--delete-entry original))
            (setq keepass-browse--entries nil) ; invalidate cache
            (kill-buffer (current-buffer))
            (message "keepassxc-cli %s entry \"%s\"" cli-action title))
        (keepass-browse--error (car run))))))

;;; Embark integration

(defvar keepass-browse--selecting nil
  "Non-nil while `keepass-browse-select' is active.")

(defun keepass-browse--path-from-minibuffer ()
  "Return the entry path from the currently-selected minibuffer candidate.
Reads the `kb-path' text property off the candidate vertico has selected
(never the typed text), so the record identity comes straight from the data
structure rather than by parsing the display."
  (or (and (bound-and-true-p vertico--index)
           (>= vertico--index 0)
           (get-text-property 0 'kb-path
                              (nth vertico--index vertico--candidates)))
      (get-text-property 0 'kb-path (minibuffer-contents))))

(defun keepass-browse--embark-target ()
  "Embark target for the entry under point or in the selection minibuffer.
Returns (PATH . keepass-browse) so Embark routes to
`keepass-browse-action-map'."
  (let (path)
    (cond
     ;; In the listing buffer: the entry at point.
     ((derived-mode-p 'keepass-browse-mode)
      (setq path (get-text-property (point) 'kb-path)))
     ;; In the selection minibuffer: the current candidate.
     ((and (active-minibuffer-window) keepass-browse--selecting)
      (setq path (keepass-browse--path-from-minibuffer))))
    (when path (cons path 'keepass-browse))))

(add-to-list 'embark-target-finders #'keepass-browse--embark-target)

(defvar-keymap keepass-browse-action-map
  :doc "Embark actions for a keepass-browse entry target."
  "u" #'keepass-browse-copy-username
  "p" #'keepass-browse-copy-password
  "l" #'keepass-browse-copy-url
  "n" #'keepass-browse-copy-notes
  "t" #'keepass-browse-copy-totp
  "P" #'keepass-browse-insert-username
  "U" #'keepass-browse-insert-password
  "r" #'keepass-browse-reveal-password
  "v" #'keepass-browse-view
  "e" #'keepass-browse-edit
  "c" #'keepass-browse-clone
  "a" #'keepass-browse-add
  "d" #'keepass-browse-delete)

(add-to-list 'embark-keymap-alist '(keepass-browse . keepass-browse-action-map))

;;; Listing buffer

(defvar keepass-browse-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "C-.") #'embark-act)
    (define-key map (kbd "g") #'keepass-browse-refresh)
    map)
  "Keymap for `keepass-browse-mode'.")

(define-derived-mode keepass-browse-mode special-mode "keepass-browse"
  "Major mode for the keepass-browse listing buffer."
  (setq buffer-read-only nil
        truncate-lines t
        revert-buffer-function #'keepass-browse--revert))

(defun keepass-browse--revert (&rest _)
  "Refresh the listing buffer from the database."
  (keepass-browse--insert-list))

(defun keepass-browse--insert-list ()
  "Insert the current entries into the current buffer."
  (let ((inhibit-read-only t))
    (erase-buffer)
    (dolist (candidate (keepass-browse--candidates))
      (insert candidate "\n"))
    (goto-char (point-min))))

(defun keepass-browse-refresh ()
  "Reload the entry list from the database and redisplay."
  (interactive)
  (let ((buf (current-buffer)))
    (keepass-browse--load-entries t)
    (with-current-buffer buf
      (keepass-browse--insert-list))))

;;;###autoload
(defun keepass-browse-buffer ()
  "Open a columned listing buffer of all entries.
Press `embark-act' (`C-.') on a row to reach the action menu."
  (interactive)
  (keepass-browse--require-db)
  (let ((buf (get-buffer-create "*keepass-browse*")))
    (switch-to-buffer buf)
    (unless (eq major-mode 'keepass-browse-mode)
      (keepass-browse-mode))
    (keepass-browse--insert-list)))

;;;###autoload
(defun keepass-browse ()
  "Select a KeePass entry via consult/vertico minibuffer completion.
RET runs `keepass-browse-default-action' (by default `keepass-browse-view')
on the selected entry; `C-.' opens `keepass-browse-action-map' for further
actions (copy username/password, edit, ...).  Returns the chosen path."
  (interactive)
  (keepass-browse--require-db)
  (keepass-browse--load-entries)
  (let ((keepass-browse--selecting t))
    (let* ((chosen (consult--read (keepass-browse--candidates)
                                  :prompt "KeePass entry: "
                                  :history keepass-browse-history
                                  :category 'keepass-browse
                                  :require-match t
                                  :sort nil
                                  :lookup #'consult--lookup-member)))
      (let ((path (keepass-browse--path-of chosen)))
        (if (null path)
            (user-error "no path on candidate")
          (when keepass-browse-default-action
            (funcall keepass-browse-default-action path))
          path)))))

(provide 'keepass-browse)
;;; keepass-browse.el ends here
