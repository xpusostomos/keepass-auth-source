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
;;   - `keepass-browse'            pick an entry through the minibuffer
;;     (consult/vertico), then act on it (RET and `C-.' both lead to the
;;     action menu)
;;   - `keepass-browse-buffer'     a columned listing buffer (Embark works
;;     on the entry at point)
;;
;; The same actions are available from the Embark action maps
;; (`keepass-browse-action-map' and `keepass-browse-select-action-map') and
;; as interactive commands.
;;
;; This package builds on `keepass-auth-source' (same package): the shared
;; keepassxc-cli execution, master-password prompting/caching, error
;; reporting and the `keepass-auth-source-verbose' flag live there.

;;; Code:

(require 'cl-lib)
(require 'consult)
(require 'embark)
(require 'embark-consult)
(require 'keepass-auth-source)
(require 'password-cache)
(require 'subr-x)

(defgroup keepass-browse nil
  "Browse and edit KeePass entries with consult and embark."
  :group 'tools
  :prefix "keepass-browse-")

(defcustom keepass-browse-databases nil
  "List of KeePass databases available for browsing.
Each element is a cons cell (NAME . SPEC), where NAME is a user-visible
label shown by `keepass-browse-select-database', and SPEC is a database
specification for `keepass-auth-source': a file name (string) or a
keyword plist from `keepass-make-db-spec'.  See
`keepass-db-spec-normalize'."
  :type '(repeat (cons (string :tag "Name")
                       (choice (file :tag "Database file")
                               keepass-db-spec)))
  :group 'keepass-browse)

(defcustom keepass-browse-database nil
  "The currently active KeePass database specification.
Either a database file name (string) or a keyword plist from
`keepass-make-db-spec', as understood by `keepass-auth-source'.  Set
interactively with `keepass-browse-select-database'.  See
`keepass-db-spec-normalize'."
  :type '(choice (const :tag "None" nil)
                 (file :tag "Database file")
                 keepass-db-spec)
  :group 'keepass-browse)

;; If the database *list* is re-set, any previously selected database may
;; point at something stale (a fixed/removed entry), and
;; `keepass-browse--ensure-database' would keep using it because it only
;; acts when `keepass-browse-database' is nil.  Reset it so the user is
;; prompted to re-select.
(add-variable-watcher 'keepass-browse-databases
                      (lambda (_sym _newval _op _where)
                        (setq keepass-browse-database nil)))

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

(defcustom keepass-browse-default-action #'keepass-browse-view
  "Function run on the selected entry when `keepass-browse' returns.
Called with the entry path.  The default, `keepass-browse-view', shows the
entry; it can be changed to e.g. `keepass-browse-copy-password' to copy the
password directly on RET."
  :type '(choice (function :tag "View entry" keepass-browse-view)
                 (function :tag "Copy password" keepass-browse-copy-password)
                 (function :tag "None (just return the path)" ignore))
  :group 'keepass-browse)

;; The single source of truth for the entry actions.  Both the Embark action
;; keymaps and the visible key-menu on the view screen are generated from
;; this list, so the two menus can never drift apart.  Each element is
;; (KEY LABEL FUNCTION), where FUNCTION takes an entry path.
(defconst keepass-browse--actions
  '(("t" "copy title"    keepass-browse-copy-title)
    ("u" "copy username" keepass-browse-copy-username)
    ("p" "copy password" keepass-browse-copy-password)
    ("l" "copy url"      keepass-browse-copy-url)
    ("n" "copy notes"    keepass-browse-copy-notes)
    ("o" "copy totp"     keepass-browse-copy-totp)
    ("v" "view"          keepass-browse-view)
    ("e" "edit"          keepass-browse-edit)
    ("c" "clone"         keepass-browse-clone)
    ("a" "add"           keepass-browse-add)
    ("d" "delete"        keepass-browse-delete))
  "Actions for a keepass-browse entry, in canonical field order.
See `keepass-browse--action-map'.  (TOTP is the entry's time-based one-time
password, i.e. a stored two-factor code; see `keepass-browse-copy-totp'.)")

;;; Internal state

(defvar keepass-browse--last-killed nil
  "The last string copied, so clearing only happens if it is unchanged.")

(defvar keepass-browse--clear-timer nil
  "Timer to clear the clipboard.")

(defvar keepass-browse-history nil
  "History for `keepass-browse-select'.")

;; vertico is an optional completion framework (consult works without it);
;; these variables only exist once vertico is loaded, hence the `defvar'
;; declarations so the byte-compiler does not warn about them, and the
;; `bound-and-true-p' guards at the call sites.
(defvar vertico--index)
(defvar vertico--candidates)

;;; Subprocess plumbing
;;
;; All keepassxc-cli execution and master-password prompting is shared with
;; `keepass-auth-source' (which this package requires); the wrappers below
;; adapt it to the database configured for browsing.  See
;; `keepass-auth-source--keepassxc-run' et al.

(defun keepass-browse--db-spec ()
  "Return the active database spec, signalling an error if none is set."
  (unless keepass-browse-database
    (user-error "No KeePass database selected; run `keepass-browse-select-database' first"))
  keepass-browse-database)

(defun keepass-browse--database-path ()
  "Return the active database's expanded file path.
The `:file' of the active database's spec, expanded so a leading \"~\"
works; `file-exists-p' accepts \"~\" but keepassxc-cli does not."
  (let ((spec (keepass-browse--db-spec)))
    (expand-file-name
     (keepass-db-spec-file (keepass-db-spec-normalize spec)))))

(defun keepass-browse--db-keyfile ()
  "Return the active database's key file argument list, or nil.
A list (\"--key-file\" FILE), ready to splice into a keepassxc-cli
invocation."
  (let ((spec (keepass-browse--db-spec)))
    (keepass-auth-source--keyfile-args
     (keepass-db-spec-keyfile (keepass-db-spec-normalize spec)))))

(defun keepass-browse--db-yubi ()
  "Return the active database's YubiKey argument list, or nil.
A list (\"--yubikey\" VALUE), ready to splice into a keepassxc-cli
invocation."
  (let ((spec (keepass-browse--db-spec)))
    (keepass-auth-source--yubi-args
     (keepass-db-spec-yubi (keepass-db-spec-normalize spec)))))

(defun keepass-browse--db-password ()
  "Return the active database's master password, per its spec.
A string or function in the spec is used as-is; `:prompt' (or an
unspecified password) asks the user via `password-cache' (keyed by the
database path), honoring `keepass-browse-cache-expiry'; nil means no
password and resolves to `:no-password'."
  (let ((db (keepass-browse--database-path))
        (password-spec (keepass-db-spec-password
                        (keepass-db-spec-normalize keepass-browse-database))))
    (keepass-auth-source--resolve-password
     password-spec db keepass-browse-cache-expiry)))

(defun keepass-browse--read-password ()
  "Return the browsing database's master password, prompting and caching it.
Deprecated alias kept for call-site clarity; use `keepass-browse--db-password'."
  (keepass-browse--db-password))

(defun keepass-browse--run (password &rest args)
  "Run keepassxc-cli with ARGS on the active database.
PASSWORD is the resolved master password, or `:no-password' for a
passwordless database (which gets keepassxc-cli's --no-password global
option and no stdin).  Looks up the key file and YubiKey from the active
spec."
  (apply #'keepass-auth-source--keepassxc-run
         password
         (append (keepass-auth-source--no-password-flag password)
                 (keepass-browse--db-keyfile)
                 (keepass-browse--db-yubi)
                 args)))

(defun keepass-browse--run-stdin (password stdin &rest args)
  "Run keepassxc-cli with ARGS and STDIN, e.g. an entry edit or add.
STDIN already contains the database password (or nothing for a
passwordless DB) plus the entry's password, as required by
`keepass-auth-source--keepassxc-run-stdin'.  PASSWORD is the database's
resolved master password (possibly `:no-password')."
  (apply #'keepass-auth-source--keepassxc-run-stdin
         stdin
         password
         (keepass-auth-source--no-password-flag password)
         (keepass-browse--db-keyfile)
         (keepass-browse--db-yubi)
         args))

(defun keepass-browse--error (output)
  "Signal an error describing a failed keepassxc-cli run (OUTPUT)."
  (keepass-auth-source--error output (keepass-browse--database-path)))

(defun keepass-browse--require-db ()
  "Signal an error unless a database is configured.
Also applies the default-to-sole-database rule."
  (keepass-browse--ensure-database))

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
PATH is normally the clean entry path.  If it is a padded display string
(which an Embark action may hand over), it is resolved through
`keepass-browse--path-of' first.  Fetches directly from keepassxc-cli with
no caching, so database changes made elsewhere (e.g. Google Drive sync) are
always seen."
  (setq path (or (keepass-browse--path-of path) path))
  (let* ((db (keepass-browse--database-path))
         (pw (keepass-browse--db-password))
         (run (apply #'keepass-browse--run pw
                     (list "show" "--quiet" "--show-protected" db path))))
    (if (eq (cdr run) 0)
        (keepass-browse--parse-show (car run))
      (keepass-browse--error (car run)))))

(defun keepass-browse--field (entry field)
  "Return the value of FIELD in parsed alist ENTRY, or \"\"."
  (or (cdr (assoc field entry)) ""))

(defun keepass-browse--entry-paths ()
  "Return the list of entry paths (excluding group rows) in the database.
Reads freshly from keepassxc-cli, with no caching."
  (let* ((db (keepass-browse--database-path))
         (run (apply #'keepass-browse--run
                     (keepass-browse--db-password)
                     (list "ls" "--quiet" "--recursive" "--flatten" db))))
    (unless (eq (cdr run) 0)
      (keepass-browse--error (car run)))
    (let ((paths (seq-filter (lambda (s)
                               (and (not (string-blank-p s))
                                    (not (string-suffix-p "/" s))))
                             (split-string (car run) "\n" t))))
      (mapcar (lambda (p) (if (string-prefix-p "/" p) p (concat "/" p)))
              paths))))

(defun keepass-browse--group-paths ()
  "Return the list of group paths (each ending in /) in the database.
Reads freshly from keepassxc-cli, with no caching."
  (let* ((db (keepass-browse--database-path))
         (run (apply #'keepass-browse--run
                     (keepass-browse--db-password)
                     (list "ls" "--quiet" "--recursive" "--flatten" db))))
    (unless (eq (cdr run) 0)
      (keepass-browse--error (car run)))
    (mapcar (lambda (g) (if (string-prefix-p "/" g) g (concat "/" g)))
            (seq-filter (lambda (s) (string-suffix-p "/" s))
                        (split-string (car run) "\n" t)))))

(defun keepass-browse--export ()
  "Return the export XML node tree for the database.
Does ONE `keepassxc-cli export' call so the whole database (all entries,
all fields, passwords included) is fetched up front, freshly each time."
  (let ((run (apply #'keepass-browse--run
                    (keepass-browse--db-password)
                    (list "export" "--quiet" (keepass-browse--database-path)))))
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

(defun keepass-browse--load-entries ()
  "Return ((PATH . FIELDS) ...) for the whole database, freshly.
Does ONE export call and discards the result, so no entries are cached
behind the scenes; database changes made elsewhere are always visible."
  (let* ((tree (keepass-browse--export))
         (root (car (keepass-browse--xml-children-tag tree 'Root)))
         (entries '()))
    (dolist (g (keepass-browse--xml-children-tag root 'Group))
      (setq entries (append entries (keepass-browse--collect g ""))))
    ;; `keepassxc-cli rm' moves deleted entries to the Recycle Bin; exclude
    ;; them so a rename (add-new + delete-old) does not show a duplicate.
    (seq-filter (lambda (e)
                  (not (string-prefix-p "/Recycle Bin/" (car e))))
                entries)))

(defun keepass-browse--entry-directory (path)
  "Return the directory part of KeePass entry PATH, trailing slash included.
Examples: \"/a/b\" -> \"/a/\", \"/b\" -> \"/\", \"/\" -> \"/\", \"\" -> \"\".
Pure string arithmetic: entry paths are record paths that just happen to
look like file names, so they must never reach the `file-name-*' functions,
which route through `file-name-handler-alist' -- and therefore through
TRAMP -- hence a title such as \"Apple:foo:bar\" (path \"/Apple:foo:bar\")
would raise \"Method `Apple' is not known\"."
  (if (string-empty-p path)
      ""
    (let ((pos (string-match "/[^/]*\\'" path)))
      (if pos (substring path 0 (1+ pos)) "/"))))

(defun keepass-browse--entry-basename (path)
  "Return the last path segment of KeePass entry PATH.
Examples: \"/a/b\" -> \"b\", \"/b\" -> \"b\", \"/\" -> \"\".  Pure string
arithmetic -- see `keepass-browse--entry-directory'."
  (if (string-match "/[^/]*\\'" path)
      (substring path (1+ (match-beginning 0)))
    path))

(defun keepass-browse--group-contents (entries group)
  "Return the immediate children of GROUP in ENTRIES.
ENTRIES is a list of (PATH . FIELDS) pairs as returned by
`keepass-browse--load-entries'.  GROUP names a group: a path ending in
\"/\" (e.g. \"/Internet/\"), or \"/\" for the root group; a missing
trailing slash is added.  Returns (GROUPS . ENTRIES), where GROUPS is the
list of child group paths (each ending in \"/\") and ENTRIES the child
entry (PATH . FIELDS) pairs, both sorted by path."
  (let* ((group (if (string-suffix-p "/" group) group (concat group "/")))
         (in-group nil)
         (subgroups nil))
    (dolist (entry entries)
      (let ((path (car entry)))
        (when (string-equal (keepass-browse--entry-directory path) group)
          (push entry in-group))
        ;; A path strictly deeper than GROUP contributes its next segment as a
        ;; subgroup; a direct child entry (rest has no "/") is just that.
        (when (and (string-prefix-p group path)
                   (string-match-p "/" (substring path (length group))))
          (let* ((rest (substring path (length group)))
                 (seg (car (split-string rest "/" t))))
            (when (and seg (not (string-empty-p seg)))
              (push (concat group seg "/") subgroups))))))
    (cons (sort (delete-dups subgroups) #'string<)
          (sort in-group
                (lambda (a b) (string< (car a) (car b)))))))

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

(defun keepass-browse--format-group (path)
  "Return a display string for group PATH, tagged with `kb-path'."
  (let* ((trimmed (if (string-suffix-p "/" path) (substring path 0 -1) path))
         (str (concat (keepass-browse--entry-basename trimmed) "/")))
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
  (setq path (or (keepass-browse--path-of path) path)) ; resolve padded target
  (let ((run (apply #'keepass-browse--run
                    (keepass-browse--db-password)
                    (list "show" "--quiet" "--totp"
                          (keepass-browse--database-path) path))))
    (when (eq (cdr run) 0)
      (string-trim (car run)))))

;;; Actions (each takes an entry path)

(defun keepass-browse-copy-title (path)
  "Copy the title of the entry at PATH."
  (interactive "sEntry path: ")
  (keepass-browse--kill (keepass-browse--field (keepass-browse--entry-get path) "Title")
                        (format "Title of %s copied" path)))

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

(defvar-local keepass-browse-view--revealed nil
  "Non-nil while the password is shown in the current view buffer.")

(defvar-local keepass-browse-view-path nil
  "The entry path shown in `keepass-browse-view-mode'.")

(defconst keepass-browse-view-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    ;; Each action operates on the entry being viewed.
    (pcase-dolist (`(,key ,_label ,fn) keepass-browse--actions)
      (define-key map (kbd key)
        (lambda ()
          (interactive)
          (funcall fn keepass-browse-view-path))))
    (define-key map (kbd "r") #'keepass-browse-view-reveal)
    (define-key map (kbd "q") #'quit-window)
    (define-key map (kbd "C-.") #'embark-act)
    map)
  "Keymap for `keepass-browse-view-mode', generated from
`keepass-browse--actions'; each action operates on the viewed entry.  The
password reveal (r) and quit (q) are view-only.")

(define-derived-mode keepass-browse-view-mode special-mode "kb-view"
  "Major mode for viewing a KeePass entry.  Password is hidden until
\\[keepass-browse-view-reveal].")

(defun keepass-browse--view-menu ()
  "Return the key menu shown at the bottom of the view buffer.
Generated from `keepass-browse--actions' plus the view-only reveal and
quit, laid out in two columns.  The view action itself is omitted: this
menu is only shown when already viewing an entry."
  (let* ((items (append (seq-filter
                         (lambda (i) (not (equal (car i) "v")))
                         keepass-browse--actions)
                        '(("r" "reveal password")
                          ("q" "quit"))))
         (half (ceiling (length items) 2))
         (width (apply #'max 0 (mapcar (lambda (i) (length (cadr i))) items)))
         (fmt (format "[%%c] %%-%ds   %%s" width))
         (rows '()))
    (dotimes (i half)
      (let ((l (nth i items))
            (r (nth (+ half i) items)))
        (push (format fmt (aref (car l) 0) (cadr l)
                      (if r (format "[%c] %s" (aref (car r) 0) (cadr r)) ""))
              rows)))
    (concat "\n\n" (string-join (nreverse rows) "\n"))))

(defun keepass-browse--database-name ()
  "Return the user-visible name of the active database, or nil.
The name is the `car' of the (NAME . SPEC) entry in
`keepass-browse-databases' whose spec is the active one.  Returns nil when
the databases list is empty or when the active spec has no matching entry."
  (let ((spec keepass-browse-database))
    (car (cl-find spec keepass-browse-databases :key #'cdr :test #'equal))))

(defun keepass-browse-view-update (reveal)
  "Redraw the current view buffer, revealing the password when REVEAL.
The password appears once, on its own line after the username.  It is hidden
until toggled with `keepass-browse-view-reveal', unless it is empty, in
which case there is nothing to hide."
  (let* ((entry (keepass-browse--entry-get keepass-browse-view-path))
         (pw-field (keepass-browse--field entry "Password"))
         (pw (if (or reveal (string-blank-p pw-field))
                 pw-field
               "[hidden - press r]")))
    (let ((inhibit-read-only t))
      (erase-buffer)
      ;; Show which database this entry came from when several are configured.
      (when (> (length keepass-browse-databases) 1)
        (insert (format "%-10s %s\n" "Database"
                        (or (keepass-browse--database-name) "(unknown)"))))
      (dolist (f '("Title" "UserName"))
        (insert (format "%-10s %s\n" f (keepass-browse--field entry f))))
      (insert (format "%-10s %s\n" "Password" pw))
      (dolist (f '("URL" "Notes"))
        (insert (format "%-10s %s\n" f (keepass-browse--field entry f))))
      (insert (keepass-browse--view-menu)))
    (goto-char (point-min)))
  (setq buffer-read-only t))

(defun keepass-browse-view-reveal ()
  "Toggle showing the password in the view buffer.
A press reveals (and copies) the password; a second press hides it again.
Does nothing for an entry with no password."
  (interactive)
  (if (string-blank-p (keepass-browse--field
                       (keepass-browse--entry-get keepass-browse-view-path)
                       "Password"))
      (message "No password for this entry")
    (setq-local keepass-browse-view--revealed
                (not keepass-browse-view--revealed))
    (when keepass-browse-view--revealed
      (keepass-browse--kill (keepass-browse--field
                             (keepass-browse--entry-get keepass-browse-view-path)
                             "Password")
                            "Password copied to clipboard"))
    (keepass-browse-view-update keepass-browse-view--revealed)))

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

(defun keepass-browse-view-refresh (&optional new-path)
  "Redraw the open view buffer from the (reloaded) database.
NEW-PATH, when given, re-points the view at the entry's new path (after a
rename).  Does nothing if no view buffer is open."
  (let ((buf (get-buffer "*keepass-browse-view*")))
    (when buf
      (with-current-buffer buf
        (when new-path
          (setq-local keepass-browse-view-path new-path))
        (keepass-browse-view-update keepass-browse-view--revealed)))))


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
      (let ((run (keepass-auth-source--keepassxc-run "" "generate" "-L" (format "%d" len))))
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
                             '("Title" "UserName" "Password" "URL" "Notes") "\n")))
      (goto-char (point-min))
      (keepass-browse-entry-mode)
      (setq-local keepass-browse--entry-action action)
      (setq-local keepass-browse--entry-original path))
    (switch-to-buffer buf)))

(defun keepass-browse--parse-entry ()
  "Parse the current entry buffer into a FIELD . VALUE alist.
Each field is a single line, except Notes, which extends from after
\"Notes: \" to the end of the buffer, so multi-line notes are preserved."
  (goto-char (point-min))
  (let ((result '())
        (keys '("Title" "UserName" "Password" "URL")))
    (dolist (key keys)
      (when (re-search-forward (concat "^" key ": ?\\(.*\\)$") nil t)
        (setq result (cons (cons key (match-string 1)) result))))
    ;; Notes is last: everything from after "Notes: " to the end of the
    ;; buffer belongs to it, so multi-line notes survive intact.
    (goto-char (point-min))
    (when (re-search-forward "^Notes: ?" nil t)
      (let ((notes (buffer-substring-no-properties (point) (point-max))))
        (setq result (cons (cons "Notes" (string-trim notes)) result))))
    (nreverse result)))

;;; Add / edit / clone / delete

(defun keepass-browse-add (&optional target)
  "Add a new entry.
When invoked as an Embark action, TARGET is the selected entry's path and
the new entry is created in the same group as that entry.  When called
directly, the group is chosen by completion.  Fill in the Title (after the
group prefix) and the other fields, then commit with
`keepass-browse--entry-commit'."
  (interactive "sEntry path: ")
  (keepass-browse--require-db)
  (let* ((group (if (and target (not (string-blank-p target)))
                    ;; Same group as the selected entry; pure string ops
                    ;; only (see `keepass-browse--entry-directory').
                    (keepass-browse--entry-directory
                     (concat "/" (string-trim-left target "/")))
                  (keepass-browse--choose-group))))
    (keepass-browse--entry-open "*keepass-browse-add*" "add" nil
                                (format "Title: %s\nUserName: \nPassword: \nURL: \nNotes: \n" group))))

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
         (title (keepass-browse--entry-basename path)))
    (keepass-browse--entry-open "*keepass-browse-edit*" "edit" path
                                (format "Title: %s\nUserName: %s\nPassword: %s\nURL: %s\nNotes: %s\n"
                                        title
                                        (keepass-browse--field entry "UserName")
                                        (keepass-browse--field entry "Password")
                                        (keepass-browse--field entry "URL")
                                        (keepass-browse--field entry "Notes")))))

(defun keepass-browse-clone (path)
  "Clone the entry at PATH into an entry buffer."
  (interactive "sEntry path: ")
  (let ((entry (keepass-browse--entry-get path)))
    (keepass-browse--entry-open "*keepass-browse-clone*" "add" nil
                                (mapconcat (lambda (f)
                                             (format "%s: %s" f (keepass-browse--field entry f)))
                                           '("Title" "UserName" "Password" "URL" "Notes")
                                           "\n"))))

(defun keepass-browse--delete-entry (path)
  "Delete the entry at PATH without confirmation."
  ;; Resolve a padded Embark target to a real path; clean paths (leading /)
  ;; are used as-is.
  (unless (string-prefix-p "/" (or path ""))
    (setq path (keepass-browse--path-of path)))
  (let ((run (apply #'keepass-browse--run
                    (keepass-browse--db-password)
                    (list "rm" "--quiet" (keepass-browse--database-path) path))))
    (if (eq (cdr run) 0)
        (progn
          ;; If the deleted entry is displayed in the view buffer, close it --
          ;; its path no longer exists, so it could only show stale data.
          (let ((view (get-buffer "*keepass-browse-view*")))
            (when (and view
                       (with-current-buffer view
                         (equal keepass-browse-view-path path)))
              (kill-buffer view)))
          (message "Deleted %s" path))
      (keepass-browse--error (car run)))))

(defun keepass-browse-delete (path)
  "Delete the entry at PATH, with confirmation."
  (interactive "sEntry path: ")
  (when (yes-or-no-p (format "Delete entry %s? " path))
    (keepass-browse--delete-entry path)))

(defun keepass-browse--entry-commit ()
  "Commit the add/clone/edit in the current entry buffer.
An edit uses `keepassxc-cli edit' in place (passing `-t' when the title
changed), so a rename is not a delete+add and never creates a Recycle-Bin
duplicate.  A new entry uses `keepassxc-cli add'."
  (interactive)
  (let* ((entry (keepass-browse--parse-entry))
         (action (buffer-local-value 'keepass-browse--entry-action (current-buffer)))
         (original (buffer-local-value 'keepass-browse--entry-original (current-buffer)))
         (title (string-trim (keepass-browse--field entry "Title")))
         (password (keepass-browse--field entry "Password"))
         (path (cond ((string= action "edit")
                      ;; keepassxc-cli `edit' renames within the current group
                      ;; via -t; the entry is at ORIGINAL.
                      original)
                     ;; add/clone: create under the original entry's group.
                     (t (concat (if original
                                     (keepass-browse--entry-directory original)
                                   "")
                                (if (string-prefix-p "/" title) title title))))))
    (when (string-empty-p title)
      (user-error "Title may not be empty"))
    (let* ((dbpw (keepass-browse--db-password))
           ;; keepassxc-cli reads the database password then (with -p) the
           ;; entry password from stdin.  For a passwordless DB there is no
           ;; database password line; --no-password tells keepassxc-cli so.
           (stdin (if (eq dbpw :no-password)
                      (concat password "\n")
                    (concat dbpw "\n" password "\n")))
           (cli (if (string= action "edit") "edit" "add"))
           ;; `-t' (title) exists only on `edit'; for `add' the title is part
           ;; of the entry path and is not passed separately.  Global options
           ;; (`--no-password', `--key-file') come after the subcommand and
           ;; before the positional database argument.
           (db (keepass-browse--database-path))
           (common (append (list "-u" (keepass-browse--field entry "UserName")
                                 "--url" (keepass-browse--field entry "URL")
                                 "--notes" (keepass-browse--field entry "Notes")
                                 "-p")))
           (global (append (keepass-auth-source--no-password-flag dbpw)
                           (keepass-browse--db-keyfile)))
           (args (if (string= action "edit")
                     (append (list cli) global (list db path "-t" title) common)
                   (append (list cli) global (list db path) common))))
      (let ((run (apply #'keepass-auth-source--keepassxc-run-stdin stdin args)))
        (if (eq (cdr run) 0)
            (progn
              ;; Re-point and redraw the view buffer at the entry as it now
              ;; exists: for an edit it may have been renamed via -t; for a
              ;; clone it is the newly created copy.
              (keepass-browse-view-refresh
               (if (string= action "edit")
                   (concat (keepass-browse--entry-directory (or original "")) title)
                 path))
              (kill-buffer (current-buffer))
              (message "keepassxc-cli %s entry \"%s\"" cli title))
          (keepass-browse--error (car run)))))))

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
The target type depends on the context, so Embark shows the right menu:
`keepass-browse-view' in the view buffer (whose menu omits the redundant
view action), `keepass-browse' in the listing buffer, and
`keepass-browse-select' in the selection minibuffer (whose menu adds the
insert actions, which only make sense while the originating buffer's point
is preserved)."
  (let (path type)
    (cond
     ;; In the listing buffer: the entry at point.
     ((derived-mode-p 'keepass-browse-mode)
      (setq type 'keepass-browse
            path (get-text-property (point) 'kb-path)))
     ;; In the view buffer: the entry being viewed.
     ((derived-mode-p 'keepass-browse-view-mode)
      (setq type 'keepass-browse-view
            path keepass-browse-view-path))
     ;; In the selection minibuffer: the current candidate.
     ((and (active-minibuffer-window) keepass-browse--selecting)
      (setq type 'keepass-browse-select
            path (keepass-browse--path-from-minibuffer))))
    (when path (cons type path))))

(add-to-list 'embark-target-finders #'keepass-browse--embark-target)

(defun keepass-browse--build-action-map (&optional excluded)
  "Build an Embark action keymap from `keepass-browse--actions'.
EXCLUDED is a list of keys (e.g. \"v\") to leave out.  define-key prepends,
so the list is walked in reverse to make the menu *display* the actions in
canonical field order; RET (the default action) is defined first so it
displays last."
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "RET") #'keepass-browse-run-default-action)
    (dolist (entry (reverse keepass-browse--actions))
      (pcase-let ((`(,key ,_label ,fn) entry))
        (unless (member key excluded)
          (define-key map (kbd key) fn))))
    map))

(defconst keepass-browse-action-map
  (keepass-browse--build-action-map)
  "Embark actions for a keepass-browse entry target.
Used in the listing buffer, where point is not in an editing context and
the insert actions do not apply.  Copy actions are listed in the canonical
field order: Title, UserName, Password, URL, Notes.")

(defconst keepass-browse-view-action-map
  (keepass-browse--build-action-map '("v"))
  "Embark actions for the entry shown in the view buffer.
Same as `keepass-browse-action-map' minus `v' (view): the view buffer
already shows the entry, so re-viewing it is meaningless.")

(defvar-keymap keepass-browse-select-action-map
  :doc "Embark actions for a keepass-browse entry selected from the
selection minibuffer.  Inherits the base actions and adds the insert
actions, which make sense because the point of the originating buffer is
preserved while the minibuffer is active."
  :parent keepass-browse-action-map
  "P" #'keepass-browse-insert-username
  "U" #'keepass-browse-insert-password)
;; The default Embark action for our target types is `keepass-browse-view'
;; (via the wrapper), not -- as Embark would otherwise fall back to for
;; minibuffer targets -- the command that opened the minibuffer
;; (`keepass-browse' itself), which would run the selector recursively and
;; error.
(mapc (lambda (type)
        (add-to-list 'embark-default-action-overrides
                     (cons type #'keepass-browse-run-default-action)))
      '(keepass-browse keepass-browse-view keepass-browse-select))

(add-to-list 'embark-keymap-alist '(keepass-browse . keepass-browse-action-map))
(add-to-list 'embark-keymap-alist
             '(keepass-browse-view . keepass-browse-view-action-map))
(add-to-list 'embark-keymap-alist
             '(keepass-browse-select . keepass-browse-select-action-map))

(defun keepass-browse-run-default-action (path)
  "Run `keepass-browse-default-action' on the entry at PATH.
A command wrapper so RET in the action map can invoke whatever function
`keepass-browse-default-action' names."
  (interactive "sEntry path: ")
  (funcall keepass-browse-default-action path))

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
    (keepass-browse--load-entries)
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

(defun keepass-browse--group-choose (entries group)
  "Drill down from GROUP, returning the chosen entry path or nil.
ENTRIES is one database's ((PATH . FIELDS) ...) (already exported, so
only a single keepassxc-cli call is made for the whole walk).  At each
level the completion candidates are the current group's subgroups and
entries; choosing a subgroup descends into it (recursively), choosing an
entry returns its path.  Returns nil if a group turns out empty."
  (let* ((contents (keepass-browse--group-contents entries group))
         (groups (car contents))
         (subentries (cdr contents)))
    (if (and (null groups) (null subentries))
        (progn (message "No entries under %s" group) nil)
      (let* ((cands (append (mapcar #'keepass-browse--format-group groups)
                            (mapcar (lambda (e)
                                      (keepass-browse--format-candidate
                                       (car e) (cdr e)))
                                    subentries)))
             (chosen (consult--read cands
                                    :prompt (format "KeePass (%s): " group)
                                    :history keepass-browse-history
                                    :category 'keepass-browse
                                    :require-match t
                                    :sort nil
                                    :lookup #'consult--lookup-member))
             (path (keepass-browse--path-of chosen)))
        (cond ((null path) (user-error "no path on candidate"))
              ;; A trailing slash marks a group: descend into it.
              ((string-suffix-p "/" path)
               (keepass-browse--group-choose entries path))
              (t path))))))

;;;###autoload
(defun keepass-browse-group (&optional path)
  "Select a KeePass entry by navigating its group hierarchy.
Start from GROUP (default \"/\", the root) and complete over each
group's children one level at a time -- subgroups and entries -- until
an entry is chosen; choosing a subgroup descends into it.  When an entry
is picked, `keepass-browse-default-action' (by default
`keepass-browse-view') runs on it, exactly as with `keepass-browse'.
Returns the chosen entry path."
  (interactive)
  (keepass-browse--require-db)
  (let ((keepass-browse--selecting t))
    (let* ((path (or path "/"))
           (entries (keepass-browse--load-entries))
           (result (keepass-browse--group-choose entries path)))
      (when (and result keepass-browse-default-action)
        (funcall keepass-browse-default-action result))
      result)))

(defun keepass-browse--check-databases ()
  "Signal a clear error if `keepass-browse-databases' has the wrong shape.
Each element must be a cons cell (NAME . SPEC): NAME is a string label and
SPEC is a database file name or a `keepass-make-db-spec' plist."
  (unless (listp keepass-browse-databases)
    (user-error "`keepass-browse-databases' must be a list of (NAME . SPEC) \
conses, got %S" keepass-browse-databases))
  (dolist (entry keepass-browse-databases)
    (unless (and (consp entry)
                 (stringp (car entry)))
      (user-error "Each element of `keepass-browse-databases' must be a \
(NAME . SPEC) cons; got %S" entry))))

(defun keepass-browse--ensure-database ()
  "Make sure a database is selected.
If `keepass-browse-database' is already set, leave it.  Otherwise, if
`keepass-browse-databases' has exactly one entry, select it automatically;
if it has several and the user has not picked one yet, prompt them with
`keepass-browse-select-database'."
  (keepass-browse--check-databases)
  (unless keepass-browse-database
    (if (= 1 (length keepass-browse-databases))
        (setq keepass-browse-database (cdar keepass-browse-databases))
      (keepass-browse-select-database)))
  keepass-browse-database)

;;;###autoload
(defun keepass-browse-select-database ()
  "Select the active KeePass database from `keepass-browse-databases'."
  (interactive)
  (keepass-browse--check-databases)
  (unless keepass-browse-databases
    (user-error "`keepass-browse-databases' is empty -- add your databases first"))
  (let* ((names (mapcar #'car keepass-browse-databases))
         (chosen (completing-read "KeePass database: " names nil t)))
    (setq keepass-browse-database
          (cdr (assoc chosen keepass-browse-databases)))
    (message "Using KeePass database %s" chosen)
    keepass-browse-database))

;;;###autoload
(defun keepass-browse-add-databases-to-auth-sources ()
  "Add every database spec in `keepass-browse-databases' to `auth-sources'.
Each entry's SPEC (the `cdr' of the (NAME . SPEC) cons) is appended to
`auth-sources' so `keepass-auth-source' can search all of them.  Call
after setting `keepass-browse-databases' and before/after
`keepass-auth-source-enable'."
  (interactive)
  (dolist (entry keepass-browse-databases)
    (let ((spec (cdr entry)))
      (unless (member spec auth-sources)
        (setq auth-sources (append auth-sources (list spec)))))))

(provide 'keepass-browse)
;;; keepass-browse.el ends here
