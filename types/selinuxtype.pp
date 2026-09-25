# An SELinux type name. Restricted to the characters SELinux allows so the
# name can be interpolated into a file_line `match` regex unescaped.
type Auditd::SelinuxType = Pattern[/\A[a-z0-9_]+_t\z/]
