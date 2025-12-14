# Log Access

System logs, journals, and event logs for diagnostics.

## Queries

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| [`get_app_logs`](get_app_logs.md) | Returns application-specific log files. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_auth_logs`](get_auth_logs.md) | Returns authentication and security logs. Requi... | :white_check_mark: | :white_check_mark: | :x: |
| [`get_event_log`](get_event_log.md) | Returns Windows Event Log entries. | :x: | :x: | :white_check_mark: |
| [`get_journal_logs`](get_journal_logs.md) | Returns systemd journal logs with filtering opt... | :white_check_mark: | :x: | :x: |
| [`get_kernel_logs`](get_kernel_logs.md) | Returns kernel ring buffer (dmesg) messages. | :white_check_mark: | :white_check_mark: | :x: |
| [`get_syslog`](get_syslog.md) | Returns traditional syslog entries. | :white_check_mark: | :white_check_mark: | :x: |


## Scope

All queries in this category are in the `logs` scope.

---

*Documentation auto-generated on 2025-12-14*
