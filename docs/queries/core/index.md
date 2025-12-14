# Core Metrics

Fundamental system health: CPU, memory, disk, network, and processes.

## Queries

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| [`get_cpu_info`](get_cpu_info.md) | Returns CPU usage, frequency, load average, and... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_disk_info`](get_disk_info.md) | Returns disk partition information including mo... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_memory_info`](get_memory_info.md) | Returns memory usage including total, used, ava... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_network_info`](get_network_info.md) | Returns network interface information including... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_processes`](get_processes.md) | Returns a list of running processes with CPU an... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_temperature`](get_temperature.md) | Returns hardware temperature sensor readings. | :white_check_mark: | :warning: | :warning: |
| [`get_uptime`](get_uptime.md) | Returns system uptime and boot time. | :white_check_mark: | :white_check_mark: | :white_check_mark: |


## Scope

All queries in this category are in the `core` scope.

---

*Documentation auto-generated on 2025-12-14*
