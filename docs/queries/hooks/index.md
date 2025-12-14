# System Hooks

Deep system introspection: scheduled tasks, kernel, network config, security.

## Queries

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| [`get_arp_table`](get_arp_table.md) | Returns ARP cache entries. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_block_devices`](get_block_devices.md) | Returns block device topology. | :white_check_mark: | :warning: | :white_check_mark: |
| [`get_capabilities`](get_capabilities.md) | Returns process capabilities. | :white_check_mark: | :x: | :x: |
| [`get_certificates`](get_certificates.md) | Returns SSL/TLS certificates from system store. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_cgroups`](get_cgroups.md) | Returns cgroup resource limits and usage. | :white_check_mark: | :x: | :x: |
| [`get_core_dumps`](get_core_dumps.md) | Returns core dump configuration and recent dumps. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_cron_jobs`](get_cron_jobs.md) | Returns cron jobs for all users and system cron... | :white_check_mark: | :white_check_mark: | :x: |
| [`get_disk_io`](get_disk_io.md) | Returns disk I/O statistics. | :white_check_mark: | :warning: | :warning: |
| [`get_dns_servers`](get_dns_servers.md) | Returns configured DNS servers. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_env_vars`](get_env_vars.md) | Returns environment variables. Sensitive values... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_firewall_rules`](get_firewall_rules.md) | Returns firewall rules. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_hardware_info`](get_hardware_info.md) | Returns hardware information (DMI/SMBIOS). | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_inode_usage`](get_inode_usage.md) | Returns inode usage per filesystem. | :white_check_mark: | :white_check_mark: | :x: |
| [`get_ipc_resources`](get_ipc_resources.md) | Returns System V IPC resources (semaphores, sha... | :white_check_mark: | :warning: | :x: |
| [`get_kernel_modules`](get_kernel_modules.md) | Returns loaded kernel modules. | :white_check_mark: | :x: | :x: |
| [`get_listening_ports`](get_listening_ports.md) | Returns listening network ports with process in... | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_loaded_drivers`](get_loaded_drivers.md) | Returns loaded kernel drivers/extensions. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_mac_status`](get_mac_status.md) | Returns Mandatory Access Control status (SELinu... | :white_check_mark: | :warning: | :x: |
| [`get_mounts`](get_mounts.md) | Returns mounted filesystems with options. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_namespaces`](get_namespaces.md) | Returns Linux namespaces. | :white_check_mark: | :x: | :x: |
| [`get_network_stats`](get_network_stats.md) | Returns network interface statistics. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_ntp_status`](get_ntp_status.md) | Returns NTP synchronization status. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_numa_topology`](get_numa_topology.md) | Returns NUMA node topology. | :white_check_mark: | :x: | :x: |
| [`get_open_files`](get_open_files.md) | Returns open file handles for a process. | :white_check_mark: | :white_check_mark: | :warning: |
| [`get_pci_devices`](get_pci_devices.md) | Returns PCI devices. | :white_check_mark: | :warning: | :warning: |
| [`get_power_state`](get_power_state.md) | Returns power supply and battery state. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_routes`](get_routes.md) | Returns routing table. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_scheduled_tasks`](get_scheduled_tasks.md) | Returns Windows Task Scheduler tasks. | :x: | :x: | :white_check_mark: |
| [`get_ssh_config`](get_ssh_config.md) | Returns SSH server configuration. Requires sens... | :white_check_mark: | :white_check_mark: | :warning: |
| [`get_startup_items`](get_startup_items.md) | Returns startup programs and services. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_sudo_config`](get_sudo_config.md) | Returns sudoers configuration. Requires sensiti... | :white_check_mark: | :white_check_mark: | :x: |
| [`get_systemd_services`](get_systemd_services.md) | Returns systemd service unit status. | :white_check_mark: | :x: | :x: |
| [`get_timezone`](get_timezone.md) | Returns timezone and locale information. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_usb_devices`](get_usb_devices.md) | Returns connected USB devices. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_user_accounts`](get_user_accounts.md) | Returns local user accounts. | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [`get_vm_info`](get_vm_info.md) | Returns virtualization/hypervisor detection. | :white_check_mark: | :white_check_mark: | :white_check_mark: |


## Scope

All queries in this category are in the `hooks` scope.

---

*Documentation auto-generated on 2025-12-14*
