ssh-agent-proxy is an agent allowing to filter all ssh keys stored in a proper ssh agent (openssh agent, or one provided by popular password managers like Bitwarden or KeePassXC)
It will be written in go 1.26.5 using standard library.

The keys can be filtered by comment, md5 fingerprint or sha256 base64 encoded hash of the public key.
Multiple keys can be grouped into separate groups, and each group can be exposed via separate endpoint (socket).
Configuration can be stored in yaml config file. It should allow to define multiple groups, and for each group a path to a socket file and list of keys belonging to that group.
The order of keys within each group is as defined in the config file.
Each key can belong to any group, multiple group, or be filtered out completely (when not belonging to any group).
With no group defined, no keys should be exposed.
The config should also contain a path to upstream ssh agent socket.
The tool should write logs to standard output using standard slog library.
The tool should initially support Linux and MacOS (both Intel and Apple silicon-based). Windows version might be implemented later, if possible.
The tool should be easy to install as a daemon.
On Linux, it should utilize systemd user services and logs should be handled by systemd journal.
On MacOS, the tool should be installable via homebrew or manually and started via Launch Agents mechanism. The logs should go to system native log mechanism using os_log.
On Windows (in the future), it should be run via task scheduler and log to system Event Log.
The tool should be automatically restarted if crashed / killed, unless it is properly stopped.
The installation, starting, stopping, checking status, and uninstallation should be handled by the tool itself with proper command-line arguments (-install, -uninstall, -start, -stop, -status, -restart).
If debug option is set in configuration file, the tool should provide verbose logging.
If -foreground option is provided when run from command-line, the tool should start in the foreground and log to standard output. 
The configuration file should be stored in user's default config directory (as returned by go os.UserConfigDir() function) + /ssh-agent-proxy/config.yaml. Required subdirectory should be automatically created during installation.
On Linux this is typically ~/.config/ssh-agent-proxy/config.yaml, on MacOS - ~/Library/Application Support/ssh-agent-proxy/config.yaml, and on Windows - %APPDATA%\ssh-agent-proxy\config.yaml
The tool should be accompanied with the README.md file containing tool description, installation and uninstallation procedure for each supported OS, description of all command-line options, description of configuration file format, and sample configuration file.
If configuration file cannot be opened, the config cannot be parsed correctly, or it is missing required options, the tool should log an error message and do nothing. It should not exit, unless run in foreground mode, to prevent it from being restarted over and over again.
The only required config option is a path to upstream ssh agent socket. No groups need to be defined, but if a group is defined, it must contain a path to group-specific socket and optional list of keys (by comment, md5 fingerprint or sha256 hash). 

