# NxPKG Command Reference / NxPKG 命令参考 (v6.2.0 "Project Chimera")

This document provides a comprehensive list of all available commands and their parameters for the NxPKG system.
本文档以详尽的列表形式，提供了 NxPKG 系统的所有可用命令及其参数。

---

### Global Options / 全局选项

These options can be used before any command.
这些选项可以用在任何命令之前。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `nxpkg` | `--help`, `-h` | Show the main help message. <br> 显示主帮助信息。 |
| `nxpkg` | `--version` | Show the version of NxPKG. <br> 显示 NxPKG 的版本号。 |
| `nxpkg` | `--debug` | Enable detailed debug output for troubleshooting. <br> 启用用于故障排查的详细调试输出。 |

---

### Core Package Management / 核心包管理

Commands for installing, removing, and querying packages.
用于安装、移除和查询软件包的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `install` (or `in`) | `<pkg...>` | Installs one or more packages and their dependencies. <br> 安装一个或多个软件包及其依赖。 |
| | `[--allow-canary]` | Allow the installation of packages marked as unstable "canary" releases, bypassing the `canary_policy` setting. <br> 允许安装被标记为不稳定“金丝雀”版本的软件包，可绕过 `canary_policy` 的设置。 |
| `remove` (or `rm`) | `<pkg...>` | Removes one or more packages from the system. <br> 从系统中移除一个或多个软件包。 |
| `upgrade` | | Upgrades all packages that are explicitly listed in the `world` file to their latest versions. <br> 将 `world` 文件中明确列出的所有软件包升级到它们的最新版本。 |
| `search` | `<keyword>` | Searches for packages in the synchronized repositories. <br> 在已同步的仓库中搜索软件包。 |
| | `--update-index` | Forces a rebuild of the search index from repository data. <br> 强制从仓库数据重新构建搜索索引。 |
| `info` | `<pkg>` | Displays detailed information about a package, including its description, version, dependencies, and blockchain trust status. <br> 显示一个软件包的详细信息，包括其描述、版本、依赖和区块链信任状态。 |
| `owns` | `<file_path>` | Finds which NxPKG-managed package owns a specific file. <br> 查找一个特定的文件属于哪个由 NxPKG 管理的软件包。 |

---

### Declarative State Management / 声明式状态管理

Commands for managing the system state declaratively using the `world` file.
使用 `world` 文件来声明式地管理系统状态的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `rebuild` | | Synchronizes the system state (packages and strata) to match the `world` file. <br> 将系统状态（软件包和Strata环境）与 `world` 文件中的声明进行同步。 |
| | `[--prune]` | Removes any packages or strata that are installed on the system but not declared in the `world` file. <br> 移除任何已安装在系统上但未在 `world` 文件中声明的软件包或Strata环境。 |
| | `[--dry-run]` | Shows a detailed plan of all changes without executing them. <br> 显示所有变更的详细计划，但不会实际执行它们。 |
| | `[-y \| --yes \| --force]` | Skips the interactive confirmation prompt and proceeds with the changes. <br> 跳过交互式确认提示，直接执行变更。 |
| `autoremove` (or `auto`, `autorm`) | | Removes orphaned packages and strata that are no longer required by anything in the `world` file. Prompts for packages and strata separately. <br> 移除 `world` 文件不再需要的孤儿软件包和Strata环境。会对软件包和Strata环境分别进行提示。 |

---

### Build System / 构建系统

Commands related to building packages from source.
与从源码构建软件包相关的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `build` | `<pkg>` | Builds a single package from its source according to its `.build` file. <br> 根据一个软件包的 `.build` 文件从源码构建它。 |
| | `[--canary]` | Appends a `-canary` suffix to the package version, marking it as a non-stable build. <br> 在软件包版本后附加一个 `-canary` 后缀，将其标记为非稳定构建版。 |
| `gen-build` | `<source_url>` | Attempts to automatically generate a basic `.build` file by analyzing a source code URL. Prints to standard output. <br> 尝试通过分析一个源码URL来自动生成一个基础的 `.build` 文件。结果会打印到标准输出。 |

---

### Strata (Meta-PM) System / Strata (元包管理器) 系统

Commands for managing isolated environments (strata).
用于管理隔离环境 (strata) 的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `strata` | `--create <name> <pm>` | Creates a new isolated environment. `<pm>` can be `apt`, `pacman`, `dnf`, or `portage`. <br> 创建一个新的隔离环境。`<pm>` 可以是 `apt`、`pacman`、`dnf` 或 `portage`。 |
| | `--list` | Lists all available Strata environments. <br> 列出所有可用的Strata环境。 |
| | `-e`, `--execute <name> <command...>` | Executes a command inside the specified Strata. <br> 在指定的Strata内部执行一个命令。 |
| | `--destroy <name>` | Permanently deletes a Strata environment and all its contents. <br> 永久删除一个Strata环境及其所有内容。 |
| | `--export-pkgs <name>` | Lists all packages installed inside a Strata in a `strata-pkg:` format suitable for the `world` file. <br> 以适用于 `world` 文件的 `strata-pkg:` 格式，列出在一个Strata内部安装的所有软件包。 |
| | `--promote <name>` | Adds a Strata and all its internal packages to the `world` file, making it part of the declarative state. <br> 将一个Strata及其所有内部软件包“提升”到 `world` 文件中，使其成为声明式状态的一部分。 |

---

### Decentralized Forum / 去中心化论坛

Commands to interact with the built-in, P2P-based forum.
用于与内置的、基于P2P的论坛进行交互的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `forum` | `sync` | Synchronizes new topics and posts from the P2P network. <br> 从P2P网络同步新的话题和帖子。 |
| | `list` | Lists all locally known topics. <br> 列出所有本地已知的话题。 |
| | `show <topic_id>` | Shows the full content and replies for a specific topic. <br> 显示一个特定话题的完整内容和所有回复。 |
| | `search <keyword>` | Searches topic titles and post contents for a keyword. <br> 在话题标题和帖子内容中搜索关键词。 |
| | `new-topic --title "..."` | Publishes a new topic. <br> 发布一个新话题。 |
| | `[--body "..."]` | (Optional) The content of the topic. If not provided, reads from standard input. <br> (可选) 话题的正文内容。如果未提供，则从标准输入读取。 |
| | `[--attach /path/to/file]` | (Optional) Attach a file to the topic. <br> (可选) 为话题附加一个文件。 |
| | `post <topic_id>` | Replies to an existing topic. <br> 回复一个已有的话题。 |
| | `[--body "..."]` | (Optional) The content of the reply. If not provided, reads from standard input. <br> (可选) 回复的正文内容。如果未提供，则从标准输入读取。 |
| | `[--attach /path/to/file]` | (Optional) Attach a file to the reply. <br> (可选) 为回复附加一个文件。 |
| | `get-attachment <hash> <out_file>` | Downloads a forum object (like an attachment or post body) from the P2P network. <br> 从P2P网络下载一个论坛对象（如附件或帖子正文）。 |
| | `export <topic_id> <file.tar.gz>` | **[NEW]** Exports a full topic with all its posts and attachments to a single portable archive (`.tar.gz`). <br> **[新增]** 将一个完整的话题及其所有帖子和附件，导出一个单一的可移植压缩包 (`.tar.gz`) 中。 |
| | `import <file.tar.gz>` | **[NEW]** Imports a topic from a portable archive, verifying its contents and merging into the local database. <br> **[新增]** 从一个可移植的压缩包导入话题，会验证其内容并合并到本地数据库。 |
| | `init` | Initializes or checks the forum database. <br> 初始化或检查论坛数据库。 |

---

### Security & Trust Management / 安全与信任管理

Commands for managing GPG keys and trust zones.
用于管理GPG密钥和信任区的命令。

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `key` | `--list` | Lists all GPG public keys in the current trust zone. <br> 列出当前信任区中的所有GPG公钥。 |
| | `--import <key_file.asc>` | Imports a GPG public key into the current trust zone. <br> 向当前信任区导入一个GPG公钥。 |
| | `--delete <KEY_ID>` | Deletes a GPG key from the current trust zone. <br> 从当前信任区删除一个GPG密钥。 |
| | `--list-zones` | Lists all available trust zones. <br> 列出所有可用的信任区。 |
| | `--create-zone <name>` | Creates a new, empty trust zone. <br> 创建一个新的、空的信任区。 |
| | `--switch-zone <name>` | Switches the active trust zone. <br> 切换到指定的信任区。 |

---

### Advanced & Maintainer Tools / 高级及维护者工具

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `adopt` | `<pkg_name> <version>` | Registers a set of user-specified files as a package in the database. Prompts for a manifest file. <br> 将一组用户指定的文件注册为一个软件包到数据库中。会提示输入一个清单文件。 |
| | `[--slot=SLOT]` | (Optional) The slot for the package. Defaults to '0'. <br> (可选) 软件包的槽位。默认为 '0'。 |
| `rollback` | `<pkg> <version>` | Rolls back a package to a specific older version, using a cached binary or rebuilding from git history. <br> 将一个软件包回滚到指定的旧版本，会使用缓存的二进制包或从git历史记录重新构建。 |
| `create-delta` | `<pkg> <old_ver> <new_ver>` | For repository maintainers. Creates a delta patch file between two binary packages. <br> 供仓库维护者使用。在两个二进制软件包之间创建一个增量补丁文件。 |
| `delta-update` | `<pkg>` | Manually triggers a delta update attempt for a package. `upgrade` may do this automatically. <br> 为一个软件包手动触发一次增量更新尝试。`upgrade` 命令可能会自动执行此操作。 |
| `clean` | | Cleans up cached files to free up disk space. <br> 清理缓存文件以释放磁盘空间。 |
| | `[--sources]` | Target the source code cache for cleaning. <br> 指定清理源码缓存。 |
| | `[--binaries]` | Target the binary package cache for cleaning. <br> 指定清理二进制包缓存。 |
| | `[--tmp]` | **[NEW]** Target temporary build/install directories for cleaning. <br> **[新增]** 指定清理临时构建/安装目录。 |
| | `[--all]` | Target all of the above. Default if no target is specified. <br> 指定以上所有。如果未指定目标，则为默认项。 |
| | `[--force \| -y]` | Perform deletion without confirmation. Default is a dry-run. <br> 无需确认直接执行删除。默认为演习（dry-run）模式。 |
| | `[--older-than DAYS]` | Only clean files older than the specified number of days. <br> 只清理比指定天数更老的文件。 |
| | `[--keep-last N]` | *[Binaries only]* Keep the last N versions of each package, even if they are orphans. <br> *[仅用于二进制包]* 为每个软件包保留最近的N个版本，即使它们是孤儿包。 |
| `manage` | `--sync-from <pm>` | Syncs package database from an external (host) package manager. `<pm>` can be `apt`, `pacman`, `dnf`, `portage`, `pip`, `npm`, `xbps`, `zypper`, `pkgsrc`. <br> 从一个外部（主机）包管理器同步软件包数据库。`<pm>`可以是`apt`、`pacman`、`dnf`、`portage`、`pip`、`npm`、`xbps`、`zypper`、`pkgsrc`。 |
| | `--list-external` | Lists locally known external package databases. <br> 列出本地已知的外部软件包数据库。 |
| | `--adopt-from <pm> <pattern>` | 'Adopts' a package from an external PM into the NxPKG database. <br> 将一个来自外部包管理器的软件包“收养”到NxPKG数据库中。 |

---

### System Initialization / 系统初始化

| Command / 命令 | Parameters / 参数 | Description / 说明 |
| :--- | :--- | :--- |
| `init` | | Initializes the entire NxPKG system structure, configuration files, cryptographic and TLS identity on a new machine. Must be run as the first command. <br> 在一台新机器上初始化整个NxPKG的系统结构、配置文件、加密身份和TLS身份。必须作为第一个命令运行。 |