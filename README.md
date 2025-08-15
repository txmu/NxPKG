# NxPKG - The Next-Generation Meta Package Manager

[**简体中文 (`README_zh.md`)**](./README_zh.md)

[**A Day With NxPKG(`a_day_with_nxpkg.md`)**](./a_day_with_nxpkg.md)


**NxPKG (Project Chimera) is a personal vision and implementation of a next-generation package manager, boldly fusing declarative system management, meta-distro capabilities, P2P content distribution, and blockchain consensus.**

The entire system is deliberately implemented as a single, self-contained, **9,000+ line shell script**, with inlined Python for secure networking tasks. It is both a functional prototype and an exploration of what's possible with the humblest of tools.

---

## Core Philosophy

I was deeply inspired by [NixOS](https://nixos.org/) & [GuixSD](https://guix.gnu.org/) (for their declarative nature), [Git](https://git-scm.com/) (for its content-addressable model), [Bedrock Linux](https://bedrocklinux.org/) & [Distrobox](https://github.com/89luca89/distrobox) (for their meta-PM models), and Proof-of-Stake blockchains (for decentralized consensus).

NxPKG is an attempt to create a system that weaves these ideas together to solve package management's greatest challenges: **supply chain security**, **repository centralization**, and **system state "rot"**.

## ✨ Key Features

### 🛡️ Decentralization & Security
*   **Hybrid Trust Model:** A defense-in-depth security core. It combines a GPG-based "Trust Zone" (a curated list of developer keys) for absolute authority with a Proof-of-Stake blockchain for decentralized consensus. By default, valid GPG signatures from the Trust Zone are mandatory.
*   **Fully Decentralized P2P Network:** Everything from package binaries, source code, and even forum content is distributed over a Kademlia-based DHT. All node-to-node communication is encrypted via HTTPS with peer certificate pinning to prevent MITM attacks.
*   **Build Sandboxing:** All package builds happen inside a `bubblewrap` sandbox with no access to your host filesystem or network, preventing malicious build scripts.

### declar Declarative & Meta-Management
*   **Declarative System State:** Manage your entire system via a simple `world` text file. This file is the single source of truth for what should be on your system.
*   **True Meta-Management (The Strata System):** You can now declare isolated environments managed by `apt`, `pacman`, or `dnf` *directly in your world file*. For example, you can state that your Arch host should have a Debian environment with `build-essential` installed.
*   **Atomic, Self-Healing Rebuilds:** The `nxpkg rebuild --prune` command is now the heart of the system. It reads your `world` file and makes it reality:
    *   It installs any missing NxPKG packages and their dependencies.
    *   It **creates** any missing Strata environments (`apt`, `pacman`, etc.).
    *   It **ensures** that specified packages are installed *inside* those Strata.
    *   The `--prune` flag automatically removes anything not declared in your `world` file, including entire Strata environments, keeping your system perfectly clean.

### 🌐 Community & Tooling
*   **Built-in Decentralized Forum:** A censorship-resistant forum is part of the package manager. Post metadata is timestamped on the blockchain, and content is distributed over P2P. It now supports searching, and exporting/importing entire topics as portable archives.

---

## 🚀 The Declarative Workflow: From Exploration to Persistence

The new `rebuild` system enables a powerful workflow, moving seamlessly from exploration to a persistent, reproducible state.

1.  **Explore:** Quickly spin up a temporary Debian environment for a project.
    ```bash
    sudo nxpkg strata --create debian-dev apt
    ```

2.  **Work:** Freely install whatever you need inside it. Your manual changes are safe.
    ```bash
    sudo nxpkg strata -e debian-dev apt install -y nodejs redis-tools
    ```

3.  **Promote:** Happy with the setup? Promote it to your system's official state with one command. This automatically adds the Strata and all its packages to your `world` file.
    ```bash
    sudo nxpkg strata --promote debian-dev
    ```

4.  **Manage:** From now on, `sudo nxpkg rebuild` will ensure this exact environment exists on any of your machines. If you delete the lines from the `world` file, `rebuild --prune` will automatically and cleanly remove the entire environment.

---

## ⚡️ Quick Start

### 1. Dependencies

NxPKG relies on a set of common command-line tools. Please ensure they are installed.

**Core Dependencies:**
`curl`, `git`, `tar`, `sha256sum`, `make`, `gcc`, `openssl`, `awk`, `sqlite3`, `python3`, `bc`, `jq`, `xxd` and the `cryptography` Python library (`pip install cryptography`).

**Optional Dependencies (for enhanced features):**
`bubblewrap` (highly recommended for sandboxing), `debootstrap`, `pacstrap`, `xdelta3`, `bsdiff`, `equery` (from app-portage/gentoolkit, for managing Portage).

To enable the `create-delta` and `delta-update` features, please install either `xdelta3` (recommended) or `bsdiff`.

### 2. Installation

As NxPKG is a single-file script, installation is trivial:

```bash
# Download the script
curl -o nxpkg.sh https://raw.githubusercontent.com/txmu/nxpkg/main/nxpkg.sh

# Move it into your PATH
sudo mv nxpkg.sh /usr/local/bin/nxpkg

# Make it executable
sudo chmod +x /usr/local/bin/nxpkg
```

### 3. System Initialization

On first run, you need to initialize the NxPKG system structure and identity:
```bash
sudo nxpkg init
```
This command creates all necessary directories, configuration files, your personal cryptographic identity, and the genesis block for the blockchain.

### 4. Your First Steps

```bash
# 1. Synchronize repository metadata
sudo nxpkg sync

# 2. Search for a package
nxpkg search hello-world

# 3. Build and install the package
sudo nxpkg install app-misc/hello-world

# 4. Run it!
hello
```

---

## 📚 Command Reference

For a complete list of commands and their parameters, please see `all_commands.md` or run `nxpkg help <command>`.

<details>
<summary><b>Expand to see a quick reference...</b></summary>

*   **Core:** `install`, `remove`, `upgrade`, `autoremove`, `search`, `info`, `owns`
*   **Declarative:** `rebuild [--prune] [--dry-run]`
*   **Build:** `build [--canary] <pkg>`
*   **Strata:** `strata --create`, `strata --list`, `strata -e`, `strata --destroy`, `strata --export-pkgs`, `strata --promote`
*   **Forum:** `forum sync`, `forum list`, `forum show`, `forum search`, `forum new-topic`, `forum post`, `forum export`, `forum import`
*   **Security:** `key --list`, `key --import`, `key --switch-zone`
*   **Tools:** `clean`, `manage`, `rollback`, `create-delta`

</details>

---

## ⚠️ Project Status

*   **Experimental:** NxPKG is currently a **Proof-of-Concept**. Please do not use it in any critical production environment.
*   **A Learning Journey:** This project has been an incredible personal journey into system design, network security, and distributed systems.
*   **Performance:** Performance is a known bottleneck due to the shell-based nature of the script. If the architecture proves valuable, core components could be rewritten in a more performant language like Go or Rust in the future.

---

## 🛠️ A Look Under the Hood: Architectural Insights for Watchers

For those interested in the design choices and trade-offs, here are a few key architectural points:

*   **Python Backend Dependency Callback:** The Python-based P2P servers need to verify message signatures, requiring access to the main database. The current implementation uses a secure but costly callback: the Python server executes `nxpkg.sh` as a subprocess to query for keys. This ensures logical consistency by reusing the main script's functions at the cost of `fork/exec` overhead. For a prototype, this is a robust and acceptable solution.

*   **Granularity of the Global Lock:** NxPKG employs a single, global lock file for almost all state-modifying operations (`install`, `build`, `sync`). This "big kernel lock" approach is a deliberate design choice prioritizing **simplicity and safety** over concurrency. It completely prevents a vast class of subtle race conditions that could otherwise corrupt the system state.

*   **Error Recovery and Atomicity on FHS:** The project makes a best effort towards transactional operations (e.g., in blockchain reorganization). However, achieving true atomicity for package installation on a standard **Filesystem Hierarchy Standard (FHS)** system is fundamentally harder than on systems like NixOS (which installs to immutable paths). NxPKG acknowledges this limitation. While it cannot easily replicate NixOS's atomic model, its declarative `rebuild` command provides a powerful mechanism for **convergent recovery**: simply run the command again, and it will attempt to bring the system back to the desired state.

---

## 🤝 How to Contribute

Feedback of all kinds is welcome! If you have ideas, suggestions, or find a bug, please feel free to open an [Issue](https://github.com/txmu/nxpkg/issues). The collision of ideas is just as valuable as the improvement of code. For those interested in building a testing framework, please see `fortesters.md`.

## A Note from the Author

**I am a high school student in China, studying humanities (liberal arts)**. I designed the entire system architecture myself and, with the help of AI for boilerplate and specific implementations, put this v6.2.0 (the 32nd version) release together in **only 48 hours** between homework and sleep. I know that building this in a shell script is unconventional, but this was an incredible learning experience about system design, security, and the power of combining human architectural vision with AI for rapid implementation.

Thanks for reading!

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## Postscript

For more in-depth information, please see the following documents:
*   [**Command Reference (`all_commands.md`)**](./all_commands.md): A detailed reference for every command and its parameters.
*   [**Mod System Details (`mod_details.md`)**](./mod_details.md): An analysis of the Mod system's scope, permissions, and security model.
*   [**A Note on Testing (`for_testers.md`)**](./for_testers.md): A roadmap for building a comprehensive test harness for NxPKG.

---

如需更深入的信息，请查阅以下文档：
*   [**命令参考 (`all_commands.md`)**](./all_commands.md): 包含每个命令及其参数的详细参考手册。
*   [**Mod 系统详解 (`mod_details.md`)**](./mod_details.md): 对 Mod 系统的适用范围、权限和安全模型的分析。
*   [**关于测试的说明 (`for_testers.md`)**](./for_testers.md): 为 NxPKG 构建一个全面测试框架的路线图。
