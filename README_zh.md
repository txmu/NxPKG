# NxPKG - 下一代元包管理器

[**English (`README.md`)**](./README.md)

[**某NxPKG用户的一天(`a_day_with_nxpkg.md`)**](./a_day_with_nxpkg.md)

**NxPKG (项目代号：Chimera) 是一个对下一代包管理器的个人构想与实现，它将声明式系统管理、元发行版能力、P2P 内容分发和区块链共识机制大胆地融合在一起。**

整个系统被有意地实现为一个**自包含的、超过9000行的 Shell 脚本**，并内联了 Python 来处理安全的网络任务。它既是一个功能完备的原型，也是对传统工具可能性边界的一次探索。

---

## 核心哲学

我深受 [NixOS](https://nixos.org/) 和 [GuixSD](https://guix.gnu.org/)（声明式特性）、[Git](https://git-scm.com/)（内容可寻址模型）、[Bedrock Linux](https://bedrocklinux.org/) 和 [Distrobox](https://github.com/89luca89/distrobox)（元包管理器模型）以及权益证明（PoS）区块链（去中心化共识）的启发。

NxPKG 旨在创建一个系统，将这些伟大的思想结合起来，以解决包管理领域中最棘手的几个挑战：**供应链安全**、**仓库中心化**和**系统状态“腐烂”**。

## ✨ 核心特性

### 🛡️ 去中心化与安全
*   **混合信任模型 (Hybrid Trust Model):** 结合了基于 GPG 的“信任区”（一组由管理员定义的权威开发者密钥）和用于去中心化共识的 PoS 区块链，构成了深度防御的核心。默认情况下，来自信任区的有效 GPG 签名是强制性的。
*   **完全去中心化的P2P网络 (Fully Decentralized P2P Network):** 从二进制包、源码、到论坛内容，一切都通过基于 Kademlia 的 DHT 网络分发。所有节点间通信都通过 HTTPS 加密，并使用对等证书锁定（Peer Certificate Pinning）来防御中间人攻击。
*   **构建沙箱 (Build Sandboxing):** 所有软件包都在 `bubblewrap` 沙箱中构建，无法访问主机文件系统或网络，有效阻止恶意构建脚本。

### declar 声明式与元管理
*   **声明式系统状态 (Declarative System State):** 通过一个简单的 `world` 文本文件来管理你的整个系统。这个文件是系统应有状态的唯一事实来源。
*   **真正的元管理 (The Strata System):** 你现在可以直接在 `world` 文件中声明由 `apt`、`pacman` 或 `dnf` 等管理的隔离环境。例如，你可以声明你的 Arch 主机应该拥有一个安装了 `build-essential` 的 Debian 环境。
*   **原子化的自我修复式重建 (Atomic Rebuilds):** `nxpkg rebuild --prune` 是系统的核心命令。它会读取你的 `world` 文件，并将其变为现实：
    *   安装任何缺失的 NxPKG 包及其依赖。
    *   **创建**任何缺失的 Strata 环境 (`apt`, `pacman` 等)。
    *   **确保**指定的软件包被安装在这些 Strata 环境**内部**。
    *   `--prune` 标志会自动移除任何未在 `world` 文件中声明的内容（包括整个 Strata 环境），保持你的系统绝对干净。

### 🌐 社区与工具
*   **内置去中心化论坛 (Built-in Decentralized Forum):** 一个抗审查的论坛是包管理器的一部分。帖子元数据在区块链上加盖时间戳，内容通过 P2P 分发。现在它支持搜索，以及将整个话题导出/导入为可移植的压缩包。

---

## 🚀 声明式工作流：从探索到持久化

新的 `rebuild` 系统带来了一个强大的工作流，可以无缝地从探索性操作过渡到一个持久的、可复现的系统状态。

1.  **探索 (Explore):** 为一个项目快速启动一个临时的 Debian 环境。
    ```bash
    sudo nxpkg strata --create debian-dev apt
    ```

2.  **工作 (Work):** 在其中自由地安装你需要的任何东西。你的手动更改是安全的。
    ```bash
    sudo nxpkg strata -e debian-dev apt install -y nodejs redis-tools
    ```

3.  **提升 (Promote):** 对这个环境感到满意？用一个命令将它“提升”为你系统的官方状态。这会自动将该 Strata 及其内部安装的所有包的声明添加到你的 `world` 文件中。
    ```bash
    sudo nxpkg strata --promote debian-dev
    ```

4.  **管理 (Manage):** 从现在开始，`sudo nxpkg rebuild` 将确保这个精确的环境存在于你的任何一台机器上。如果你从 `world` 文件中删除了相关行，`rebuild --prune` 将会自动并干净地移除整个环境。

---

## ⚡️ 快速开始

### 1. 依赖项

NxPKG 依赖一些常见的命令行工具。请确保它们已安装：

**核心依赖:**
`curl`, `git`, `tar`, `sha256sum`, `make`, `gcc`, `openssl`, `awk`, `sqlite3`, `python3`, `bc`, `jq`, `xxd` 以及 `cryptography` Python 库 (`pip install cryptography`)。

**可选依赖 (增强功能):**
`bubblewrap` (强烈推荐，用于沙箱), `debootstrap`, `pacstrap`, `xdelta3`, `bsdiff`, `equery` (来自app-portage/gentoolkit, 用于manage Portage)。

要启用 `create-delta` 和 `delta-update` 功能，请安装 `xdelta3` (推荐) 或 `bsdiff`。

### 2. 安装

由于 NxPKG 是一个单文件脚本，安装非常简单：

```bash
# 下载脚本
curl -o nxpkg.sh https://raw.githubusercontent.com/txmu/nxpkg/main/nxpkg.sh

# 移动到你的 PATH 中
sudo mv nxpkg.sh /usr/local/bin/nxpkg

# 设为可执行
sudo chmod +x /usr/local/bin/nxpkg
```

### 3. 初始化系统

第一次运行时，你需要初始化 NxPKG 的系统结构和身份：
```bash
sudo nxpkg init
```
这个命令会创建所有必要的目录、配置文件、你的个人加密身份和创世区块。

### 4. 你的第一步

```bash
# 1. 同步仓库元数据
sudo nxpkg sync

# 2. 搜索一个包
nxpkg search hello-world

# 3. 构建并安装这个包
sudo nxpkg install app-misc/hello-world

# 4. 运行它！
hello
```

---

## 📚 命令参考

请查阅 `all_commands.md` 或使用 `nxpkg help <command>` 获取更详细的帮助。

<details>
<summary><b>点击展开快速参考...</b></summary>

*   **核心包管理:** `install`, `remove`, `upgrade`, `autoremove`, `search`, `info`, `owns`
*   **声明式管理:** `rebuild [--prune] [--dry-run]`
*   **构建系统:** `build [--canary] <pkg>`
*   **Strata 系统:** `strata --create`, `strata --list`, `strata -e`, `strata --destroy`, `strata --export-pkgs`, `strata --promote`
*   **去中心化论坛:** `forum sync`, `forum list`, `forum show`, `forum search`, `forum new-topic`, `forum post`, `forum export`, `forum import`
*   **安全与信任:** `key --list`, `key --import`, `key --switch-zone`
*   **高级工具:** `clean`, `manage`, `rollback`, `create-delta`

</details>

---

## ⚠️ 项目状态

*   **实验性:** NxPKG 目前是一个**概念验证 (Proof-of-Concept)** 项目。请不要在任何关键的生产环境中使用它。
*   **学习过程:** 这个项目是我个人学习系统设计、网络安全和分布式系统的宝贵经历。
*   **性能:** 由于其基于 Shell，性能会是瓶颈。如果这个架构被证明有价值，未来可以用 Go 或 Rust 等更高效的语言重写核心组件。

---

## 🛠️ 深入底层：为观察者准备的架构洞察

对于那些对设计选择和权衡感兴趣的人，这里有几个关键的架构点：

*   **Python 后端依赖回调 (Python Backend Dependency Callback):** 基于 Python 的 P2P 服务器需要验证消息签名，这要求访问主数据库。当前的实现使用了一种安全但开销较高的回调机制：Python 服务器将 `nxpkg.sh` 作为一个子进程来执行，以查询密钥。这通过复用主脚本的函数来确保逻辑的一致性，但代价是 `fork/exec` 的开销。对于一个原型来说，这是一个健壮且可接受的解决方案。

*   **全局锁的粒度 (Granularity of the Global Lock):** NxPKG 对几乎所有修改状态的操作（`install`, `build`, `sync` 等）都使用了一个单一的全局锁文件。这种“大内核锁”的方式是一个深思熟虑的设计选择，它将**简洁性和安全性**置于并发性之上。它完全避免了一大类可能破坏系统状态的、非常微妙的竞争条件。

*   **错误恢复与在FHS上的原子性 (Error Recovery and Atomicity on FHS):** 本项目尽力实现了事务性操作（例如在区块链重组中）。然而，在一个标准的**文件系统层次结构标准（FHS）**的系统上，为软件包安装实现真正的原子性，从根本上说比在 NixOS 这样的系统上要困难得多（NixOS安装到不可变路径）。NxPKG 承认这个局限性。虽然它无法轻易地复制 NixOS 的原子模型，但其声明式的 `rebuild` 命令提供了一个强大的**收敛式恢复**机制：只需再次运行该命令，它就会尝试将系统带回到 `world` 文件中定义的目标状态。

---

## 🤝 如何贡献

欢迎各种形式的反馈！如果你有任何想法、建议或发现了 Bug，请随时提出 [Issue](https://github.com/txmu/nxpkg/issues)。思想的碰撞和代码的改进同样重要。对于有兴趣构建测试框架的朋友，请参考 `fortesters.md`。

## 作者的话

**我是一名学习文科的中国高中生**。我独立设计了整个系统架构，并在课业与睡眠的夹缝中，借助 AI 辅助（用于生成样板代码和实现定义明确的函数）**在48小时内**完成了这个 v6.2.0 （第32个版本）版本的实现。我知道用 Shell 脚本来构建它有些非主流，但这对我来说是一次关于系统设计、安全以及如何将人类的架构构想与AI的快速实现能力相结合的宝贵学习经历。

感谢你的阅读！

## 📄 许可证

本项目采用 [MIT License](LICENSE)。

## 后记

For more in-depth information, please see the following documents:
*   [**Command Reference (`all_commands.md`)**](./all_commands.md): A detailed reference for every command and its parameters.
*   [**Mod System Details (`mod_details.md`)**](./mod_details.md): An analysis of the Mod system's scope, permissions, and security model.
*   [**A Note on Testing (`for_testers.md`)**](./for_testers.md): A roadmap for building a comprehensive test harness for NxPKG.

---

如需更深入的信息，请查阅以下文档：
*   [**命令参考 (`all_commands.md`)**](./all_commands.md): 包含每个命令及其参数的详细参考手册。
*   [**Mod 系统详解 (`mod_details.md`)**](./mod_details.md): 对 Mod 系统的适用范围、权限和安全模型的分析。
*   [**关于测试的说明 (`for_testers.md`)**](./for_testers.md): 为 NxPKG 构建一个全面测试框架的路线图。
