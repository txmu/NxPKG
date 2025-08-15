# A Day in the Life of an NxPKG User
# 一个NxPKG用户的一天

Meet Alex. Alex is a developer who loves powerful tools and a clean system. They just set up a new machine and are ready to shape it using NxPKG. Let's follow their journey.

认识一下 Alex。Alex 是一名热爱强大工具和干净系统的开发者。他们刚配置好一台新机器，准备用 NxPKG 来打造自己的工作环境。让我们跟随 Alex 的脚步，看看他们的一天。

---

### ☕ 早上 9:00 - 系统同步与重建 (System Sync & Rebuild)

Alex starts their day with a coffee and a simple command. They've just cloned their dotfiles, which includes their master `world` file, into `/etc/nxpkg/`. Time to make this new machine feel like home.

Alex 用一杯咖啡和一个简单的命令开始新的一天。他们刚刚把包含主 `world` 文件的 dotfiles 克隆到了 `/etc/nxpkg/` 目录下。是时候让这台新机器变得像家一样了。

```bash
# First, let's see what the plan is.
# 首先，看看计划是什么。
sudo nxpkg rebuild --prune --dry-run
```

The output shows a plan: install `vim`, `git`, `ripgrep`, and create a `debian-base` Strata environment that Alex uses for web development. It also plans to remove `nano`, which came with the base OS but isn't in Alex's `world` file. Perfect.

输出显示了一个计划：安装 `vim`, `git`, `ripgrep`，并创建一个 Alex 用于 Web 开发的 `debian-base` Strata 环境。计划还包括移除 `nano`，这是操作系统自带但不在 Alex 的 `world` 文件里的包。完美。

```bash
# Looks good. Let's make it happen.
# 看起来不错，开始执行。
sudo nxpkg rebuild --prune -y
```

NxPKG gets to work, installing packages and setting up the Strata. A few minutes later, Alex's core environment is perfectly replicated.

NxPKG 开始工作，安装软件包并配置 Strata。几分钟后，Alex 的核心环境被完美地复刻了出来。

---

### 🕙 上午 10:30 - 处理数据的新需求 (A New Need for Data Munging)

Alex gets a task that involves parsing a huge JSON file. `sed` and `awk` are great, but `jq` would be perfect. Is it in the NxPKG repos?

Alex 接到了一个需要解析巨大 JSON 文件的任务。`sed` 和 `awk` 固然不错，但 `jq` 才是最完美的工具。NxPKG 的仓库里有它吗？

```bash
# Let's search for it.
# 搜索一下。
nxpkg search jq
```

> ```
> app-misc/jq
>   Description: Command-line JSON processor
>   Status: Available
> ```

Excellent. Time to install it. Alex also uses `nxpkg info` to quickly check its dependencies.

太棒了。是时候安装它了。Alex 还顺手用 `nxpkg info` 快速看了一眼它的依赖。

```bash
nxpkg info app-misc/jq
sudo nxpkg install app-misc/jq
```

NxPKG downloads, builds, and installs `jq`. Now, Alex wants this tool to be part of their standard setup on all machines. Instead of just installing it, they add it to their `world` file.

NxPKG 下载、构建并安装了 `jq`。现在，Alex 希望这个工具成为他们所有机器上标准配置的一部分。所以他们不只是安装它，而是把它也加入到了 `world` 文件中。

```bash
# Add 'app-misc/jq' to /etc/nxpkg/world
# 将 'app-misc/jq' 添加到 /etc/nxpkg/world 文件中
echo "app-misc/jq" | sudo tee -a /etc/nxpkg/world
```

---

### 🕑 下午 2:00 - 探索 Strata (Strata Exploration)

Alex needs to test a Python script that requires an old version of a library, best managed by `apt`. The `debian-base` Strata is clean, so they'll create a new, temporary one for this experiment.

Alex 需要测试一个依赖某个旧版本库的 Python 脚本，这种依赖最好用 `apt` 来管理。`debian-base` Strata 环境很干净，所以他们准备为这个实验创建一个新的、临时的 Strata。

```bash
# Create a temporary Debian environment.
# 创建一个临时的 Debian 环境。
sudo nxpkg strata --create py-legacy apt

# Jump inside and install what's needed.
# 进入环境，安装所需工具。
sudo nxpkg strata -e py-legacy apt update
sudo nxpkg strata -e py-legacy apt install -y python3-pip python3-dev
sudo nxpkg strata -e py-legacy pip install legacy-lib==1.2.3
```

After some testing, Alex realizes this setup is actually quite useful and will be needed for a long-term project. Time to promote it from a temporary playground to a declarative part of the system.

经过一番测试，Alex 发现这个环境其实非常有用，并且一个长期项目也需要它。是时候把它从一个临时“沙盒”提升为系统的声明式状态的一部分了。

```bash
# Promote the strata. This automatically updates the world file!
# 提升这个 strata。这会自动更新 world 文件！
sudo nxpkg strata --promote py-legacy
```

Alex checks their `world` file. New lines have been added automatically:
Alex 检查了一下 `world` 文件，发现被自动加入了新的几行：

> ```
> # Promoted Strata: py-legacy (on ...)
> strata:py-legacy:apt
> strata-pkg:py-legacy:python3-pip
> strata-pkg:py-legacy:python3-dev
> ... (and other dependencies) ...
> ```

Now, running `nxpkg rebuild` on any machine will create this exact environment. Magic.

现在，在任何机器上运行 `nxpkg rebuild` 都会创建出这个一模一样的环境。太神奇了。

---

### 🕓 下午 4:00 - 打包一个新工具 (Packaging a New Tool)

Alex discovers a cool new terminal UI for Git called `lazygit` and wants to package it for NxPKG.

Alex 发现了一个超酷的 Git 终端 UI 工具，名叫 `lazygit`，想把它打包进 NxPKG。

```bash
# 1. Get the source URL and try to auto-generate a .build file.
# 1. 获取源码 URL，尝试自动生成一个 .build 文件。
nxpkg gen-build https://github.com/jesseduffield/lazygit/archive/v0.40.2.tar.gz > lazygit.build
```

The generated file is a good starting point. Alex opens `lazygit.build` and makes some edits: sets a proper `pkgdesc`, adds `golang` to `makedepends`, and adjusts the `build()` function to use Go's build system.

自动生成的文件是个不错的起点。Alex 打开 `lazygit.build` 并做了一些修改：设置了正确的 `pkgdesc`，在 `makedepends` 中加入了 `golang`，并调整了 `build()` 函数来使用 Go 的构建系统。

```bash
# 2. Time to build it! The --canary flag is great for test builds.
# 2. 开始构建！--canary 标志非常适合用于测试构建。
sudo nxpkg build --canary dev-util/lazygit
```

The build succeeds, creating `lazygit-0.40.2-canary-0-x86_64.nxpkg.tar.zst`. Alex installs and tests it. It works great. Now, they want to share it with the community.

构建成功了，生成了 `lazygit-0.40.2-canary-0-x86_64.nxpkg.tar.zst`。Alex 安装并测试了它，一切正常。现在，他们想把它分享给社区。

```bash
# 3. Share the .build file on the decentralized forum.
# 3. 在去中心化论坛上分享这个 .build 文件。
sudo nxpkg forum new-topic --title "[NEW PKG] dev-util/lazygit-0.40.2" \
    --body "Here is a build file for the awesome git TUI, lazygit. Enjoy!" \
    --attach /path/to/repo/dev-util/lazygit/lazygit.build
```

---

### 🕕 晚上 6:00 - 系统清理 (System Cleanup)

The workday is done. Alex decides to free up some space by cleaning up old caches.

一天的工作结束了。Alex 决定清理一下旧的缓存来释放些磁盘空间。

```bash
# First, a dry-run to see what will be deleted.
# 首先，演习一下，看看哪些东西会被删除。
sudo nxpkg clean --all

# It lists some old binary packages and the source for nano. Looks safe.
# 列表显示了一些旧的二进制包和 nano 的源码。看起来很安全。

# Let's do it for real.
# 来真的吧。
sudo nxpkg clean --all --force
```

With their system clean, synchronized, and perfectly tailored to their needs, Alex closes the terminal. It was a productive day with NxPKG.

随着系统变得干净、同步，并完美地满足了自己的需求，Alex 关闭了终端。这是使用 NxPKG 高效的一天。

---

Note: The above packages did not exist at the time of publication of this document, but the functional infrastructure supporting their existence is already relatively complete.

备注：以上各个包在本文件发布之时尚不存在，然而支撑其存在的功能基础设施已经较为完善。
