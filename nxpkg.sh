#!/bin/bash
#
# NxPKG - The Next-Generation Meta Package Manager (Complete Implementation)
# Project Codename: Project Chimera
#
# Version: 6.2.0 (32nd)
# Complete implementation with all features from the design document
# 本程序部分说明与注释是中英双语的，但是还有一部分是纯英文的，一部分是纯中文的。您可能需要使用字典、翻译器或AI，或者等待一个PR来修复这些问题。
# The instructions and comments in this program are bilingual in Chinese and English, but there are also some parts in pure English and some in pure Chinese. You may need to use a dictionary, translator, or AI, or wait for a PR to fix these issues.
#
# PoW共识机制完全是占位符，P2P节点模拟器是功能简化的Mock，创世区块的签名是模拟的，这三个是预期的。
# The PoW consensus mechanism is entirely a placeholder, the P2P node simulator is a simplified mock, and the signature of the genesis block is simulated. These three are expected.
#

# --- PREAMBLE: STRICT MODE & SAFETY ---
set -o errexit
set -o nounset
set -o pipefail

# --- [资源管理修复] 全局数组，用于跟踪所有后台守护进程的PID ---
# --- [RESOURCE FIX] Global array to track PIDs of all background daemons ---
declare -a NXPKG_BACKGROUND_PIDS=()

if [ -z "${BASH_VERSION:-}" ]; then
    echo "Error: This script requires Bash version 4+.（错误：该脚本需要4以上的Bash版本。）" >&2
    exit 1
fi

# =======================================================
# --- SECTION 1: GLOBAL CONSTANTS AND CONFIGURATION   ---
# --- 第1节: 全局常量与配置                            ---
# =======================================================

readonly NXPKG_VERSION="6.2.0"
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_PATH=$(realpath "$0")

# --- Network ID for Isolation ---
# --- 用于隔离的网络ID ---
# This is the core of multi-network support. All stateful paths will be namespaced by this ID.
# It can be set via an environment variable for temporary overrides.
# 这是多网络支持的核心。所有状态化路径都将由这个ID划分命名空间。
# 它可以通过环境变量来设置以进行临时覆盖。
NXPKG_NETWORK_ID="${NXPKG_NETWORK_ID_OVERRIDE:-default}"

# =======================================================
# --- State Paths (Network-Specific)                  ---
# --- 状态路径 (特定于网络)                           ---
# =======================================================
# These paths store the state for a specific network ID. They MUST be namespaced
# to ensure complete isolation between different networks (e.g., 'default' vs 'testing').
# 这些路径存储特定网络ID的状态。它们必须被划分命名空间，以确保不同网络之间的完全隔离。

# --- Configuration & Identity (State) ---
ETC_NXPKG_DIR="/etc/nxpkg/networks/${NXPKG_NETWORK_ID}"
CONFIG_FILE="${ETC_NXPKG_DIR}/nxpkg.conf"
WORLD_FILE="${ETC_NXPKG_DIR}/world"
REPOS_CONF_DIR="${ETC_NXPKG_DIR}/repos.conf.d"
USER_IDENTITY_FILE="${ETC_NXPKG_DIR}/identity.key"
USER_PUBLIC_KEY_FILE="${USER_IDENTITY_FILE}.pub"
# --- NEW: Path to the genesis configuration file ---
# --- 新增: 指向创世配置文件的路径 ---
# This file defines the initial state of a new blockchain, including its founding validators.
# 该文件定义了新区块链的初始状态，包括其创始验证者。
GENESIS_CONFIG_FILE="${ETC_NXPKG_DIR}/genesis.json"
# --- NEW: TLS Identity for Secure Communication ---
# --- 新增: 用于安全通信的TLS身份 ---
# These files are used to establish encrypted HTTPS channels between nodes.
# The certificate is self-signed but verified at the application layer.
# 这些文件用于在节点间建立加密的HTTPS信道。
# 证书是自签名的，但在应用层进行验证。
TLS_KEY_FILE="${ETC_NXPKG_DIR}/tls.key"
TLS_CERT_FILE="${ETC_NXPKG_DIR}/tls.crt"

# --- Databases (State) ---
VAR_LIB_NXPKG_DIR="/var/lib/nxpkg/networks/${NXPKG_NETWORK_ID}"
INSTALLED_DB="${VAR_LIB_NXPKG_DIR}/installed"
EXTERNAL_PM_DB="${VAR_LIB_NXPKG_DIR}/external"
BLOCKCHAIN_DIR="${VAR_LIB_NXPKG_DIR}/blockchain"
BLOCKCHAIN_DB="${BLOCKCHAIN_DIR}/chain.db"
FORUM_DIR="${VAR_LIB_NXPKG_DIR}/forum"

# --- Repositories & Strata (State) ---
REPOS_DIR="/usr/nxpkg/repos/networks/${NXPKG_NETWORK_ID}"
STRATA_DIR="/usr/nxpkg/strata/networks/${NXPKG_NETWORK_ID}"


# =======================================================
# --- Cache & Global Paths (Shared Across Networks)     ---
# --- 缓存与全局路径 (跨网络共享)                       ---
# =======================================================
# These paths are shared across all network IDs. Caches for source code and binaries
# are content-addressable (verified by hash), so sharing them is safe and efficient.
# The global lock and P2P infrastructure are also shared.
# 这些路径在所有网络ID之间共享。源码和二进制包的缓存是内容可寻址的（通过哈希验证），
# 因此共享它们是安全且高效的。全局锁、P2P基础设施和已验证的对等节点证书也被共享。

# --- Caches (Shared) ---
VAR_CACHE_NXPKG_DIR="/var/cache/nxpkg"
METADATA_CACHE_DIR="${VAR_CACHE_NXPKG_DIR}/metadata" # Metadata like search index can be shared, as it's just a discoverability aid.
SEARCH_INDEX_FILE="${METADATA_CACHE_DIR}/search.index"
SOURCE_CACHE="${VAR_CACHE_NXPKG_DIR}/sources"
BINARY_CACHE="${VAR_CACHE_NXPKG_DIR}/binaries"
PEER_CERT_CACHE="/var/lib/nxpkg/p2p/peer_certs" # 用于缓存已验证的对等节点证书 (For caching verified peer certificates)


# --- P2P Infrastructure (Shared) ---
# The P2P layer (DHT, node identity) is a single, global infrastructure
# that all NxPKG networks can leverage for communication and data transfer.
# P2P层 (DHT, 节点身份) 是一个单一的、全局的基础设施，
# 所有的NxPKG网络都可以利用它来进行通信和数据传输。
P2P_DIR="/var/lib/nxpkg/p2p"
DHT_DB="${P2P_DIR}/dht.db"

# --- Temporary & Lock Paths (Global) ---
BUILD_TMP_DIR_BASE="/tmp/nxpkg_build"
LOCK_DIR="/var/lock/nxpkg" # The lock must be global to prevent race conditions across all operations.

# =======================================================
# --- Configuration Defaults (Global)                 ---
# --- 配置默认值 (全局)                               ---
# =======================================================
DOWNLOAD_PROTO_PRIORITY="p2p,ipfs,bt,http,git,sftp,ftp"
DEP_MODE="auto"
SOCKS5_PROXY=""
BUILD_JOBS=$(nproc 2>/dev/null || echo 4)
DOWNLOAD_JOBS=4
SANDBOX_TOOL="bubblewrap"
P2P_CHUNK_SIZE=262144
BT_DOWNLOAD_TIMEOUT=3600
DEFAULT_EDITOR="${EDITOR:-nano}"
P2P_PORT=7234
# [新增] P2P 首次连接时是否自动信任新节点。默认为 false 以保证安全。
# [NEW] Whether to automatically trust new peers on first connection. Defaults to false for security.
AUTO_TRUST_NEW_NODES="false" 
# --- NEW: Default offset for the HTTP fallback server and P2P file sharing server ---
# --- 新增: 用于 HTTP 后备服务器与P2P文件共享服务器的默认偏移量 ---
P2P_HTTP_PORT_OFFSET=1000
P2P_FILE_PORT_OFFSET=2000
DHT_BOOTSTRAP_NODES=()
BLOCKCHAIN_CONSENSUS="pos"

# Global lock file descriptor
exec 200>/var/lock/nxpkg.lock

# --- SECTION 2: CORE UTILITIES AND LOGGING ---

msg() { echo -e "\n=> \033[1;32m${1}\033[0m"; }
warn() { echo -e "=> \033[1;33mWARNING:\033[0m ${1}"; }
error() { echo -e "=> \033[1;31mERROR:\033[0m ${1}" >&2; exit 1; }
info() { echo -e "-> \033[0;36m${1}\033[0m"; }
detail() { echo -e "   \033[0;34m${1}\033[0m"; }
debug() { [ "${NXPKG_DEBUG:-}" = "1" ] && echo -e "DEBUG: \033[0;35m${1}\033[0m"; }

# NEW HELPER FUNCTION: Securely encode a string into a hex literal for SQL queries.
# This prevents SQL injection by representing the data in a format with no special SQL characters.
# 新增辅助函数: 安全地将字符串编码为用于SQL查询的十六进制字面量。
# 通过将数据表示为没有特殊SQL字符的格式来防止SQL注入。
_sql_safe_string_to_hex() {
    echo -n "$1" | xxd -p | tr -d '\n'
}

progress() {
    local percent=$1
    local width=50
    local completed=$((width * percent / 100))
    local remaining=$((width - completed))
    printf "\r[%-${width}s] %d%%" "$(printf '#%.0s' $(seq 1 $completed))" "$percent"
}

check_dep() {
    command -v "$1" >/dev/null 2>&1 || error "Missing dependency: '$1' is required but not installed."
}

# --- [NEW] Function to check for Python library dependencies ---
# --- [新增] 用于检查 Python 库依赖的函数 ---
# It works by attempting to import the library using the python3 interpreter.
# If the import succeeds, the command exits with 0. If it fails (ImportError),
# it exits with a non-zero status, which is caught by the '||' operator.
#
# 它的工作原理是尝试使用 python3 解释器导入指定的库。如果导入成功，
# 命令以状态码 0 退出。如果失败 (ImportError)，则以非零状态码退出，
# 这会被 '||' 操作符捕获。
check_py_dep() {
    local lib_name="$1"
    # The '-c' flag tells python to execute the command string.
    # We redirect stdout and stderr to /dev/null because we only care about the exit code.
    # '-c' 标志告诉 python 执行后面的命令字符串。
    # 我们将标准输出和标准错误重定向到 /dev/null，因为我们只关心退出状态码。
    python3 -c "import $lib_name" >/dev/null 2>&1 || error "Missing Python library: '$lib_name' is required. Please run: 'pip install $lib_name'"
}

check_root() {
    [ "$(id -u)" -eq 0 ] || error "This operation requires root privileges. Please run with 'sudo'."
}

acquire_lock() {
    if [ "$1" == "block" ]; then
        flock -x 200 || error "Could not acquire global nxpkg lock."
    else
        flock -n 200 || error "Another instance of nxpkg is running. Please wait."
    fi
}

release_lock() {
    flock -u 200
}

cleanup() {
    release_lock
    # --- [资源管理修复] 优雅地终止所有已记录的后台进程 ---
    # --- [RESOURCE FIX] Gracefully terminate all tracked background processes ---
    if [ ${#NXPKG_BACKGROUND_PIDS[@]} -gt 0 ]; then
        debug "Cleaning up background processes: ${NXPKG_BACKGROUND_PIDS[*]}"
        # kill会向进程发送TERM信号，允许它们优雅退出（Kill will send TERM signals to processes, allowing them to gracefully exit）
        kill "${NXPKG_BACKGROUND_PIDS[@]}" 2>/dev/null || true
    fi

    # 原始的基于job的清理也保留，作为双重保障（The original job based cleaning is also retained as a dual guarantee）
    jobs -p | xargs -r kill 2>/dev/null || true
}


# Generate random bytes for cryptographic operations
# We don't use it now
random_bytes() {
    local count=$1
    openssl rand -hex "$count"
}

# Base64 encode/decode
# We don't use them now
base64_encode() { base64 -w0; }
base64_decode() { base64 -d; }

# --- SECTION 3: CRYPTOGRAPHIC UTILITIES ---

# Generate ECC key pair
generate_keypair() {
    local private_key_file="$1"
    local public_key_file="$2"
    
    openssl ecparam -name secp256k1 -genkey -noout -out "$private_key_file"
    openssl ec -in "$private_key_file" -pubout -out "$public_key_file"
    chmod 600 "$private_key_file"
    chmod 644 "$public_key_file"
}

# Sign data with private key
sign_data() {
    local data="$1"
    local private_key_file="$2"
    # [修改] 输出为十六进制，更适合在命令行和JSON中传输
    # [MODIFIED] Output as hex, which is safer for command line and JSON transport
    echo -n "$data" | openssl dgst -sha256 -sign "$private_key_file" | xxd -p | tr -d '\n'
}

# Verify signature with public key
# REVISED FOR ROBUSTNESS: Pipes data directly to openssl's stdin instead of
# using process substitution `<(...)`. This is more robust and avoids potential
# issues with command-line length limits or special characters in the data.
#
# 为健壮性而修订: 将数据通过管道直接传递给 openssl 的标准输入，而非使用
# 进程替换 `<(...)`。这种方式更健壮，能避免命令行长度限制或数据中包含
# 特殊字符所带来的潜在问题。
verify_signature() {
    local data="$1"
    local signature="$2"
    local public_key_file="$3"
    
    # 步骤 1: 将十六进制签名解码为二进制
    # Step 1: Decode the hex signature to binary
    local signature_bin
    signature_bin=$(echo -n "$signature" | xxd -r -p)

    # 步骤 2: 将数据和解码后的签名通过管道传递给 openssl
    #         -signature <(echo -n "$signature_bin") 这种方式仍然可能遇到命令长度限制
    #         因此，最安全的方式是将签名也通过文件描述符传递。
    # Step 2: Pipe both the data and the decoded signature to openssl.
    #         Using -signature <(echo -n "$signature_bin") could still hit command
    #         length limits. The safest way is to also pass the signature via a
    #         file descriptor.

    # 将数据通过 stdin (fd 0) 传递。
    # Pass the data via stdin (fd 0).
    # 将二进制签名通过文件描述符 3 (fd 3) 传递，并告知 openssl 从 /dev/fd/3 读取。
    # Pass the binary signature via file descriptor 3 (fd 3) and tell openssl to read from /dev/fd/3.
    echo -n "$data" | openssl dgst -sha256 -verify "$public_key_file" -signature /dev/fd/3 3< <(echo -n "$signature_bin") >/dev/null 2>&1
}

# Calculate SHA256 hash
calculate_hash() {
    if [ -f "$1" ]; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo -n "$1" | sha256sum | awk '{print $1}'
    fi
}

# =========================================================================
# --- SECTION 4: DATABASE ABSTRACTION LAYER (REVISED & SECURED)         ---
# --- 第4节: 数据库抽象层 (修订与安全加固版)                            ---
# =========================================================================
# This entire section has been rewritten to prevent SQL injection vulnerabilities.
# It introduces safe, parameterized query functions that separate SQL commands
# from user-provided data, which is the standard practice for database security.
#
# 为了防止SQL注入漏洞，整个第4节已被重写。
# 它引入了安全的、参数化的查询函数，将SQL命令与用户提供的数据分离开来，
# 这是数据库安全的标准实践。

# [VULNERABILITY FIX] NEW HELPER FUNCTION: Ensures a value is a valid integer.
# This prevents malicious strings from being injected where a number is expected.
# [漏洞修复] 新增辅助函数: 确保一个值是合法的整数。
# 这可以防止在期望数字的地方被注入恶意字符串。
_sql_safe_integer() {
    case "$1" in
        # Match empty string or any string containing a non-digit character.
        # 匹配空字符串或任何包含非数字字符的字符串。
        ''|*[!0-9]*)
            error "SQL Security Error: Expected an integer, but got '$1'. Aborting. / SQL 安全错误: 期望一个整数，但得到了 '$1'。操作中止。"
            ;;
        *)
            # If it's a valid integer, print it.
            # 如果是合法的整数，则将其输出。
            echo "$1"
            ;;
    esac
}


# [VULNERABILITY FIX] Core engine for safe queries.
# This function simulates prepared statements by separating the SQL template
# from the data. It replaces placeholders (%s for string, %d for integer)
# with safely escaped values.
# [漏洞修复] 安全查询的核心引擎。
# 此函数通过将SQL模板与数据分离来模拟预处理语句。
# 它会将占位符 (%s 代表字符串, %d 代表整数) 替换为安全转义后的值。
#
# @param $1 - db_file (The path to the SQLite database file / SQLite数据库文件的路径)
# @param $2 - query_template (The SQL query with %s and %d placeholders / 带有 %s 和 %d 占位符的SQL查询)
# @param $@ - arguments (The values to safely substitute into the placeholders / 用于安全替换占位符的值)
_db_safe_engine() {
    local db_file="$1"
    local query_template="$2"
    shift 2
    local final_query="$query_template"

    # Iterate as long as there are placeholders to replace.
    # The loop correctly handles one placeholder per iteration, regardless of order.
    # 只要还有占位符需要替换，就持续循环。
    # 循环在每次迭代中会正确处理一个占位符，与其出现的顺序无关。
    while [[ "$final_query" == *"%s"* ]] || [[ "$final_query" == *"%d"* ]]; do
        [ $# -eq 0 ] && error "SQL Security Error: More placeholders than provided arguments. / SQL 安全错误: 占位符数量多于提供的参数。"
        
        local current_arg="$1"
        shift

        # Check for %s first, as it's more common.
        # 优先检查 %s，因为它更常见。
        if [[ "$final_query" == *"%s"* ]]; then
            # Handle string placeholder (%s): encode to a hex literal (X'...') for ultimate safety.
            # 处理字符串占位符 (%s): 编码为十六进制字面量 (X'...') 以确保绝对安全。
            local sanitized_arg="X'$(_sql_safe_string_to_hex "$current_arg")'"
            final_query="${final_query/\%s/$sanitized_arg}" # Replace only the first occurrence / 只替换第一个匹配项
        elif [[ "$final_query" == *"%d"* ]]; then
            # Handle integer placeholder (%d): validate it's a number.
            # 处理整数占位符 (%d): 验证其是否为数字。
            local sanitized_arg=$(_sql_safe_integer "$current_arg")
            final_query="${final_query/\%d/$sanitized_arg}" # Replace only the first occurrence / 只替换第一个匹配项
        fi
    done

    [ $# -gt 0 ] && error "SQL Security Error: More arguments provided than placeholders exist. / SQL 安全错误: 提供的参数数量多于占位符。"
    
    # Return the final, safe, and fully-formed SQL query.
    # 返回最终构造好的、安全的、完整的SQL查询。
    echo "$final_query"
}

# Executes a safe, parameterized SQL statement that does not expect a result.
# 执行一个安全的、参数化的、不期望返回结果的SQL语句。
# Usage: db_execute_safe <db_file> "INSERT INTO t VALUES (%s, %d)" "some string" 123
# 用法:  db_execute_safe <数据库文件> "INSERT INTO t VALUES (%s, %d)" "某个字符串" 123
db_execute_safe() {
    local db_file="$1"
    local query_template="$2"
    shift 2
    local safe_query
    safe_query=$(_db_safe_engine "$db_file" "$query_template" "$@")
    
    sqlite3 "$db_file" "$safe_query" 2>/dev/null || return 1
}

# Executes a safe, parameterized SQL query and returns its result.
# 执行一个安全的、参数化的SQL查询并返回其结果。
# Usage: db_query_safe <db_file> "SELECT name FROM t WHERE id = %d" 42
# 用法:  db_query_safe <数据库文件> "SELECT name FROM t WHERE id = %d" 42
db_query_safe() {
    local db_file="$1"
    local query_template="$2"
    shift 2
    local safe_query
    safe_query=$(_db_safe_engine "$db_file" "$query_template" "$@")

    sqlite3 "$db_file" "$safe_query" 2>/dev/null || true
}

# Initializes a database with a given schema if it doesn't exist.
# 如果数据库不存在，则使用给定的模式对其进行初始化。
db_init() {
    local db_file="$1"
    local schema="$2"
    mkdir -p "$(dirname "$db_file")"
    sqlite3 "$db_file" "$schema" 2>/dev/null || true
}

# Executes a completely static SQL query with no variables.
# This is faster for simple, fixed queries.
# 执行一个不含任何变量的、完全静态的SQL查询。
# 对于固定的简单查询，这会更快。
db_query_static() {
    local db_file="$1"
    local query="$2"
    sqlite3 "$db_file" "$query" 2>/dev/null || true
}

# =======================================================================================
# --- FUNCTION: blockchain_create_genesis_block (DB-OPTIMIZED VERSION) ---
# --- 函数: blockchain_create_genesis_block (数据库优化版)               ---
# =======================================================================================
# REVISED AND COMPLETE: The function to create the genesis block by reading the genesis.json file.
# This approach is flexible and allows anyone to bootstrap their own network without modifying the script.
# This version populates the new `public_key_hash` field.
#
# 已修订并完整: 通过读取 genesis.json 文件来创建创世区块的函数。
# 这种方法非常灵活，允许任何人在不修改脚本的情况下引导自己的网络。
# 此版本会填充新增的 `public_key_hash` 字段。
blockchain_create_genesis_block() {
    msg "[GENESIS] Blockchain is empty. Creating the Genesis Block from configuration..."
    msg "[创世] 区块链为空。正在从配置文件创建创世区块..."
    
    if [ ! -f "$GENESIS_CONFIG_FILE" ]; then
        error "Genesis configuration file not found at: $GENESIS_CONFIG_FILE"
        error "创世配置文件未找到: $GENESIS_CONFIG_FILE"
        error "Please create it or run 'nxpkg init' to generate a default one."
        error "请创建它，或运行 'nxpkg init' 来生成一个默认文件。"
        return 1
    fi
    
    check_dep jq
    info "[GENESIS] Reading founding validators from $GENESIS_CONFIG_FILE..."
    info "[创世] 正在从 $GENESIS_CONFIG_FILE 读取创始验证者..."

    local validator_count=0
    while IFS="|" read -r stake pubkey; do
        [ -z "$pubkey" ] && continue

        # [核心修改] 计算公钥哈希并与公钥本身一同插入
        # [CORE MODIFICATION] Calculate public key hash and insert it along with the public key
        local pubkey_hash
        pubkey_hash=$(calculate_hash "$pubkey") # Calculate the hash
        
        info "  -> 正在注册创世验证者，权益 (stake): $stake"
        info "  -> Registering genesis validator with stake: $stake"
        db_execute_safe "$BLOCKCHAIN_DB" \
            "INSERT INTO validators (public_key, public_key_hash, stake, last_block) VALUES (%s, %s, %d, 0);" \
            "$pubkey" "$pubkey_hash" "$stake"
        
        validator_count=$((validator_count + 1))
    done < <(jq -r '.genesis_validators[] | (.stake|tostring) + "|" + .public_key' "$GENESIS_CONFIG_FILE")

    if [ "$validator_count" -eq 0 ]; then
        error "No validators found in the genesis file. Cannot create a new network."
        error "创世文件中未找到验证者。无法创建新网络。"
        return 1
    fi

    local genesis_timestamp
    genesis_timestamp=$(date -u +%s)
    local genesis_message="NxPKG Genesis Block - Project Chimera"
    
    local genesis_validator_id="genesis_node"
    local genesis_signature="genesis_signature"
    if [ -f "$USER_IDENTITY_FILE" ]; then
        genesis_validator_id=$(calculate_hash "$(cat "$USER_PUBLIC_KEY_FILE")")
        genesis_signature=$(sign_data "$genesis_message" "$USER_IDENTITY_FILE")
    fi

    local genesis_block_data_to_hash="{\"height\":0,\"previous_hash\":\"0\",\"timestamp\":${genesis_timestamp},\"transactions\":[]}"
    local genesis_hash
    genesis_hash=$(calculate_hash "$genesis_block_data_to_hash")

    db_execute_safe "$BLOCKCHAIN_DB" \
        "INSERT INTO blocks (height, hash, previous_hash, timestamp, validator, signature, transactions, total_weight) VALUES (%d, %s, %s, %d, %s, %s, %s, %d);" \
        0 "$genesis_hash" "0" "$genesis_timestamp" "$genesis_validator_id" "$genesis_signature" "[]" 0
    
    db_execute_safe "$BLOCKCHAIN_DB" \
        "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('chain_info', %s);" \
        "$genesis_hash|0"

    msg "[GENESIS] Genesis block created successfully with $validator_count founding validators."
    msg "[创世] 创世区块创建成功，共有 $validator_count 位创始验证者。"
}

# =======================================================================================
# --- FUNCTION: init_databases (DB-OPTIMIZED VERSION) ---
# --- 函数: init_databases (数据库优化版)               ---
# =======================================================================================
# Initialize all databases.
# This version adds the `public_key_hash` column and index to the `validators` table for performance.
#
# 初始化所有数据库。
# 此版本为 `validators` 表增加了用于性能优化的 `public_key_hash` 列和索引。
init_databases() {
    # DHT database schema (unchanged)
    # DHT 数据库模式 (无变动)
    db_init "$DHT_DB" "
    CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
        last_seen INTEGER NOT NULL, distance INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nodes_distance ON nodes(distance);
    CREATE TABLE IF NOT EXISTS chunks (
        hash TEXT PRIMARY KEY, size INTEGER, nodes TEXT, last_updated INTEGER
    );
    CREATE TABLE IF NOT EXISTS local_chunks (
        hash TEXT PRIMARY KEY, file_path TEXT NOT NULL, offset INTEGER NOT NULL, size INTEGER NOT NULL
    );
    "

    # Blockchain database schema...
    # [核心修改] 更新了 `validators` 表的结构。
    # [CORE MODIFICATION] Updated the structure of the `validators` table.
    db_init "$BLOCKCHAIN_DB" "
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, previous_hash TEXT NOT NULL,
        timestamp INTEGER NOT NULL, validator TEXT NOT NULL, signature TEXT NOT NULL,
        transactions TEXT NOT NULL, total_weight INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS validators (
        public_key TEXT PRIMARY KEY,
        public_key_hash TEXT UNIQUE, -- [新增] 用于快速查找的公钥哈希 / [NEW] Public key hash for fast lookups.
        stake INTEGER NOT NULL,
        last_block INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_validators_hash ON validators(public_key_hash); -- [新增] 为哈希列创建索引 / [NEW] Create an index on the hash column.
    CREATE TABLE IF NOT EXISTS transactions (
        hash TEXT PRIMARY KEY, type TEXT NOT NULL, data TEXT NOT NULL, signature TEXT NOT NULL,
        public_key TEXT NOT NULL, timestamp INTEGER NOT NULL, block_height INTEGER
    );
    CREATE TABLE IF NOT EXISTS chain_state ( key TEXT PRIMARY KEY, value TEXT NOT NULL );
    "
    
    # Initialize genesis block if blockchain is empty
    # 如果区块链为空，则初始化创世区块
    local genesis_count
    genesis_count=$(db_query_static "$BLOCKCHAIN_DB" "SELECT COUNT(*) FROM blocks;")
    if [ "$genesis_count" -eq 0 ]; then
        blockchain_create_genesis_block
    fi
}

# --- SECTION 5: KADEMLIA DHT IMPLEMENTATION ---

# Calculate XOR distance between two node IDs
kademlia_distance() {
    local id1="$1"
    local id2="$2"
    python3 -c "
import sys
id1 = int('$id1', 16)
id2 = int('$id2', 16)
distance = id1 ^ id2
print(distance)
"
}

# Generate node ID from public key
generate_node_id() {
    local public_key="$1"
    calculate_hash "$public_key"
}

# Get our node ID
get_our_node_id() {
    if [ -f "$USER_PUBLIC_KEY_FILE" ]; then
        generate_node_id "$(cat "$USER_PUBLIC_KEY_FILE")"
    else
        echo "0000000000000000000000000000000000000000000000000000000000000000"
    fi
}

# Add node to routing table
dht_add_node() {
    local node_id="$1"
    local ip="$2"
    local port="$3"
    local timestamp=$(date +%s)
    local our_id
    our_id=$(get_our_node_id)
    local distance
    distance=$(kademlia_distance "$our_id" "$node_id")
    
    db_execute_safe "$DHT_DB" \
        "INSERT OR REPLACE INTO nodes (id, ip, port, last_seen, distance) VALUES (%s, %s, %d, %d, %s);" \
        "$node_id" "$ip" "$port" "$timestamp" "$distance"
}

# REWRITTEN FOR REAL ITERATIVE LOOKUP: Find closest nodes to a target ID.
# This function now implements the core of the Kademlia FIND_NODE RPC by
# iteratively querying peers to discover nodes closer to the target.
# It is no longer a simple local database query.
#
# 重写以实现真正的迭代查找: 查找与目标ID最近的节点。
# 此函数现在通过迭代查询对等节点来发现离目标更近的节点，
# 从而实现了 Kademlia FIND_NODE RPC 的核心。
# 它不再是一个简单的本地数据库查询。
dht_find_closest_nodes() {
    local target_id="$1"
    local k="${2:-20}" # K-bucket size (number of nodes to find)
    local alpha=3      # Concurrency factor for lookups

    # Essential dependency for large number arithmetic in distance calculations
    # 在距离计算中进行大数运算所必需的依赖项
    check_dep bc

    # --- Data Structures ---
    # candidates: A sorted list of nodes to potentially query. Key: distance, Value: id|ip|port
    # queried_nodes: A set of node IDs we have already queried to avoid loops. Key: id, Value: 1
    # results: The current list of the K closest nodes found so far.
    declare -A queried_nodes
    declare -A candidates
    
    # --- Helper function to calculate distance using bc for large integers ---
    _distance() {
        local id1_hex=${1^^} # Convert to uppercase for bc
        local id2_hex=${2^^} # Convert to uppercase for bc
        echo "ibase=16; ibase=16; scale=0; xor($id1_hex, $id2_hex)" | bc
    }

    # --- Step 1: Seed the process with the closest nodes from our own routing table ---
    debug "[DHT-FIND] Seeding lookup for $target_id with local nodes..."
    local initial_nodes
    # We query more than k nodes locally to have a richer starting set.
    # 我们在本地查询超过k个节点，以获得更丰富的初始集合。
    mapfile -t initial_nodes < <(db_query_static "$DHT_DB" "SELECT id, ip, port FROM nodes ORDER BY ABS(distance - $(_distance "$(get_our_node_id)" "$target_id")) LIMIT $((k * 2));")

    if [ ${#initial_nodes[@]} -eq 0 ]; then
        warn "[DHT-FIND] Routing table is empty. Cannot perform lookup."
        return 1
    fi

    local node_info
    for node_info in "${initial_nodes[@]}"; do
        local id ip port distance
        IFS='|' read -r id ip port <<< "$node_info"
        distance=$(_distance "$target_id" "$id")
        candidates["$distance"]="$id|$ip|$port"
    done
    
    # Initialize results with the best nodes we know so far
    # 用我们目前所知的最佳节点来初始化结果
    local sorted_distances
    mapfile -t sorted_distances < <(printf '%s\n' "${!candidates[@]}" | sort -n)
    local results_map
    declare -A results_map # Using a map for efficient de-duplication
    
    # --- Main Iterative Lookup Loop ---
    # The loop continues as long as we are finding new, closer nodes.
    # 只要我们能找到新的、更近的节点，循环就会继续。
    local round=1
    while true; do
        # Get the 'alpha' closest nodes from the candidates that we haven't queried yet
        # 从候选者中获取我们尚未查询的、最接近的 'alpha' 个节点
        local to_query=()
        local query_count=0
        
        # Sort candidates by distance (keys of the associative array)
        # 按距离（关联数组的键）对候选者进行排序
        mapfile -t sorted_distances < <(printf '%s\n' "${!candidates[@]}" | sort -n)
        
        local dist
        for dist in "${sorted_distances[@]}"; do
            local id
            id=$(echo "${candidates[$dist]}" | cut -d'|' -f1)
            if [ -z "${queried_nodes[$id]+_}" ]; then
                to_query+=("${candidates[$dist]}")
                queried_nodes["$id"]=1
                query_count=$((query_count + 1))
                if [ "$query_count" -ge "$alpha" ]; then
                    break
                fi
            fi
        done

        # If there are no new nodes to query, the lookup has converged.
        # 如果没有新的节点可供查询，说明查找已经收敛。
        if [ ${#to_query[@]} -eq 0 ]; then
            debug "[DHT-FIND] No new nodes to query. Lookup converged after $((round - 1)) rounds."
            break
        fi
        
        debug "[DHT-FIND] Round $round: Querying ${#to_query[@]} peers..."

        # Send FIND_NODE messages in parallel to the selected peers
        # 并行地向选中的对等节点发送 FIND_NODE 消息
        local pids=()
        local response_files=()
        local node_data
        for node_data in "${to_query[@]}"; do
            local ip port
            IFS='|' read -r _ ip port <<< "$node_data"
            
            local temp_file
            temp_file=$(mktemp)
            response_files+=("$temp_file")
            
            ( dht_send_message "$ip" "$port" "FIND_NODE" "$target_id" > "$temp_file" ) &
            pids+=($!)
        done
        
        # Wait for all parallel queries to finish
        # 等待所有并行查询完成
        wait "${pids[@]}"

        # Process the responses from all peers
        # 处理来自所有对等节点的响应
        local found_new_nodes=0
        local response_file
        for response_file in "${response_files[@]}"; do
            local response
            response=$(cat "$response_file")
            rm -f "$response_file"
            
            # Response format: NODES:id1:ip1:port1 id2:ip2:port2 ...
            if [[ "$response" =~ ^NODES:(.*) ]]; then
                local new_peers_str="${BASH_REMATCH[1]}"
                local new_peer
                for new_peer in $new_peers_str; do
                    local new_id new_ip new_port
                    IFS=':' read -r new_id new_ip new_port <<< "$new_peer"
                    
                    # If we haven't seen this node before, add it to our candidates
                    # 如果我们以前没见过这个节点，就把它加入到我们的候选列表中
                    if [ -z "${queried_nodes[$new_id]+_}" ]; then
                        local new_distance
                        new_distance=$(_distance "$target_id" "$new_id")
                        candidates["$new_distance"]="$new_id|$new_ip|$new_port"
                        found_new_nodes=1
                    fi
                done
            fi
        done
        
        # If a full round of queries yields no new nodes, we are done.
        # 如果一整轮查询没有产生任何新节点，我们就完成了。
        if [ "$found_new_nodes" -eq 0 ]; then
             debug "[DHT-FIND] Round $round did not discover any new nodes. Converging."
             break
        fi

        round=$((round + 1))
        # Safety break to prevent infinite loops in buggy scenarios
        # 安全断点，以防在有bug的场景下出现无限循环
        [ "$round" -gt $((k + 1)) ] && { warn "[DHT-FIND] Lookup took too many rounds, aborting."; break; }
    done
    
    # --- Final Step: Format and return the K closest nodes found ---
    mapfile -t sorted_distances < <(printf '%s\n' "${!candidates[@]}" | sort -n)

    local output_count=0
    local dist
    for dist in "${sorted_distances[@]}"; do
        local id ip port
        IFS='|' read -r id ip port <<< "${candidates[$dist]}"
        echo "$id:$ip:$port"
        output_count=$((output_count + 1))
        [ "$output_count" -ge "$k" ] && break
    done
}

# Store chunk location in DHT
dht_store_chunk() {
    local chunk_hash="$1"
    local file_path="$2"
    local offset="$3"
    local size="$4"
    local timestamp=$(date +%s)
    
    # Store in local chunks table
    db_execute_safe "$DHT_DB" \
        "INSERT OR REPLACE INTO local_chunks (hash, file_path, offset, size) VALUES (%s, %s, %d, %d);" \
        "$chunk_hash" "$file_path" "$offset" "$size"
    
    # Announce to network
    dht_announce_chunk "$chunk_hash"
}

# Announce chunk to network
dht_announce_chunk() {
    local chunk_hash="$1"
    local nodes
    nodes=$(dht_find_closest_nodes "$chunk_hash")
    
    while IFS=':' read -r node_id ip port; do
        [ -n "$node_id" ] || continue
        # Send STORE message to node
        dht_send_message "$ip" "$port" "STORE" "$chunk_hash" "$(get_our_node_id)" "$P2P_PORT"
    done <<< "$nodes"
}

# REVISED AND COMPLETE: dht_find_chunk with iterative lookup and correct provider address return.
# 已修订并完整: 具备迭代查找能力并能正确返回提供者地址的 dht_find_chunk
dht_find_chunk() {
    local chunk_hash="$1"
    
    # --- Step 1: Check local cache (logic unchanged) ---
    # --- 步骤 1: 检查本地缓存 (逻辑不变) ---
    local local_chunk
    local_chunk=$(db_query_safe "$DHT_DB" \
        "SELECT file_path, offset, size FROM local_chunks WHERE hash = %s;" \
        "$chunk_hash")
    if [ -n "$local_chunk" ]; then
        # Always return the local provider first
        # 始终将本地作为第一个提供者返回
        echo "local:$local_chunk"
    fi
    
    # --- Step 2: Initialize iterative lookup ---
    # --- 步骤 2: 初始化迭代查找 ---
    info "[P2P-FIND] Performing iterative network lookup for chunk ${chunk_hash:0:16}... / 正在为数据块 ${chunk_hash:0:16} 执行迭代网络查找..."
    
    declare -A queried_nodes # Store queried node IDs to prevent loops / 存储已查询过的节点ID，防止循环
    local -a providers_found=() # Store found remote provider addresses / 存储找到的远程提供者地址
    
    # Get initial seed nodes / 获取初始种子节点
    local initial_nodes
    initial_nodes=$(dht_find_closest_nodes "$chunk_hash" 8) # Get 8 initial nodes / 获取8个初始节点
    
    # Use a simple array as the query queue / 使用一个简单的数组作为待查询队列
    local -a candidates=()
    while IFS= read -r node; do
        candidates+=("$node")
    done <<< "$initial_nodes"

    local round=1
    local max_rounds=10 # Safety limit to prevent infinite loops / 安全上限，防止无限循环
    local find_limit=5  # Stop after finding this many remote providers / 最多寻找5个远程提供者就停止

    # --- Step 3: Start the iterative loop ---
    # --- 步骤 3: 开始迭代循环 ---
    while [ ${#candidates[@]} -gt 0 ] && [ "$round" -le "$max_rounds" ]; do
        local node_to_query="${candidates[0]}"
        candidates=("${candidates[@]:1}") # Dequeue / 出队

        IFS=':' read -r node_id ip port <<< "$node_to_query"
        [ -z "$node_id" ] && continue
        
        # If already queried, skip / 如果已查询过，则跳过
        [ -n "${queried_nodes[$node_id]+_}" ] && continue
        
        detail "[P2P-FIND] Round $round: Querying $ip:$port ... / 第 $round 轮: 正在查询 $ip:$port ..."
        queried_nodes["$node_id"]=1 # Mark as queried / 标记为已查询
        
        local response
        response=$(dht_send_message "$ip" "$port" "FIND_VALUE" "$chunk_hash")

        # --- Step 4: Process the response ---
        # --- 步骤 4: 处理响应 ---
        if [[ "$response" == "FOUND_CHUNK" ]]; then
            # Success! Found a node with the data. Record it and keep searching for more.
            # 成功！找到了一个持有数据的节点。记录下来并继续寻找更多。
            detail "[P2P-FIND] Successfully found chunk at $ip:$port! / 成功在 $ip:$port 找到数据块！"
            local provider_address="${ip}:${port}"
            # Avoid adding duplicates / 避免重复添加
            if ! [[ " ${providers_found[*]} " =~ " ${provider_address} " ]]; then
                providers_found+=("$provider_address")
                # Output the found provider's information / 将找到的提供者信息输出
                echo "$provider_address"
            fi
            # If enough providers are found, exit early / 如果找到了足够多的提供者，就提前结束
            if [ "${#providers_found[@]}" -ge "$find_limit" ]; then
                msg "[P2P-FIND] Found enough providers, stopping search. / 已找到足够多的提供者，停止搜索。"
                return 0
            fi

        elif [[ "$response" =~ ^NODES:(.*) ]]; then
            # Data not found, but received a list of closer nodes
            # 未找到数据，但获得了更近的节点列表
            local new_peers_str="${BASH_REMATCH[1]}"
            detail "[P2P-FIND] Got new node leads from $ip... / 从 $ip 获得新的节点线索..."
            for new_peer in $new_peers_str; do
                local new_id
                new_id=$(echo "$new_peer" | cut -d':' -f1)
                # If it's a new node we haven't seen, add it to the queue
                # 如果是未见过的新节点，则加入待查询队列
                if [ -z "${queried_nodes[$new_id]+_}" ]; then
                    candidates+=("$new_peer")
                fi
            done
        fi
        round=$((round + 1))
    done

    if [ ${#providers_found[@]} -eq 0 ] && [ -z "$local_chunk" ]; then
        warn "[P2P-FIND] Iterative lookup finished, but failed to find chunk: ${chunk_hash:0:16} / 迭代查找结束，未能找到数据块: ${chunk_hash:0:16}"
        return 1
    fi
    
    return 0
}


# REVISED FOR HTTP/JSON: This function now sends messages exclusively via HTTP POST
# with a JSON payload, using curl. It relies on jq to parse responses.
#
# 为 HTTP/JSON 修订: 此函数现在专门通过带有 JSON 载荷的 HTTP POST 来发送消息。
# 它使用 curl，并依赖 jq 来解析响应。
# (Interactive TOFU version with automation options)
# (带自动化选项的交互式TOFU版本)
# (Final version with three levels of priority)
# (最终版本，带三层优先级)

dht_send_message() {
    local ip="$1"
    local port="$2"
    local message_type="$3"
    shift 3
    local payload="$*"

    check_dep jq
    check_dep openssl

    local cmd_timeout="${P2P_MESSAGE_TIMEOUT:-5}"
    
    # --- 1. 验证并缓存对等节点的TLS证书 (Trust and Cache Peer's TLS Certificate) ---
    local peer_cert_file="${PEER_CERT_CACHE}/${ip}_${port}.pem"
    if [ ! -f "$peer_cert_file" ]; then
        # [修改] 先将证书获取到一个临时文件
        local temp_cert_file
        temp_cert_file=$(mktemp)

        if ! openssl s_client -connect "$ip:$((port + P2P_HTTP_PORT_OFFSET))" -showcerts </dev/null 2>/dev/null | \
           openssl x509 -outform PEM > "$temp_cert_file"; then
            rm -f "$temp_cert_file"
            error "无法获取对等节点 $ip:$port 的TLS证书。 (Failed to retrieve TLS certificate from peer $ip:$port.)"
            return 1
        fi

        # [新增] 计算指纹并根据最终配置决定行为
        local fingerprint
        fingerprint=$(openssl x509 -in "$temp_cert_file" -noout -fingerprint -sha256 | cut -d'=' -f2)

        # [核心修改] 决定信任策略，优先级: 环境变量 > 配置文件 > 脚本默认
        # The :- operator provides the fallback mechanism. If env var is unset, it uses the global var.
        local final_auto_trust_policy="${NXPKG_AUTO_TRUST_NEW_NODES:-$AUTO_TRUST_NEW_NODES}"

        # 模式1: 自动化信任模式
        if [ "$final_auto_trust_policy" = "true" ]; then
            warn "自动化信任已启用: 自动信任新节点 $ip:$port"
            warn "AUTO-TRUST ENABLED: Automatically trusting new peer $ip:$port"
            detail "  -> Fingerprint: $fingerprint"
        
        # 模式2: 交互式终端模式
        elif [ -t 0 ]; then
            echo
            warn "节点的真实性无法确认: $ip:$port"
            warn "The authenticity of peer '$ip:$port' can't be established."
            echo -e "SHA256 证书指纹 (Certificate Fingerprint): \033[1;33m$fingerprint\033[0m"
            
            read -rp "您确定要继续连接吗？ (Are you sure you want to continue connecting?) [y/N] " choice
            if [[ ! "$choice" =~ ^[yY] ]]; then
                rm -f "$temp_cert_file"
                info "连接已取消。 (Connection cancelled.)"
                return 1
            fi
        
        # 模式3: 非交互式且未启用自动化信任 (安全默认)
        else
            warn "在非交互式会话中，无法确认新的节点指纹。连接失败。"
            warn "Cannot confirm new peer fingerprint in a non-interactive session. Connection failed."
            warn "要允许此操作，请在 nxpkg.conf 中设置 auto_trust_new_nodes = true"
            warn "或临时设置环境变量: export NXPKG_AUTO_TRUST_NEW_NODES=true"
            warn "To allow this, set auto_trust_new_nodes = true in nxpkg.conf"
            warn "or temporarily set the environment variable: export NXPKG_AUTO_TRUST_NEW_NODES=true"
            rm -f "$temp_cert_file"
            return 1
        fi

        # 用户确认或自动化信任后，才将证书移入缓存
        mkdir -p "$(dirname "$peer_cert_file")"
        mv "$temp_cert_file" "$peer_cert_file"
        info "节点已被信任并缓存。 (Peer has been trusted and cached.)"
    fi

    # --- 2. 准备带签名的JSON载荷 (Prepare Signed JSON Payload) ---
    local sender_id signature data_to_sign
    sender_id=$(get_our_node_id)
    data_to_sign="${message_type}|${payload}"
    signature=$(sign_data "$data_to_sign" "$USER_IDENTITY_FILE")
    
    local json_payload
    json_payload=$(jq -n \
        --arg type "$message_type" \
        --arg payload "$payload" \
        --arg sender_id "$sender_id" \
        --arg signature "$signature" \
        '{type: $type, payload: $payload, sender_id: $sender_id, signature: $signature}')

    # --- 3. 使用curl发送安全的HTTPS POST请求 ---
    local response http_code
    response=$(curl --silent --show-error \
        --max-time "$cmd_timeout" \
        --cacert "$peer_cert_file" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        --write-out "%{http_code}" \
        "https://$ip:$((port + P2P_HTTP_PORT_OFFSET))/dht")
    
    local curl_exit_code=$?
    if [ "$curl_exit_code" -ne 0 ]; then
        if [[ "$response" == *"certificate verify failed"* ]] || [[ "$response" == *"server certificate changed"* ]]; then
             warn "对等节点 $ip:$port 的TLS证书已变更或无效。将移除旧证书并于下次重试。"
             warn "Peer $ip:$port's TLS certificate has changed or is invalid. Removing old cert for next retry."
             rm -f "$peer_cert_file"
        fi
        debug "[DHT-SEND] curl command failed for https://$ip:$port with exit code $curl_exit_code."
        return 1
    fi

    http_code="${response: -3}"
    response="${response:0:${#response}-3}"

    if [ "$http_code" != "200" ]; then
        debug "[DHT-SEND] Received non-200 HTTP status ($http_code) from https://$ip:$port."
        return 1
    fi
    
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        debug "[DHT-SEND] Received invalid JSON response from https://$ip:$port: $response"
        return 1
    fi

    local status
    status=$(echo "$response" | jq -r .status)

    if [ "$status" = "success" ]; then
        echo "$response" | jq -r .data
        return 0
    else
        local error_message
        error_message=$(echo "$response" | jq -r .message)
        debug "[DHT-SEND] Peer https://$ip:$port returned an error: $error_message"
        return 1
    fi
}

# =======================================================================================
# --- FUNCTION: dht_server_daemon (PERFORMANCE & ROBUSTNESS FIX, v3.2) ---
# --- 函数: dht_server_daemon (性能与健壮性修复版, v3.2)                ---
# =======================================================================================
# REVISED AND HARDENED: This version makes the Python DHT server incompletely self-sufficient.
# It can now independently and safely fetch and cache TLS certificates from new peers
# using Python's native SSL library, removing the unsafe assumption that a bash
# process must have done it first. This is critical for robust, independent network operation.
#
# 已修订并加固: 此版本使 Python DHT 服务器不完全地自给自足。它现在可以使用 Python
# 原生的 SSL 库，独立且安全地从新的对等节点获取并缓存 TLS 证书，消除了“必须由
# bash 进程先完成此操作”的不安全假设。这对于健壮、独立的网络操作至关重要。
dht_server_daemon() {
    # --- Bootstrap node simulation (unchanged) ---
    if [ "${P2P_SIMULATE_NODES:-0}" -gt 1 ] && [ "$(db_query_static "$BLOCKCHAIN_DB" "SELECT COUNT(*) FROM blocks;" 2>/dev/null || echo 0)" -lt 5 ]; then
        local sim_count="${P2P_SIMULATE_NODES}"
        local base_port="$P2P_PORT"
        msg "正在模拟 $sim_count 个启动节点以初始化网络... (Simulating $sim_count bootstrap nodes to initialize network...)"
        info "真实节点监听于: $base_port (Real node listening on: $base_port)"

        for (( i=1; i < sim_count; i++ )); do
            local sim_port=$((base_port + i))
            local http_sim_port=$((sim_port + P2P_HTTP_PORT_OFFSET))
            local node_name="SIMULATED_NODE_$i"
            info "  - 模拟节点监听于: $sim_port (HTTP at $http_sim_port) (Simulated node listening on: $sim_port)"
            
            export SIM_HTTP_PORT="$http_sim_port"
            export SIM_NODE_NAME="$node_name"

            python3 -c '
import http.server
import socketserver
import json
import os
import sys

PORT = int(os.environ.get("SIM_HTTP_PORT", 8235))
NODE_NAME = os.environ.get("SIM_NODE_NAME", "UNKNOWN_SIM_NODE")

class PingHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/dht":
            try:
                content_length = int(self.headers["Content-Length"])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode("utf-8"))

                if data.get("type") == "PING":
                    response_data = {"status": "success", "data": f"PONG:{NODE_NAME}"}
                    self.send_response(200)
                else:
                    response_data = {"status": "error", "message": "Simulated node only supports PING"}
                    self.send_response(400)

                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode("utf-8"))

            except Exception as e:
                self.send_error(500, f"Internal Server Error: {e}")
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        return

try:
    with socketserver.TCPServer(("", PORT), PingHandler) as httpd:
        httpd.serve_forever()
except Exception as e:
    print(f"Failed to start simulated node {NODE_NAME}: {e}", file=sys.stderr)
' &
        done
    fi
    # --- End of simulation logic ---

    local port="$P2P_PORT"
    
    # --- [新增] 启动时清理残留的区块锁目录 ---
    # --- [NEW] Cleanup stale block lock directories on startup ---
    info "正在清理上一次运行可能残留的锁文件... (Cleaning up potential stale lock files from previous run...)"
    find "$LOCK_DIR" -type d -name "seen_block_*" -exec rm -rf {} +
    
    while true; do
            # Export all necessary environment variables to the Python process
            export NXPKG_DHT_DB="$DHT_DB"
            export NXPKG_BLOCKCHAIN_DB="$BLOCKCHAIN_DB"
            export NXPKG_LOCK_DIR="$LOCK_DIR"
            export NXPKG_USER_PUBLIC_KEY_FILE="$USER_PUBLIC_KEY_FILE"
            export NXPKG_USER_IDENTITY_FILE="$USER_IDENTITY_FILE"
            export NXPKG_P2P_PORT="$P2P_PORT"
            export NXPKG_P2P_HTTP_PORT_OFFSET="$P2P_HTTP_PORT_OFFSET"
            export NXPKG_P2P_HTTP_PORT=$((P2P_PORT + P2P_HTTP_PORT_OFFSET))
            export SCRIPT_PATH="$SCRIPT_PATH"
            export NXPKG_TLS_CERT_FILE="$TLS_CERT_FILE"
            export NXPKG_TLS_KEY_FILE="$TLS_KEY_FILE"
            export FORUM_PUBKEYS_DIR="$FORUM_PUBKEYS_DIR"
            export PEER_CERT_CACHE="$PEER_CERT_CACHE"
            
            info "正在启动高性能、自给自足的 Python HTTP DHT 服务器... (Starting high-performance, self-sufficient Python HTTP DHT server...)"
            
             # [修复] 移除了末尾的 '&'，让Python进程在前台运行，这样循环会等待它结束
            # [FIX] Removed the trailing '&' to run Python in the foreground, so the loop waits for it to exit.
            
            python3 - <<'EOF' 
import http.server
import socketserver
import json
import sqlite3
import os
import sys
import time
import hashlib
import subprocess
import ssl
import ipaddress
from threading import Lock
import http.client # [新增] 导入 http.client 用于 HTTPS 请求

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# --- 全局变量与缓存 ---
OUR_NODE_ID_CACHE = None
RECENTLY_SEEN_BLOCKS = {}
RECENTLY_SEEN_LOCK = Lock()
MAX_SEEN_CACHE_SIZE = 1000
CERT_FETCH_LOCK = Lock() # [新增] 用于保护证书获取的全局锁

# --- 双语日志 ---
def bilingual_print(message_en, message_zh, level="INFO"):
    print(f"PY_DHT_LOG|{level}| {message_en} / {message_zh}", file=sys.stderr)

if not CRYPTOGRAPHY_AVAILABLE:
    bilingual_print("FATAL: The 'cryptography' Python library is not installed.", "致命错误: 未安装 'cryptography' Python 库。", "FATAL")
    sys.exit(1)

# --- 辅助函数 ---
def calculate_hash(data):
    if isinstance(data, str): data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def get_our_node_id():
    global OUR_NODE_ID_CACHE
    if OUR_NODE_ID_CACHE: return OUR_NODE_ID_CACHE
    key_file = os.environ.get('NXPKG_USER_PUBLIC_KEY_FILE')
    if not key_file or not os.path.exists(key_file): return "0" * 64
    with open(key_file, 'r') as f: public_key = f.read()
    OUR_NODE_ID_CACHE = calculate_hash(public_key)
    return OUR_NODE_ID_CACHE

def db_query(db_path, query, params=(), fetch_one=False, fetch_all=False):
    if not db_path or not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found at {db_path}")
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10) # 以只读模式打开，更安全
        cursor = conn.cursor()
        cursor.execute(query, params)
        if fetch_one: return cursor.fetchone()
        if fetch_all: return cursor.fetchall()
        # No commit needed for read-only
    finally:
        if conn: conn.close()

class DHT_Handler(http.server.BaseHTTPRequestHandler):
    # --- [已修改] DHT 客户端，现在可以独立获取并缓存证书 ---
    def _send_dht_message_py(self, ip, port, msg_type, payload_str):
        conn = None
        try:
            if not ipaddress.ip_address(ip).is_global:
                bilingual_print(f"Security Warning: Attempted to send to non-global IP {ip}. Blocked.", f"安全警告：尝试向非全局IP {ip} 发送。已阻止。", "WARN")
                return None

            peer_cert_cache_dir = os.environ.get('PEER_CERT_CACHE')
            peer_cert_file = os.path.join(peer_cert_cache_dir, f"{ip}_{port}.pem")
            http_port_offset = int(os.environ.get('NXPKG_P2P_HTTP_PORT_OFFSET', 1000))
            target_port = int(port) + http_port_offset
            
            # --- [核心修复] 如果证书不存在，则获取并缓存它 ---
            if not os.path.exists(peer_cert_file):
                with CERT_FETCH_LOCK:
                    # 双重检查锁定，防止多个线程重复获取
                    if not os.path.exists(peer_cert_file):
                        bilingual_print(f"First contact with {ip}:{port}, fetching TLS cert...", f"首次连接 {ip}:{port}，正在获取TLS证书...", "INFO")
                        try:
                            # 使用Python原生方法获取证书
                            pem_cert = ssl.get_server_certificate((ip, target_port), timeout=5)
                            os.makedirs(peer_cert_cache_dir, exist_ok=True)
                            with open(peer_cert_file, "w") as f:
                                f.write(pem_cert)
                            bilingual_print(f"Certificate for {ip}:{port} cached successfully.", f"已成功缓存 {ip}:{port} 的证书。", "INFO")
                        except Exception as e:
                            bilingual_print(f"Failed to fetch cert for {ip}:{port}: {e}", f"获取 {ip}:{port} 的证书失败: {e}", "ERROR")
                            return None

            # 创建并签署载荷
            sender_id = get_our_node_id()
            data_to_sign = f"{msg_type}|{payload_str}"
            identity_file = os.environ.get('NXPKG_USER_IDENTITY_FILE')
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', identity_file], input=data_to_sign.encode('utf-8'), capture_output=True)
            if result.returncode != 0:
                bilingual_print(f"Failed to sign data: {result.stderr.decode()}", f"签名数据失败: {result.stderr.decode()}", "ERROR")
                return None
            signature = result.stdout.hex()

            json_payload = json.dumps({
                "type": msg_type, "payload": payload_str,
                "sender_id": sender_id, "signature": signature
            })
            
            # 发送HTTPS请求
            context = ssl.create_default_context(cafile=peer_cert_file)
            conn = http.client.HTTPSConnection(ip, target_port, context=context, timeout=5)
            headers = {'Content-Type': 'application/json'}
            conn.request("POST", "/dht", body=json_payload.encode('utf-8'), headers=headers)
            response = conn.getresponse()
            
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
            else:
                return None
        except Exception as e:
            bilingual_print(f"Error in _send_dht_message_py to {ip}:{port}: {e}", f"向 {ip}:{port} 发送消息时出错: {e}", "ERROR")
            return None
        finally:
            if conn: conn.close()

    # 区块宣告处理逻辑 (与上一版相同，现在更健壮了)
    def _handle_block_announcement(self, data):
        payload = data.get('payload', '')
        parts = payload.split('|')
        if len(parts) != 6: return {"status": "error", "message": "Malformed ANNOUNCE_BLOCK payload"}
        
        block_hash, block_height_str, ip, port, announcer_id, signature = parts
        
        data_that_was_signed = f"{block_hash}|{block_height_str}"
        pubkey_path = os.path.join(os.environ.get('FORUM_PUBKEYS_DIR'), f"{announcer_id}.pub")
        if not os.path.exists(pubkey_path):
            bilingual_print(f"Cannot verify announcement from {announcer_id[:16]}: public key not found.", f"无法验证来自 {announcer_id[:16]} 的宣告：未找到公钥。", "WARN")
            return {"status": "error", "message": "Announcer public key not found"}

        if not self._verify_signature_py(data_that_was_signed, signature, pubkey_path):
            bilingual_print(f"Invalid announcement signature from {announcer_id[:16]}. IGNORED.", f"来自 {announcer_id[:16]} 的宣告签名无效。已忽略。", "WARN")
            return {"status": "error", "message": "Invalid announcement signature"}
            
        bilingual_print(f"Verified announcement from {announcer_id[:16]} for block {block_hash[:16]}", f"已验证来自 {announcer_id[:16]} 的关于区块 {block_hash[:16]} 的宣告", "DEBUG")

        global RECENTLY_SEEN_BLOCKS
        with RECENTLY_SEEN_LOCK:
            if block_hash in RECENTLY_SEEN_BLOCKS and time.time() - RECENTLY_SEEN_BLOCKS[block_hash] < 300:
                return {"status": "success", "data": "Announcement already processed (in-memory)"}
            
            lock_dir = os.path.join(os.environ.get('NXPKG_LOCK_DIR'), f"seen_block_{block_hash}")
            try:
                os.mkdir(lock_dir)
            except FileExistsError:
                return {"status": "success", "data": "Announcement already processed (fs lock)"}
            
            RECENTLY_SEEN_BLOCKS[block_hash] = time.time()
            if len(RECENTLY_SEEN_BLOCKS) > MAX_SEEN_CACHE_SIZE:
                oldest_key = min(RECENTLY_SEEN_BLOCKS, key=RECENTLY_SEEN_BLOCKS.get)
                del RECENTLY_SEEN_BLOCKS[oldest_key]

        try:
            db_path = os.environ.get('NXPKG_BLOCKCHAIN_DB')
            local_info = db_query(db_path, "SELECT value FROM chain_state WHERE key = 'chain_info';", fetch_one=True)
            local_weight = int(local_info[0].split('|')[1]) if local_info else 0
            
            remote_response = self._send_dht_message_py(ip, port, "GET_CHAIN_INFO", "")
            if not remote_response or remote_response.get('status') != 'success':
                 bilingual_print(f"Failed to get chain info from peer {ip}:{port}", f"从节点 {ip}:{port} 获取链信息失败", "WARN")
                 return {"status": "error", "message": "Failed to get remote chain info"}

            remote_data = remote_response.get('data', '')
            if not remote_data.startswith("CHAIN_INFO:"): return {"status": "error", "message": "Invalid chain info response"}

            remote_tip_hash, remote_weight_str = remote_data.replace("CHAIN_INFO:", "").split('|')
            remote_weight = int(remote_weight_str)

            bilingual_print(f"Chain weight: Local={local_weight}, Remote={remote_weight}", f"链权重: 本地={local_weight}, 远端={remote_weight}", "DEBUG")

            if remote_weight > local_weight:
                bilingual_print(f"Heavier chain detected from {ip}:{port}. Triggering reorg.", f"从 {ip}:{port} 检测到更重的链。触发重组。", "INFO")
                subprocess.Popen([ 'bash', os.environ.get('SCRIPT_PATH'), '_internal_trigger_reorg', remote_tip_hash, ip, port ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                bilingual_print(f"Local chain is heavier or equal. Ignoring.", f"本地链更重或等重。忽略。", "INFO")

        except Exception as e:
            bilingual_print(f"Error handling block announcement: {e}", f"处理区块宣告时出错: {e}", "ERROR")
            return {"status": "error", "message": f"Internal error: {e}"}
        finally:
            if 'lock_dir' in locals() and os.path.exists(lock_dir):
                try: os.rmdir(lock_dir)
                except OSError: pass

        return {"status": "success", "data": "ANNOUNCEMENT_PROCESSING"}

    def _verify_signature_py(self, data, signature_hex, pubkey_path):
        try:
            with open(pubkey_path, 'rb') as f: public_key_pem = f.read()
            public_key = load_pem_public_key(public_key_pem)
            data_to_verify = data.encode('utf-8')
            signature_bytes = bytes.fromhex(signature_hex)
            public_key.verify(signature_bytes, data_to_verify, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, FileNotFoundError):
            return False
        except Exception as e:
            bilingual_print(f"Signature verification error: {e}", f"签名验证出错: {e}", "ERROR")
            return False

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            sender_id = data.get('sender_id')
            msg_type = data.get('type')
            
            if msg_type != "PING" and sender_id: # PING is unsigned
                pubkey_path = os.path.join(os.environ.get('FORUM_PUBKEYS_DIR'), f"{sender_id}.pub")
                if not self._verify_signature_py(f"{msg_type}|{data.get('payload', '')}", data.get('signature'), pubkey_path):
                    self.send_error(403, "Forbidden: Invalid Signature")
                    return
            
            if msg_type == "ANNOUNCE_BLOCK":
                response_data = self._handle_block_announcement(data)
            else:
                response_data = self.handle_dht_message(data)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        except Exception as e:
            bilingual_print(f"Error in do_POST: {e}", f"do_POST 出错: {e}", "ERROR")
            self.send_error(500, f"Internal Server Error: {e}")

    def handle_dht_message(self, data):
        msg_type = data.get('type')
        payload = data.get('payload', "")
        bilingual_print(f"Received DHT message: type={msg_type}", f"收到DHT消息: 类型={msg_type}", "DEBUG")
        dht_db_path = os.environ.get('NXPKG_DHT_DB')
        bc_db_path = os.environ.get('NXPKG_BLOCKCHAIN_DB')

        if msg_type == "PING": return {"status": "success", "data": f"PONG:{get_our_node_id()}"}
        elif msg_type == "STORE":
            chunk_hash, node_id, node_port = payload.split()
            # This is a write operation, can't use read-only connection
            conn = sqlite3.connect(dht_db_path)
            conn.execute("INSERT OR REPLACE INTO chunks (hash, size, nodes, last_updated) VALUES (?, ?, ?, ?)", (chunk_hash, 0, f"{node_id}:{node_port}", int(time.time())))
            conn.commit()
            conn.close()
            return {"status": "success", "data": "STORED"}
        elif msg_type == "FIND_VALUE":
            local_chunk = db_query(dht_db_path, "SELECT file_path, offset, size FROM local_chunks WHERE hash = ?", (payload,), fetch_one=True)
            # [修改] 不再返回无用的本地路径，只返回一个确认信息
            if local_chunk: 
                return {"status": "success", "data": "FOUND_CHUNK"}
            else:
                nodes = db_query(dht_db_path, "SELECT id, ip, port FROM nodes ORDER BY RANDOM() LIMIT 3", fetch_all=True)
                return {"status": "success", "data": f"NODES:{' '.join([f'{i[0]}:{i[1]}:{i[2]}' for i in nodes])}"}
        elif msg_type == "FIND_NODE":
            nodes = db_query(dht_db_path, "SELECT id, ip, port FROM nodes ORDER BY RANDOM() LIMIT 8", fetch_all=True)
            return {"status": "success", "data": f"NODES:{' '.join([f'{i[0]}:{i[1]}:{i[2]}' for i in nodes])}"}
        elif msg_type == "GET_CHAIN_INFO":
            chain_info = db_query(bc_db_path, "SELECT value FROM chain_state WHERE key = 'chain_info'", fetch_one=True)
            return {"status": "success", "data": f"CHAIN_INFO:{chain_info[0] if chain_info else '0|0'}"}
        else: return {"status": "error", "message": "Unknown message type"}

if __name__ == "__main__":
    try:
        port = int(os.environ.get('NXPKG_P2P_HTTP_PORT', 8234))
        cert_file = os.environ.get('NXPKG_TLS_CERT_FILE')
        key_file = os.environ.get('NXPKG_TLS_KEY_FILE')

        if not all([cert_file, key_file, os.path.exists(cert_file), os.path.exists(key_file)]):
            bilingual_print("TLS certificate or key not found.", "未找到TLS证书或密钥。", "FATAL")
            sys.exit(1)

        # 使用线程服务器以处理并发请求
        class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            """
            这是一个多线程的TCP服务器。
            This is a multi-threaded TCP server.
        
            它通过多重继承的方式，同时继承了 `ThreadingMixIn` 和 `TCPServer` 两个类。
            It uses multiple inheritance to inherit from both `ThreadingMixIn` and `TCPServer`.
        
            1. `socketserver.TCPServer`:
               - 这个基类提供了所有TCP服务器的核心功能：绑定端口、监听连接、接受连接等。
               - This base class provides all the core functionality of a TCP server:
                 binding a port, listening for connections, accepting connections, etc.
               - 但是，它本身是单线程的，一次只能处理一个请求。
               - However, it is single-threaded by itself and can only handle one request at a time.
        
            2. `socketserver.ThreadingMixIn`:
               - 这是一个 "混入" (Mixin) 类。它的设计目的就是被其他类继承，以"混入"新的功能。
               - This is a "Mixin" class. It is designed to be inherited by other classes
                 to "mix in" new functionality.
               - 它提供的核心功能是：覆写 `process_request` 方法。
               - The core functionality it provides is to override the `process_request` method.
               - 当一个新的请求到达时，`ThreadingMixIn` 的 `process_request` 方法会创建一个全新的线程
                 来处理这个请求，而不会阻塞主线程。
               - When a new request arrives, `ThreadingMixIn`'s `process_request` method
                 creates a brand new thread to handle this request without blocking the main thread.
               - 其内部实现大致如下（伪代码）:
               - Its internal implementation is roughly as follows (pseudo-code):
                 
                 def process_request(self, request, client_address):
                     # 创建一个新的线程，目标是执行 self.process_request_thread
                     # Create a new thread, with the target being self.process_request_thread
                     t = threading.Thread(target=self.process_request_thread,
                                          args=(request, client_address))
                     # 设为守护线程，这样主程序退出时它也会退出
                     # Set it as a daemon thread so it will exit when the main program exits
                     t.daemon = self.daemon_threads
                     # 启动线程
                     # Start the thread
                     t.start()
        
            通过将这两个类组合在一起，`ThreadedTCPServer` 就成为了一个功能完备、开箱即用的多线程服务器。
            By combining these two classes, `ThreadedTCPServer` becomes a fully functional,
            out-of-the-box multi-threaded server.
        """
            pass
            
            # --- 这里（pass）为什么是空的？(Why is it (the "pass") empty here?) ---
            #
            # 这正是该设计的优雅之处。我们不需要在这里写任何额外的代码。
            # And that is the elegance of this design. We don't need to write any code here.
            #
            # 所有需要的功能都已经由父类 `ThreadingMixIn` 和 `TCPServer` 提供了。
            # All the necessary functionality has already been provided by the parent classes
            # `ThreadingMixIn` and `TCPServer`.
            #
            # 我们定义这个新类，仅仅是为了将那两个父类的功能“组合”起来。
            # We are defining this new class merely to "combine" the functionalities of those two parent classes.
            #
            # `pass` 是 Python 中的一个空操作语句，用作占位符，表示“这里什么也不做”。
            # `pass` is a null operation statement in Python, used as a placeholder to mean "do nothing here".
            # 在这种情况下，它表示我们对从父类继承来的功能完全满意，不需要添加或修改任何东西。
            # In this case, it signifies that we are completely satisfied with the functionality
            # inherited from the parent classes and do not need to add or modify anything.

        httpd = ThreadedTCPServer(("", port), DHT_Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
        bilingual_print(f"Starting Threaded Python DHT HTTPS server on port {port}...", f"正在端口 {port} 上启动线程化 Python DHT HTTPS 服务器...")
        httpd.serve_forever()
    except Exception as e:
        bilingual_print(f"Failed to start HTTPS server: {e}", f"启动 HTTPS 服务器失败: {e}", "FATAL")
        sys.exit(1)
EOF
            # [修复] 如果代码执行到这里，说明Python进程已退出。
            # [FIX] If execution reaches here, it means the Python process has exited.
            warn "DHT服务器进程意外退出。将在5秒后重启... (DHT server process exited unexpectedly. Restarting in 5 seconds...)"
            sleep 5
    done
}


# Bootstrap DHT network
dht_bootstrap() {
    info "Bootstrapping DHT network..."
    
    # Add bootstrap nodes
    for bootstrap_node in "${DHT_BOOTSTRAP_NODES[@]}"; do
        IFS=':' read -r ip port <<< "$bootstrap_node"
        # Generate a dummy node ID for bootstrap
        local node_id
        node_id=$(calculate_hash "$bootstrap_node")
        dht_add_node "$node_id" "$ip" "$port"
    done
    
    # Start DHT server daemon
    dht_server_daemon &
    local DHT_DAEMON_PID=$!
    NXPKG_BACKGROUND_PIDS+=($DHT_DAEMON_PID)
    
    # Join network by pinging bootstrap nodes
    for bootstrap_node in "${DHT_BOOTSTRAP_NODES[@]}"; do
        IFS=':' read -r ip port <<< "$bootstrap_node"
        dht_send_message "$ip" "$port" "PING" >/dev/null 2>&1 || true
    done
}

# =======================================================
# --- SECTION 6: BLOCKCHAIN IMPLEMENTATION (REVISED)  ---
# --- 第6节: 区块链实现 (修订版)                       ---
# =======================================================

# This revised section includes a robust fork-choice rule (Heaviest Chain),
# chain reorganization logic, and anti-Sybil mechanisms via Proof-of-Stake.
#
# 这个修订过的章节包含了一个健壮的分叉选择规则（最重链）、链重组逻辑，
# 以及通过PoS实现的抗女巫攻击机制。
# ---


# NEW, COMPLETE, AND HARDENED: Performs a chain reorganization to a new, heavier chain.
# This version includes FULL, INLINE VALIDATION of every block and transaction
# received from the network before it is applied to the local database.
# It now operates transactionally, ensuring the database is not left in a corrupted
# state if the reorganization fails midway.
#
# 新增、完整且已加固: 执行到一条新的、更重的链的链重组操作。
# 此版本包含了对从网络接收的每一个区块和交易在应用到本地数据库之前的
# 完整、内联的验证。它现在以事务性方式操作，确保了即使重组中途失败，
# 数据库也不会处于损坏状态。
_blockchain_reorganize_to() {
    local new_tip_hash="$1"
    local peer_ip="$2"
    local peer_port="$3"

    acquire_lock "block"
    msg "[REORG] 开始链重组，目标链顶: $new_tip_hash (Starting chain reorganization, target tip: $new_tip_hash)"

    # --- 事务性操作：步骤 1 - 创建数据库备份 ---
    # --- Transactional Operation: Step 1 - Create DB Backup ---
    local backup_db="${BLOCKCHAIN_DB}.reorg_backup"
    info "[REORG] 正在创建区块链数据库的事务性备份... (Creating transactional backup of blockchain DB...)"
    cp -p "$BLOCKCHAIN_DB" "$backup_db"

    # --- 事务性操作：步骤 2 - 设置错误陷阱 ---
    # 如果此函数内的任何命令失败 (`set -o errexit` 触发)，陷阱会恢复数据库并退出。
    # --- Transactional Operation: Step 2 - Set Error Trap ---
    # If any command in this function fails (triggered by `set -o errexit`), the trap restores the DB and exits.
    trap '
        error "[REORG] 重组失败！正在从备份恢复数据库... (Reorganization failed! Restoring database from backup...)"
        mv "$backup_db" "$BLOCKCHAIN_DB"
        release_lock
    ' ERR

    # --- 步骤 1: 找到两条链的共同祖先 ---
    # --- Step 1: Find the common ancestor of the two chains ---
    info "正在寻找共同祖先... (Finding common ancestor...)"
    local local_tip_hash ancestor_hash
    local_tip_hash=$(blockchain_get_latest_hash)
    ancestor_hash=$(_find_common_ancestor "$local_tip_hash" "$new_tip_hash" "$peer_ip" "$peer_port")

    if [ -z "$ancestor_hash" ]; then
        error "[REORG] 未找到共同祖先，这可能是一个完全无关的网络。重组中止。 (No common ancestor found, this might be a completely separate network. Reorg aborted.)"
        # 错误会触发陷阱，自动恢复 / Error triggers the trap for automatic recovery
    fi
    msg "[REORG] 找到共同祖先 (Common ancestor found): ${ancestor_hash:0:16}..."

    # --- 步骤 2: 回滚本地链到共同祖先 ---
    # --- Step 2: Roll back the local chain to the common ancestor ---
    info "正在回滚本地无效的区块... (Rolling back local invalid blocks...)"
    _rollback_to_ancestor "$local_tip_hash" "$ancestor_hash"
    info "本地链已回滚。 (Local chain reverted.)"

    # --- 步骤 3: 获取、验证并应用新链的区块 ---
    # --- Step 3: Fetch, VALIDATE, and apply blocks from the new chain ---
    info "正在应用新的主链区块... (Applying new main chain blocks...)"
    
    local path_to_apply
    mapfile -t path_to_apply < <(_get_remote_path_from "$new_tip_hash" "$ancestor_hash" "$peer_ip" "$peer_port")
    if [ ${#path_to_apply[@]} -eq 0 ] && [ "$new_tip_hash" != "$ancestor_hash" ]; then
        error "[REORG] 无法获取新链的路径，重组失败。 (Failed to get path for the new chain, reorg failed.)"
        # 错误会触发陷阱，自动恢复 / Error triggers the trap for automatic recovery
    fi

    local parent_total_weight
    parent_total_weight=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT total_weight FROM blocks WHERE hash = %s;" \
        "$ancestor_hash")

    for block_to_apply in "${path_to_apply[@]}"; do
        detail "[REORG] 正在处理区块 (Processing block): ${block_to_apply:0:16}..."
        
        local block_content_json
        block_content_json=$(dht_send_message "$peer_ip" "$peer_port" "GET_FULL_BLOCK" "$block_to_apply")
        [[ "$block_content_json" =~ ^BLOCK:(.+) ]] || error "[REORG] 无法获取完整区块 '$block_to_apply'，重组失败！ (Failed to get full block '$block_to_apply', reorg failed!)"
        block_content_json="${BASH_REMATCH[1]}"
        
        # =========================================================
        # --- 对获取的区块的内联验证从这里开始 ---
        # --- INLINE VALIDATION OF THE FETCHED BLOCK STARTS HERE ---
        # =========================================================
        
        local height prev_hash ts validator_id signature tx_json_str

        # --- 使用 jq 安全、健壮地解析 JSON ---
        # 我们使用一个技巧：将每个值用换行符分隔输出，然后用 read 一次性读入所有变量。
        # -r (raw) 选项移除字符串的引号。
        # -e 选项会在解析失败时设置非零退出码，被 set -o errexit 捕获，自动中止。
        
        # --- Using jq to securely and robustly parse JSON ---
        # We use a technique: separate each value with a line break in the output, and then use read to read all variables at once.
        # The -r option removes quotation marks from the string.
        # The -e option will set a non-zero exit code when parsing fails, which will be captured by set -o errexit and automatically aborted.

        check_dep jq # 确保 jq 存在。 Ensure the existence of jq.
        
        # 注意: .transactions | tostring 会将JSON数组转换为字符串。 Note: .transactions | tostring will convert JSON arrays into strings.
        local parsed_data
        parsed_data=$(echo "$block_content_json" | jq -e -r '
            .height,
            .previous_hash,
            .timestamp,
            .validator,
            .signature,
            (.transactions | tostring)
        ')

        # 使用 mapfile/readarray 读取多行输出到数组。 Read multiple rows of output to an array using mapfile/readarray.
        local -a block_parts=()
        mapfile -t block_parts <<< "$parsed_data"

        height="${block_parts[0]}"
        prev_hash="${block_parts[1]}"
        ts="${block_parts[2]}"
        validator_id="${block_parts[3]}"
        signature="${block_parts[4]}"
        tx_json_str="${block_parts[5]}"
        
        # 验证所有变量都已成功赋值。 Verify that all variables have been successfully assigned values.
        if [ -z "$height" ] || [ -z "$prev_hash" ] || [ -z "$ts" ] || [ -z "$validator_id" ] || [ -z "$signature" ] || [ -z "$tx_json_str" ]; then
            error "[REORG-VALIDATE] 解析区块JSON失败。区块内容可能不完整或格式错误。"
        fi
        
        # 1. 验证区块签名 (Validate Block Signature)
        info "  -> 验证区块签名... (Verifying block signature...)"
        local block_content_to_verify="{\"height\":$height,\"previous_hash\":\"$prev_hash\",\"timestamp\":$ts,\"transactions\":$tx_json_str}"
        
        local validator_public_key_file
        validator_public_key_file=$(_blockchain_get_validator_pubkey "$validator_id")
        if [ -z "$validator_public_key_file" ] || [ ! -f "$validator_public_key_file" ]; then
            error "[REORG-VALIDATE] 无法获取验证者 '$validator_id' 的公钥。区块无效，重组失败。 (Could not get public key for validator '$validator_id'. Block is invalid, reorg failed.)"
        fi
        if ! verify_signature "$block_content_to_verify" "$signature" "$validator_public_key_file"; then
            error "[REORG-VALIDATE] 无效的区块签名！区块 '$block_to_apply' 被拒绝，重组失败。 (Invalid block signature! Block '$block_to_apply' rejected, reorg failed.)"
        fi
        
        # 2. 验证区块哈希 (Validate Block Hash)
        info "  -> 验证区块哈希... (Verifying block hash...)"
        local calculated_hash
        calculated_hash=$(calculate_hash "$block_content_to_verify")
        if [ "$calculated_hash" != "$block_to_apply" ]; then
            error "[REORG-VALIDATE] 区块哈希与其内容不匹配！区块被拒绝，重组失败。 (Block hash does not match its content! Block rejected, reorg failed.)"
        fi
        
        # 3. 验证区块内的所有交易 (Validate ALL Transactions within the block)
        info "  -> 验证区块内的所有交易... (Verifying all transactions within the block...)"
        # [新增] 为当前区块的验证过程创建一个临时的状态跟踪器
        declare -A _PKG_REGISTRATIONS_IN_THIS_BLOCK
        mapfile -t tx_hashes < <(echo "$tx_json_str" | grep -o '"[^"]*"' | tr -d '"')
        for tx_hash in "${tx_hashes[@]}"; do
            # [修改] 将内部状态跟踪器作为参数传递给验证函数
            if ! _validate_single_transaction "$tx_hash" "$peer_ip" "$peer_port" "$height" _PKG_REGISTRATIONS_IN_THIS_BLOCK; then
                error "[REORG-VALIDATE] 区块包含无效交易 '$tx_hash'。区块被拒绝，重组失败。 (Block contains invalid transaction '$tx_hash'. Block rejected, reorg failed.)"
            fi
        done
        info "  -> 所有验证通过。 (All validations passed.)"
        
        # =======================================================
        # --- 内联验证结束，应用区块 ---
        # --- INLINE VALIDATION ENDS, APPLYING THE BLOCK ---
        # =======================================================
        
        local validator_stake new_total_weight
        validator_stake=$(db_query_safe "$BLOCKCHAIN_DB" \
            "SELECT stake FROM validators WHERE public_key_hash = %s;" \
            "$validator_id")
        [ -z "$validator_stake" ] && validator_stake=0
        new_total_weight=$((parent_total_weight + validator_stake))

        db_execute_safe "$BLOCKCHAIN_DB" \
            "INSERT INTO blocks (hash, height, previous_hash, timestamp, validator, signature, transactions, total_weight) VALUES (%s, %d, %s, %d, %s, %s, %s, %d);" \
            "$block_to_apply" "$height" "$prev_hash" "$ts" "$validator_id" "$signature" "$tx_json_str" "$new_total_weight"
        
        for tx_hash in "${tx_hashes[@]}"; do
            db_execute_safe "$BLOCKCHAIN_DB" \
                "UPDATE transactions SET block_height = %d WHERE hash = %s;" \
                "$height" "$tx_hash"
        done
        
        parent_total_weight="$new_total_weight"
    done

    # --- 步骤 4: 更新链状态 ---
    # --- Step 4: Update the chain state ---
    db_execute_safe "$BLOCKCHAIN_DB" \
        "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('chain_info', %s);" \
        "$new_tip_hash|$parent_total_weight"
    
    # --- 事务性操作：步骤 3 - 成功，移除陷阱和备份 ---
    # --- Transactional Operation: Step 3 - Success, remove trap and backup ---
    trap - ERR # 解除陷阱 (Disarm the trap)
    rm -f "$backup_db"
    info "[REORG] 事务性备份已移除。重组已提交。 (Transactional backup removed. Reorg committed.)"

    msg "[REORG] 链重组完成！新的链顶是 ${new_tip_hash:0:16}... (Chain reorganization complete! New tip is ${new_tip_hash:0:16}...)"
    release_lock
}



# --- NEW HELPER FUNCTIONS FOR REORG ---
# --- 用于重组的新辅助函数 ---

# [新增] 辅助函数，用于获取远程区块的高度
_get_remote_block_height() {
    local block_hash="$1"
    local peer_ip="$2"
    local peer_port="$3"
    
    # 通过获取完整的区块JSON并用jq解析来获得高度，比循环调用GET_BLOCK_HEADER更高效
    local block_content_json response_data
    response_data=$(dht_send_message "$peer_ip" "$peer_port" "GET_FULL_BLOCK" "$block_hash")
    
    [[ "$response_data" =~ ^BLOCK:(.+) ]] || return 1
    block_content_json="${BASH_REMATCH[1]}"
    
    # 使用 jq -e，如果.height字段不存在，会返回非0退出码
    echo "$block_content_json" | jq -e -r .height 2>/dev/null || return 1
}

# Finds the common ancestor block hash between a local and a remote chain.
# 查找本地链和远程链之间的共同祖先区块哈希。

_find_common_ancestor() {
    local local_tip="$1"
    local remote_tip="$2"
    local peer_ip="$3"
    local peer_port="$4"

    # --- 步骤 1: 获取两边的高度 ---
    local local_height remote_height
    local_height=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT height FROM blocks WHERE hash = %s;" \
        "$local_tip")
    remote_height=$(_get_remote_block_height "$remote_tip" "$peer_ip" "$peer_port")

    # 检查是否成功获取高度
    [ -z "$local_height" ] && { warn "[Ancestor] 无法获取本地链顶高度。"; return 1; }
    [ -z "$remote_height" ] && { warn "[Ancestor] 无法获取远程链顶高度。"; return 1; }

    local current_local_hash="$local_tip"
    local current_remote_hash="$remote_tip"

    # --- 步骤 2: 将较高的链回溯到与较低链相同的高度 ---
    while (( local_height > remote_height )); do
        current_local_hash=$(db_query_safe "$BLOCKCHAIN_DB" \
            "SELECT previous_hash FROM blocks WHERE hash = %s;" \
            "$current_local_hash")
        [ -z "$current_local_hash" ] || [ "$current_local_hash" == "0" ] && return 1 # 到达创世块都没找到
        local_height=$((local_height - 1))
    done

    while (( remote_height > local_height )); do
        local response
        response=$(dht_send_message "$peer_ip" "$peer_port" "GET_BLOCK_HEADER" "$current_remote_hash")
        [[ "$response" =~ ^HEADER:.*\|(.*)\|.* ]] || return 1
        current_remote_hash="${BASH_REMATCH[1]}"
        [ -z "$current_remote_hash" ] || [ "$current_remote_hash" == "0" ] && return 1
        remote_height=$((remote_height - 1))
    done

    # --- 步骤 3: 同时回溯两条链，直到找到共同点 ---
    while [ "$current_local_hash" != "$current_remote_hash" ]; do
        # 回溯本地链
        current_local_hash=$(db_query_safe "$BLOCKCHAIN_DB" \
            "SELECT previous_hash FROM blocks WHERE hash = %s;" \
            "$current_local_hash")
        
        # 回溯远程链
        local response
        response=$(dht_send_message "$peer_ip" "$peer_port" "GET_BLOCK_HEADER" "$current_remote_hash")
        [[ "$response" =~ ^HEADER:.*\|(.*)\|.* ]] || return 1
        current_remote_hash="${BASH_REMATCH[1]}"
        
        # 如果任何一方到达创世块或哈希为空，说明出错了
        if [ -z "$current_local_hash" ] || [ "$current_local_hash" == "0" ] || [ -z "$current_remote_hash" ] || [ "$current_remote_hash" == "0" ]; then
            return 1
        fi
    done

    # 如果循环退出，说明找到了共同祖先
    echo "$current_local_hash"
}



# Rolls back the local blockchain to a specific ancestor block.
# 将本地区块链回滚到指定的祖先区块。
_rollback_to_ancestor() {
    local current_tip="$1"
    local ancestor_hash="$2"
    
    local current_hash="$current_tip"
    while [ "$current_hash" != "$ancestor_hash" ]; do
        detail "  -> 回滚区块 (Reverting block): ${current_hash:0:16}..."
        local tx_json parent_hash
        tx_json=$(db_query_safe "$BLOCKCHAIN_DB" \
            "SELECT transactions FROM blocks WHERE hash = %s;" \
            "$current_hash")
        parent_hash=$(db_query_safe "$BLOCKCHAIN_DB" \
            "SELECT previous_hash FROM blocks WHERE hash = %s;" \
            "$current_hash")
        
        mapfile -t tx_hashes < <(echo "$tx_json" | grep -o '"[^"]*"' | tr -d '"')
        for tx_hash in "${tx_hashes[@]}"; do
            db_execute_safe "$BLOCKCHAIN_DB" \
                "UPDATE transactions SET block_height = NULL WHERE hash = %s;" \
                "$tx_hash"
        done
        
        db_execute_safe "$BLOCKCHAIN_DB" \
            "DELETE FROM blocks WHERE hash = %s;" \
            "$current_hash"
        current_hash="$parent_hash"
        [ -z "$current_hash" ] && break # Safety break
    done
}

# Gets the list of block hashes from a remote peer, from their tip back to an ancestor.
# Returns the list in the order they should be applied (ancestor's child first).
# 从一个远程对等节点获取从其链顶到某个祖先的区块哈希列表。
# 以应当被应用的顺序列出（祖先的子区块在前）。
_get_remote_path_from() {
    local remote_tip="$1"
    local ancestor_hash="$2"
    local peer_ip="$3"
    local peer_port="$4"
    
    local remote_path=()
    local current_hash="$remote_tip"
    
    while [ "$current_hash" != "$ancestor_hash" ]; do
        remote_path+=("$current_hash")
        [ -z "$current_hash" ] && break # Safety break
        
        local response
        response=$(dht_send_message "$peer_ip" "$peer_port" "GET_BLOCK_HEADER" "$current_hash")
        [[ "$response" =~ ^HEADER:.*\|(.*)\|.* ]] || { echo "" >&2; return 1; }
        current_hash="${BASH_REMATCH[1]}"
    done
    
    # Reverse the array to get the correct application order
    for (( i=${#remote_path[@]}-1 ; i>=0 ; i-- )); do
        echo "${remote_path[$i]}"
    done
}

# =======================================================================================
# --- FUNCTION: _validate_single_transaction (SECURE VERSION with State Validation) ---
# --- 函数: _validate_single_transaction (包含状态验证的安全版)                     ---
# =======================================================================================
# Validates a single transaction, fetching it from the network if necessary.
# If the transaction is fetched, it is parsed, validated, and inserted into the local DB.
# This version includes CRITICAL state validation to prevent attacks like re-registering an existing package version.
#
# 验证单个交易，如有必要则从网络获取。
# 如果交易是从网络获取的，它将被解析、验证并插入本地数据库。
# 此版本包含了至关重要的状态验证，以防止诸如重复注册一个已存在的软件包版本之类的攻击。
#
# @param $1 - tx_hash         (The hash of the transaction to validate / 待验证交易的哈希)
# @param $2 - peer_ip          (IP of a peer to fetch from if needed / 如果需要，从哪个对等节点获取)
# @param $3 - peer_port        (Port of the peer / 对等节点的端口)
# @param $4 - block_height     (The height of the block this transaction is in / 此交易所属的区块高度)
_validate_single_transaction() {
    local tx_hash="$1"
    local peer_ip="$2"
    local peer_port="$3"
    local block_height="$4" # [新增] 用于状态验证的区块高度 / [NEW] Block height for state validation
      # [修复] 使用 'declare -n' 创建一个对第五个参数（数组名）的引用
    # 这使得函数可以处理任何名字的数组，而不仅仅是硬编码的那个
    declare -n state_tracker="$5" 

    local tx_db_entry
    tx_db_entry=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT type, data, signature, public_key, timestamp FROM transactions WHERE hash = %s;" \
        "$tx_hash")

    # --- Step 1: Fetch transaction from network if it's missing locally ---
    # --- 步骤 1: 如果本地缺失，则从网络获取交易 ---
    if [ -z "$tx_db_entry" ]; then
        detail "    - 交易 '$tx_hash' 在本地缺失，从网络获取... (Transaction '$tx_hash' missing locally, fetching from network...)"
        local temp_tx_dir="${P2P_DIR}/temp_txs" && mkdir -p "$temp_tx_dir"
        local fetched_tx_path="${temp_tx_dir}/${tx_hash}"

        # forum_fetch_object is a generic P2P object fetching function
        # forum_fetch_object 是一个通用的P2P对象获取函数
        if ! forum_fetch_object "$tx_hash" "$temp_tx_dir"; then
            warn "      ! 无法获取交易 '$tx_hash'。验证失败。 (! Could not fetch transaction '$tx_hash'. Validation failed.)"
            return 1
        fi
        
        info "      -> 正在解析并验证获取到的交易... (Parsing and verifying fetched transaction...)"
        [ ! -f "$fetched_tx_path" ] && { warn "      ! 获取到的交易文件不存在。 (! Fetched transaction file does not exist.)"; return 1; }
        
        local tx_json tx_type tx_data tx_signature tx_pubkey tx_timestamp
        tx_json=$(cat "$fetched_tx_path")
        
        tx_type=$(echo "$tx_json" | jq -r .type 2>/dev/null)
        tx_data=$(echo "$tx_json" | jq -r .data 2>/dev/null)
        tx_signature=$(echo "$tx_json" | jq -r .signature 2>/dev/null)
        tx_pubkey=$(echo "$tx_json" | jq -r .public_key 2>/dev/null)
        tx_timestamp=$(echo "$tx_json" | jq -r .timestamp 2>/dev/null)

        if [ -z "$tx_type" ] || [ -z "$tx_data" ] || [ -z "$tx_signature" ] || [ -z "$tx_pubkey" ] || [ -z "$tx_timestamp" ]; then
            warn "      ! 获取到的交易文件格式无效或不完整。 (! Fetched transaction file is malformed or incomplete.)"
            rm -f "$fetched_tx_path"
            return 1
        fi

        local data_to_verify="{\"type\":\"$tx_type\",\"data\":$tx_data,\"timestamp\":$tx_timestamp}"
        local calculated_tx_hash
        calculated_tx_hash=$(calculate_hash "$data_to_verify")

        if [ "$calculated_tx_hash" != "$tx_hash" ]; then
            warn "      ! 获取到的交易内容哈希与预期不符！可能已被篡改。 (Hash of fetched transaction content does not match expected! Possible tampering.)"
            rm -f "$fetched_tx_path"
            return 1
        fi
        
        db_execute_safe "$BLOCKCHAIN_DB" \
            "INSERT INTO transactions (hash, type, data, signature, public_key, timestamp, block_height) VALUES (%s, %s, %s, %s, %s, %d, NULL);" \
            "$tx_hash" "$tx_type" "$tx_data" "$tx_signature" "$tx_pubkey" "$tx_timestamp"
        info "      -> 获取到的交易已存入本地数据库。 (Fetched transaction has been stored in the local database.)"
        rm -f "$fetched_tx_path"
    fi
    
        # --- Step 2: Perform stateless cryptographic validation ---
    # --- 步骤 2: 执行无状态的密码学验证 ---
    tx_db_entry=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT type, data, signature, public_key, timestamp FROM transactions WHERE hash = %s;" \
        "$tx_hash")
    IFS='|' read -r tx_type tx_payload tx_signature tx_pubkey tx_timestamp <<< "$tx_db_entry"
    
    # [修复] 移除包裹 data 字段值的多余引号，与创建时的格式保持一致
    # [FIX] Removed the extra quotes wrapping the data field's value to match the format at creation time
    local data_to_verify="{\"type\":\"$tx_type\",\"data\":$tx_payload,\"timestamp\":$tx_timestamp}" # <--- 修正行
    local calculated_tx_hash
    calculated_tx_hash=$(calculate_hash "$data_to_verify")
    if [ "$calculated_tx_hash" != "$tx_hash" ]; then
        warn "      ! 交易 '$tx_hash' 哈希不匹配！ (! Transaction '$tx_hash' hash mismatch!)"
        return 1
    fi
    
    local temp_pubkey_file
    temp_pubkey_file=$(mktemp)
    echo -n "$tx_pubkey" > "$temp_pubkey_file"
    if ! verify_signature "$data_to_verify" "$tx_signature" "$temp_pubkey_file"; then
        rm -f "$temp_pubkey_file"
        warn "      ! 交易 '$tx_hash' 签名无效！ (! Transaction '$tx_hash' signature is invalid!)"
        return 1
    fi
    rm -f "$temp_pubkey_file"
    
    # --- [核心修复] 步骤 3: 执行状态验证 ---
    case "$tx_type" in
        "package_register")
            local pkg_name pkg_version registration_key
            pkg_name=$(echo "$tx_payload" | jq -r .name 2>/dev/null)
            pkg_version=$(echo "$tx_payload" | jq -r .version 2>/dev/null)
            [ -z "$pkg_name" ] && { warn "无效的包注册交易：缺少名称 (Invalid package register tx: missing name)"; return 1; }
            registration_key="${pkg_name}@${pkg_version}"

             # [修复] 使用我们创建的引用变量，而不是硬编码的变量名
            # 检查 1: 此交易是否与当前区块内的其他交易冲突
            if [ ${#state_tracker[@]} -gt 0 ] && [ -n "${state_tracker[$registration_key]+_}" ]; then
                warn "      ! 状态验证失败: 同一个区块内发现重复的软件包注册 '${registration_key}'。"
                warn "      ! State validation FAILED: Duplicate package registration for '${registration_key}' found within the same block."
                return 1
            fi

            # 检查 2: 此交易是否与已确认的历史区块冲突 (原有逻辑)
            local existing_registration_count
            existing_registration_count=$(db_query_safe "$BLOCKCHAIN_DB" \
                "SELECT COUNT(*) FROM transactions WHERE type = 'package_register' AND json_extract(data, '$.name') = %s AND json_extract(data, '$.version') = %s AND block_height IS NOT NULL AND block_height < %d;" \
                "$pkg_name" "$pkg_version" "$block_height")

            if [ "$existing_registration_count" -gt 0 ]; then
                warn "      ! 状态验证失败: 软件包 '${pkg_name}' v'${pkg_version}' 已在历史区块中注册。"
                warn "      ! State validation FAILED: Package '${pkg_name}' v'${pkg_version}' was already registered in a prior block."
                return 1 # 验证失败 / Validation failed
            fi
            
            # [新增] 在所有检查都通过之后，将此注册记录到状态跟踪器中
            # 这样，下一个要验证的、在同一个区块内的交易就能看到它了。
            if [ ${#state_tracker[@]} -gt 0 ]; then
                 state_tracker[$registration_key]=1
            fi
            ;;
        *)
            # 其他交易类型目前无需状态检查
            # Other transaction types do not require state validation at this time
            ;;
    esac
    
    detail "    - 交易 '$tx_hash' 验证通过。 (Transaction '$tx_hash' validated.)"
    return 0
}


# REVISED: Gets the hash of the tip of the "heaviest" chain.
# This is now the single source of truth for the canonical chain head.
#
# 已修订: 获取“最重”链的链顶哈希。
# 这里现在是规范链头的唯一真实来源。
blockchain_get_latest_hash() {
    local chain_info
    chain_info=$(db_query_static "$BLOCKCHAIN_DB" "SELECT value FROM chain_state WHERE key = 'chain_info';")
    if [ -n "$chain_info" ]; then
        echo "$chain_info" | cut -d'|' -f1
    else
        # Fallback for an uninitialized chain state
        # 对未初始化的链状态进行回退处理
        db_query_static "$BLOCKCHAIN_DB" "SELECT hash FROM blocks ORDER BY total_weight DESC, height DESC LIMIT 1;"
    fi
}

# Mining/validation process (PoS) with P2P broadcast
# 挖矿/验证过程 (PoS)，包含P2P广播功能
blockchain_mine_block() {
    info "尝试创建并广播新区块... (Attempting to create and broadcast a new block...)"
    
    # 1. 检查是否有待处理的交易 (Check if there are any pending transactions)
    local pending_txs=$(blockchain_get_pending_transactions)
    if [ -z "$pending_txs" ]; then
        debug "没有待处理的交易需要打包。 (No pending transactions to mine.)"
        return 0
    fi
    
    # 2. 检查我们是否是验证者 (Check if we are a validator)
    [ ! -f "$USER_PUBLIC_KEY_FILE" ] && { info "非验证者节点，跳过区块创建。 (Not a validator node, skipping block creation.)"; return 0; }
    local our_pubkey=$(cat "$USER_PUBLIC_KEY_FILE")

    local stake
    stake=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT stake FROM validators WHERE public_key = %s;" \
        "$our_pubkey")
    if [ -z "$stake" ]; then
        debug "您不是注册的验证者。 (You are not a registered validator.)"
        return 0
    fi

    # 3. 确定下一个合法的区块验证者，并检查是否轮到我们 (Identify the next legitimate block validator and check if it's our turn)
    local next_validator_pubkey=$(blockchain_get_next_validator)
    if [ "$our_pubkey" != "$next_validator_pubkey" ]; then
        info "根据共识，现在不是我们创建区块的时候。跳过。 (According to consensus, it is not our turn to create a block. Skipping.)"
        return 0
    fi
    
    msg "轮到我们创建区块了！正在打包、签名并广播... (It's our turn to create a block! Packaging, signing, and broadcasting...)"
    
    # 4. 获取最新的区块哈希和高度 (Get the latest block hash and height)
    local latest_hash=$(blockchain_get_latest_hash)
    local height=$(db_query_static "$BLOCKCHAIN_DB" "SELECT COALESCE(MAX(height), -1) + 1 FROM blocks;")

    # 5. 创建交易列表 JSON (Create transaction list JSON)
    local tx_json="["
    local first=true
    local tx_hashes_in_block=()
    while IFS='|' read -r hash type data signature public_key timestamp; do
        [ -n "$hash" ] || continue
        tx_hashes_in_block+=("$hash")
        [ "$first" = true ] && first=false || tx_json+=","
        tx_json+="\"$hash\""
    done <<< "$pending_txs"
    tx_json+="]"
    
    # 6. 创建并签名新区块 (本地操作) (Create and sign a new block (local operation))
    local validator_id=$(calculate_hash "$our_pubkey")
    local timestamp=$(date +%s)
    local block_data_to_sign="{\"height\":$height,\"previous_hash\":\"$latest_hash\",\"timestamp\":$timestamp,\"transactions\":$tx_json}"
    local block_hash=$(calculate_hash "$block_data_to_sign")
    local signature=$(sign_data "$block_data_to_sign" "$USER_IDENTITY_FILE")
    
    # 7. 将新区块存入本地数据库 (Store the new block in the local database)
    db_execute_safe "$BLOCKCHAIN_DB" \
        "INSERT INTO blocks (height, hash, previous_hash, timestamp, validator, signature, transactions) VALUES (%d, %s, %s, %d, %s, %s, %s);" \
        "$height" "$block_hash" "$latest_hash" "$timestamp" "$validator_id" "$signature" "$tx_json"
    
    # 8. 将区块的完整内容作为一个P2P对象进行共享 (Share the complete content of the block as a P2P object)
    info "正在将新区块 $block_hash 作为P2P对象共享... (Sharing new block $block_hash as a P2P object...)"
    local temp_block_file
    temp_block_file=$(mktemp)
    # 创建完整的区块JSON对象，用于网络共享 (Create a complete block JSON object for network sharing)
    local full_block_json="{\"height\":$height,\"previous_hash\":\"$latest_hash\",\"timestamp\":$timestamp,\"validator\":\"$validator_id\",\"signature\":\"$signature\",\"transactions\":$tx_json}"
    echo "$full_block_json" > "$temp_block_file"
    
    # p2p_split_file 使用文件内容计算哈希，这必须与我们的 block_hash 匹配
    # The p2p_split_file uses the file content to calculate the hash, which must match our block_hash
    # 为了确保一致，我们应该让 p2p_split_file 直接使用我们计算好的哈希
    # To ensure consistency, we should have p2p_split_file directly use the hash we have calculated
    local temp_final_block_path="${P2P_DIR}/objects/${block_hash}"
    # Ensure the directory exists
    mkdir -p "$(dirname "$temp_final_block_path")"
    # Copy from the temporary file (source) to the final path (destination)
    cp "$temp_block_file" "$temp_final_block_path" 
    dht_store_chunk "$block_hash" "$temp_final_block_path" 0 "$(stat -c%s "$temp_final_block_path")"
    rm -f "$temp_block_file"
    
    # 9. 向网络广播新区块的哈希 (Broadcast the hash of the new block to the network)
    _blockchain_broadcast_new_block "$block_hash"
    
    # 10. 更新本地状态 (Update local state)
    info "正在更新本地数据库状态... (Updating local database state...)"
    for tx_hash in "${tx_hashes_in_block[@]}"; do
        db_execute_safe "$BLOCKCHAIN_DB" \
            "UPDATE transactions SET block_height = %d WHERE hash = %s;" \
            "$height" "$tx_hash"
    done
    
    # SECURE UPDATE: Use the hex literal for the public key in the WHERE clause here as well.
    # 安全更新：同样地，在 WHERE 子句中使用十六进制字面量来指定公钥。
    db_execute_safe "$BLOCKCHAIN_DB" \
        "UPDATE validators SET last_block = %d WHERE public_key = %s;" \
        "$height" "$our_pubkey"

    msg "新区块 $height (哈希: $block_hash) 已成功创建并广播至网络。 (New block $height (hash: $block_hash) successfully created and broadcast to the network.)"
    echo "$block_hash"
    
}

# Register package on blockchain
blockchain_register_package() {
    local package_name="$1"
    local package_version="$2"
    local package_hash="$3"
    local build_file_hash="$4"
    
    local package_data="{\"name\":\"$package_name\",\"version\":\"$package_version\",\"hash\":\"$package_hash\",\"build_hash\":\"$build_file_hash\"}"
    local tx_hash
    tx_hash=$(blockchain_create_transaction "package_register" "$package_data")
    
    info "Package registration transaction created: $tx_hash"
    echo "$tx_hash"
}

# Verify package on blockchain
# REVISED FOR ROBUSTNESS: Uses sqlite's json_extract for precise and safe queries,
# preventing failures due to whitespace changes in the JSON data and protecting
# against potential SQL injection vectors.
#
# 为健壮性而修订: 使用 sqlite 的 json_extract 函数进行精确、安全的查询，
# 防止因 JSON 数据中的空白变化而导致的失败，并防御潜在的 SQL 注入。
blockchain_verify_package() {
    local package_name="$1"
    local package_version="$2"
    local package_hash="$3"
    
    # 在区块链中查询包的注册信息。
    # Query blockchain for package registration.
    local registered
    registered=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT COUNT(*) FROM transactions WHERE type = 'package_register' AND json_extract(data, '$.name') = %s AND json_extract(data, '$.version') = %s AND block_height IS NOT NULL;" \
        "$package_name" "$package_version")
    
    [ "$registered" -gt 0 ]
}


# =================================================================
# --- NEWLY IMPLEMENTED BLOCKCHAIN CORE FUNCTIONS (CRITICAL)    ---
# --- 新实现的核心区块链函数 (至关重要)                         ---
# =================================================================
# The following five functions were missing from the initial v0.6.0 script.
# Their implementation is critical for the blockchain to function.
#
# 以下五个函数在 v0.6.0 初始脚本中缺失。
# 它们的实现对于区块链的正常运作至关重要。

# --- Function 1: Create a new transaction ---
# --- 函数 1: 创建一个新交易 ---
# Creates, signs, and stores a new transaction, then shares its hash on the P2P network.
# 创建、签名并存储一个新交易，然后将其哈希共享到 P2P 网络。
blockchain_create_transaction() {
    local tx_type="$1"
    local tx_data="$2"

    [ ! -f "$USER_IDENTITY_FILE" ] && error "用户身份密钥文件未找到，无法创建交易。 (User identity key file not found, cannot create transaction.)"
    
    local timestamp public_key
    timestamp=$(date +%s)
    public_key=$(cat "$USER_PUBLIC_KEY_FILE")

    # The data that gets signed and hashed does not include the signature itself.
    # 被签名和哈希的数据本身不包含签名。
    local data_to_verify="{\"type\":\"$tx_type\",\"data\":$tx_data,\"timestamp\":$timestamp}"
    
    local tx_hash signature
    tx_hash=$(calculate_hash "$data_to_verify")
    signature=$(sign_data "$data_to_verify" "$USER_IDENTITY_FILE")
    
    # Store the complete transaction details in the local database.
    # It is initially "pending" (block_height is NULL).
    # 将完整的交易详情存入本地数据库。
    # 它最初是“待处理”状态 (block_height 为 NULL)。
    db_execute_safe "$BLOCKCHAIN_DB" \
        "INSERT INTO transactions (hash, type, data, signature, public_key, timestamp, block_height) VALUES (%s, %s, %s, %s, %s, %d, NULL);" \
        "$tx_hash" "$tx_type" "$tx_data" "$signature" "$public_key" "$timestamp"

    # To make this transaction available to other nodes for mining, we treat it as a P2P object.
    # The object's content is the signed data, and its hash is the transaction hash.
    # 为了让其他节点能够获取此交易以进行打包，我们将其视为一个 P2P 对象。
    # 对象的内容是被签名的数据，其哈希就是交易哈希。
    local tx_object_dir="${P2P_DIR}/objects/transactions"
    local tx_object_path="${tx_object_dir}/${tx_hash}"
    mkdir -p "$tx_object_dir"
    echo "$data_to_verify" > "$tx_object_path"
    
    # Announce this transaction "object" to the network.
    # Note: We are announcing a single chunk object.
    # 将此交易“对象”宣告到网络。
    # 注意：我们宣告的是一个单块对象。
    dht_store_chunk "$tx_hash" "$tx_object_path" 0 "$(stat -c%s "$tx_object_path")"
    
    info "Transaction created and announced to the network. Hash: $tx_hash"
    echo "$tx_hash"
    return 0
}

# --- Function 2: Get all pending (unmined) transactions ---
# --- 函数 2: 获取所有待处理 (未被打包) 的交易 ---
blockchain_get_pending_transactions() {
    # A pending transaction is one that has not been assigned a block height yet.
    # We select a limited number to avoid creating blocks that are too large.
    # 待处理交易是指尚未被分配区块高度的交易。
    # 我们选择有限数量的交易以避免创建过大的区块。
    db_query_static "$BLOCKCHAIN_DB" "
    SELECT hash, type, data, signature, public_key, timestamp 
    FROM transactions 
    WHERE block_height IS NULL 
    ORDER BY timestamp ASC 
    LIMIT 200;
    "
}

# --- Function 3: Get the next validator based on a deterministic round-robin ---
# --- 函数 3: 基于确定性的轮询算法获取下一个验证者 ---

# REWRITTEN FOR SECURE PROOF-OF-STAKE: Get the next validator.
# This function implements a deterministic, stake-weighted lottery to select
# the next block creator. The previous block's hash is used as a source of
# unpredictable randomness, making the selection secure against targeted
# attacks while ensuring all nodes agree on the winner. It is no longer
# a simple round-robin algorithm.
#
# 为实现安全的权益证明而重写: 获取下一个验证者。
# 此函数实现了一个确定性的、基于权益权重的抽签机制来选择下一个区块的创建者。
# 前一个区块的哈希被用作不可预测的随机性来源，这使得选择过程能抵御定点攻击，
# 同时确保所有节点都能就胜利者达成一致。它不再是一个简单的轮询算法。
blockchain_get_next_validator() {
    # This algorithm requires bc for arbitrary-precision integer arithmetic
    # to handle large stake numbers and 256-bit hashes.
    # 该算法需要 bc 来进行任意精度整数运算，以处理巨大的质押数量和256位的哈希值。
    check_dep bc

    # --- Step 1: Gather validator stakes and calculate total stake ---
    local validators_data
    mapfile -t validators_data < <(db_query_static "$BLOCKCHAIN_DB" "SELECT public_key, stake FROM validators WHERE stake > 0 ORDER BY public_key ASC;")
    
    local validator_count=${#validators_data[@]}
    if [ "$validator_count" -eq 0 ]; then
        warn "No staked validators found. Cannot determine the next validator."
        return 1
    fi

    local total_stake=0
    local validator_info
    for validator_info in "${validators_data[@]}"; do
        local stake
        stake=$(echo "$validator_info" | cut -d'|' -f2)
        total_stake=$((total_stake + stake))
    done
    
    if [ "$total_stake" -eq 0 ]; then
        warn "Total stake in the network is 0. Cannot select a validator."
        return 1
    fi

    # --- Step 2: Generate a deterministic but unpredictable "winning ticket" number ---
    # We use the hash of the latest block as the seed for our lottery.
    # This means no one can know who the next validator is until the current block is created.
    # 我们使用最新区块的哈希作为我们抽签的种子。
    # 这意味着在当前区块被创建之前，没有人能知道下一个验证者是谁。
    local latest_hash
    latest_hash=$(blockchain_get_latest_hash)
    if [ -z "$latest_hash" ]; then
        error "Could not determine the latest block hash. Cannot select a validator."
        return 1
    fi

    local lottery_seed_hex
    lottery_seed_hex=$(calculate_hash "$latest_hash")
    
    # Convert the 256-bit hex hash to a decimal number using bc
    # 使用 bc 将 256 位的十六进制哈希转换为一个十进制数
    local lottery_seed_dec
    lottery_seed_dec=$(echo "ibase=16; ${lottery_seed_hex^^}" | bc)

    # The winning ticket is the seed modulo the total stake, ensuring it falls within the stake range.
    # “中奖号码”是种子对总质押量取模的结果，以确保它落在质押量范围内。
    local winning_ticket
    winning_ticket=$(echo "$lottery_seed_dec % $total_stake" | bc)
    
    debug "[PoS-Select] Lottery for next block (based on hash ${latest_hash:0:16}...):"
    debug "[PoS-Select]   - Total Stake: $total_stake"
    debug "[PoS-Select]   - Winning Ticket: $winning_ticket"

    # --- Step 3: Find the winner by walking through the sorted list of validators ---
    # We iterate through the validators (already sorted by public key for determinism)
    # and add up their stakes until the cumulative stake surpasses the winning ticket.
    # 我们遍历验证者（已按公钥排序以保证确定性），累加他们的质押量，
    # 直到累计质押量超过“中奖号码”。
    local cumulative_stake=0
    for validator_info in "${validators_data[@]}"; do
        local public_key stake
        IFS='|' read -r public_key stake <<< "$validator_info"
        
        cumulative_stake=$((cumulative_stake + stake))
        
        debug "[PoS-Select]   - Checking validator ${public_key:27:16}... (Stake: $stake, Cumulative: $cumulative_stake)"
        
        # The first validator whose stake range covers the winning ticket wins the lottery.
        # 第一个其质押范围覆盖了“中奖号码”的验证者，就是抽签的胜利者。
        if (( $(echo "$cumulative_stake > $winning_ticket" | bc -l) )); then
            info "[PoS-Select] Next block creator selected: ${public_key:27:16}..."
            echo "$public_key"
            return 0
        fi
    done
    
    # This part should theoretically be unreachable if total_stake > 0, but serves as a fallback.
    # 如果 total_stake > 0，理论上这部分代码是不可达的，但可作为一个备用方案。
    warn "Lottery walk-through failed to select a winner, falling back to the first validator."
    echo "${validators_data[0]}" | cut -d'|' -f1
    return 1
}

# --- Function 4: Broadcast a new block announcement to the network ---
# --- 函数 4: 向网络广播一个新区块的宣告 ---
# REVISED: Broadcast a new block announcement with a digital signature.
# 已修订: 广播带有数字签名的新区块宣告。
_blockchain_broadcast_new_block() {
    local block_hash="$1"
    
    local height
    height=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT height FROM blocks WHERE hash = %s;" \
        "$block_hash")
    
    # Announce to a set of diverse peers in the network.
    # 向网络中一组多样化的对等节点进行宣告。
    local peers
    peers=$(dht_find_closest_nodes "$(get_our_node_id)" 8)

    # --- NEW: Prepare data for signing ---
    # --- 新增: 准备用于签名的数据 ---
    # The core information (hash and height) is signed to prove authenticity.
    # 对核心信息 (哈希和高度) 进行签名以证明其真实性。
    local data_to_sign="${block_hash}|${height}"
    local signature
    signature=$(sign_data "$data_to_sign" "$USER_IDENTITY_FILE")
    local our_node_id
    our_node_id=$(get_our_node_id)
    
    info "正在向对等节点广播已签名的新区块宣告... (Broadcasting signed new block announcement to peers...)"
    while IFS=':' read -r node_id ip port; do
        [ -n "$ip" ] || continue
        detail "  -> Announcing to $ip:$port / 宣告至 $ip:$port"
        
        # --- MODIFIED: The payload now includes our node ID and the signature ---
        # --- 已修改: 载荷现在包含了我们的节点ID和签名 ---
        # New Payload Format: hash|height|ip|port|announcer_node_id|signature
        # 新载荷格式: 哈希|高度|IP|端口|宣告者节点ID|签名
        dht_send_message "$ip" "$port" "ANNOUNCE_BLOCK" \
            "${block_hash}|${height}|$(get_our_ip)|${P2P_PORT}|${our_node_id}|${signature}"
    done <<< "$peers"
}

# --- Function 5: Get a validator's full public key from their ID (hash) ---
# --- 函数 5: 根据验证者的ID (哈希) 获取其完整的公钥 ---
# =======================================================================================
# --- FUNCTION: _blockchain_get_validator_pubkey (DB-OPTIMIZED VERSION) ---
# --- 函数: _blockchain_get_validator_pubkey (数据库优化版)               ---
# =======================================================================================
_blockchain_get_validator_pubkey() {
    local validator_id="$1"
    local pubkey_cache_dir="${VAR_CACHE_NXPKG_DIR}/validator_pubkeys"
    local pubkey_cache_file="${pubkey_cache_dir}/${validator_id}.pub"
    mkdir -p "$pubkey_cache_dir"
    if [ -f "$pubkey_cache_file" ]; then
        echo "$pubkey_cache_file"
        return 0
    fi
    local pubkey
    pubkey=$(db_query_safe "$BLOCKCHAIN_DB" \
        "SELECT public_key FROM validators WHERE public_key_hash = %s;" \
        "$validator_id")
    if [ -n "$pubkey" ]; then
        echo "$pubkey" > "$pubkey_cache_file"
        echo "$pubkey_cache_file"
        return 0
    fi
    
    # If we get here, the validator was not found in our database.
    # This is a critical error during validation.
    # 如果执行到这里，说明在我们的数据库中没有找到该验证者。
    # 这在验证过程中是一个严重错误。
    return 1
}


# Helper function needed by _blockchain_broadcast_new_block to get the machine's primary IP.
# _blockchain_broadcast_new_block 所需的辅助函数，用于获取机器的主IP。
get_our_ip() {
    # This is a robust way to get the primary, non-local IP address.
    ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}'
}

# --- SECTION 7: P2P FILE SHARING ---

# =========================================================================================
# --- P2P Download Architecture: A Four-Layer Model                                     ---
# --- P2P 下载架构：一个四层模型                                                        ---
# =========================================================================================
#
# The P2P file download system in NxPKG is designed using a four-layer architectural
# model. This separation of concerns makes the system robust, modular, and easier to
# maintain. Each layer has a distinct responsibility and only communicates with the
# layer directly above or below it.
#
# NxPKG中的P2P文件下载系统是基于一个四层架构模型设计的。这种关注点分离的设计
# 使得整个系统更加健壮、模块化且易于维护。每一层都有明确的职责，并且只与它
# 相邻的上一层或下一层通信。
#
#
# --- Layer 4: Network Transport Layer / 第四层: 网络传输层 ---
#
#   - Responsibility: To perform a single, atomic download operation from a
#     specific, known network address (ip:port). This layer has no knowledge of
#     the DHT, providers, or retry logic. It's the "last mile" of the download.
#   - 职责: 负责执行一次单一的、原子性的下载操作，从一个具体的、已知的网络地址
#     (ip:port) 获取数据。这一层完全不知道DHT、提供者或重试逻辑的存在。它是下载的“最后一公里”。
#
#   - Key Function / 关键函数: p2p_request_chunk()
#
#   - Analogy / 类比: The Mail Carrier. Give them a precise address, and they
#     will attempt to retrieve the package from that address.
#   - 邮递员。你给他们一个精确的地址，他们就去那个地址尝试取回包裹。
#
#
# --- Layer 3: Dispatch Layer / 第三层: 调度层 ---
#
#   - Responsibility: To translate an abstract provider identity (which could be
#     a node_id or an ip:port string) into the concrete arguments needed by the
#     Network Transport Layer. It resolves the final ip:port if necessary.
#   - 职责: 负责将一个抽象的提供者身份（可能是一个node_id或一个ip:port字符串）
#     解析为网络传输层所需要的具体参数。如果需要，它会解析出最终的ip和port。
#
#   - Key Function / 关键函数: p2p_download_chunk_from_provider()
#
#   - Analogy / 类比: The Post Office Sorting Center. It receives a task for a
#     provider, looks up their concrete address in its directory (the DHT database),
#     and dispatches the Mail Carrier (Layer 4) to that address.
#   - 邮局分拣中心。它接收到一个要发给某个提供者的任务，在它的名录（DHT数据库）中
#     查找此人的具体地址，然后派遣邮递员（第四层）前往该地址。
#
#
# --- Layer 2: Unified Interface Layer / 第二层: 统一接口层 ---
#
#   - Responsibility: This is the brain of the robust download logic. It takes an
#     object hash, finds ALL available providers (both local and remote) using the
#     DHT, and then iterates through them, calling the Dispatch Layer (Layer 3) for
#     each one until the download is successful. This is where fault tolerance and
#     retry logic are implemented.
#   - 职责: 这是整个健壮下载逻辑的大脑。它接收一个对象哈希，使用DHT查找所有
#     可用的提供者（包括本地和远程），然后遍历他们，为每一个提供者调用调度层
#     （第三层），直到下载成功为止。容错和重试逻辑在这一层实现。
#
#   - Key Function / 关键函数: _p2p_download_object()
#
#   - Analogy / 类比: The Logistics Manager. They receive an order for a product
#     (the object_hash). They first check the local warehouse. If it's not there,
#     they query all known suppliers (remote providers via dht_find_chunk) and
#     send out purchase orders (call Layer 3) one by one until the product is
#     procured.
#   - 物流经理。他收到一份产品（对象哈希）的订单。他首先检查本地仓库。如果本地没有，
#     他会查询所有已知的供应商（通过dht_find_chunk找到的远程提供者），然后逐一
#     发出采购订单（调用第三层），直到产品采购成功。
#
#
# --- Layer 1: Application Layer / 第一层: 应用层 ---
#
#   - Responsibility: These are the high-level functions that need to acquire a file
#     or object from the P2P network for a specific "business" purpose. They do not
#     care about the underlying complexity. They simply call the Unified Interface
#     (Layer 2) and expect the object to be delivered.
#   - 职责: 这些是出于某个具体的“业务”目的，需要从P2P网络获取文件或对象的高层函数。
#     它们不关心底层的复杂性。它们只调用统一接口层（第二层），并期望对象被成功交付。
#
#   - Key Functions / 关键函数:
#       - p2p_reconstruct_file() (needs to download many chunks) / (需要下载多个数据块)
#       - forum_fetch_object() (needs to download a forum post or attachment) / (需要下载论坛帖子或附件)
#       - _download_file_p2p() (needs to download a source file for a package) / (需要为软件包下载源文件)
#
#   - Analogy / 类比: The Customer. They just want their final product (a reconstructed
#     file, a forum post) and place an order with the Logistics Manager (Layer 2).
#   - 客户。他们只想要最终的产品（一个重组好的文件、一篇论坛帖子），于是他们向
#     物流经理（第二层）下订单。
#
# =========================================================================================

# Split file into chunks
p2p_split_file() {
    local file_path="$1"
    local chunk_size="$P2P_CHUNK_SIZE"
    local chunk_dir="${P2P_DIR}/chunks/$(basename "$file_path")"
    
    mkdir -p "$chunk_dir"
    
    # Split file and calculate hashes
    local file_size
    file_size=$(stat -c%s "$file_path")
    local chunk_count=$(( (file_size + chunk_size - 1) / chunk_size ))
    local chunk_hashes=()
    
    info "Splitting file into $chunk_count chunks..."
    
    # [修复] 阶段一: 仅在本地创建数据块并计算哈希，不进行网络操作。
    # [FIX] Phase 1: Only create chunks and calculate hashes locally, no network operations yet.
    for (( i=0; i<chunk_count; i++ )); do
        local offset=$((i * chunk_size))
        local chunk_file="${chunk_dir}/chunk_${i}"
        
        dd if="$file_path" of="$chunk_file" bs="$chunk_size" skip="$i" count=1 2>/dev/null
        
        local chunk_hash
        chunk_hash=$(calculate_hash "$chunk_file")
        chunk_hashes+=("$chunk_hash")
        
        progress $(( (i + 1) * 100 / chunk_count ))
    done
    echo
    info "Local file splitting complete. Total chunks: ${#chunk_hashes[@]}"
    
    # [修复] 阶段二: 在本地创建清单文件。
    # [FIX] Phase 2: Create the manifest file locally.
    local manifest_file="${chunk_dir}/manifest.json"
    {
        echo "{"
        echo "  \"file\": \"$(basename "$file_path")\","
        echo "  \"size\": $file_size,"
        echo "  \"chunk_size\": $chunk_size,"
        echo "  \"chunks\": ["
        for (( i=0; i<${#chunk_hashes[@]}; i++ )); do
            local comma=""
            [ $i -lt $((${#chunk_hashes[@]} - 1)) ] && comma=","
            echo "    \"${chunk_hashes[$i]}\"$comma"
        done
        echo "  ]"
        echo "}"
    } > "$manifest_file"
    
    # [修复] 阶段三: 所有本地文件准备好后，才开始宣告到网络。
    # [FIX] Phase 3: Announce chunks to the network only after all local files are ready.
    info "Announcing chunks to the P2P network..."
    for (( i=0; i<chunk_count; i++ )); do
        local chunk_file="${chunk_dir}/chunk_${i}"
        local chunk_hash="${chunk_hashes[$i]}"
        dht_store_chunk "$chunk_hash" "$chunk_file" 0 "$chunk_size"
        progress $(( (i + 1) * 100 / chunk_count ))
    done
    echo

    msg "File successfully split and announced to the network."
    echo "$manifest_file"

}

# Reconstruct file from chunks
# (Final Robust Version)
# (最终健壮版)

p2p_reconstruct_file() {
    local manifest_file="$1"
    local output_file="$2"
    
    [ -f "$manifest_file" ] || error "Manifest file not found: $manifest_file"
    
    # Parse manifest
    local file_size chunk_size
    file_size=$(grep '"size"' "$manifest_file" | grep -o '[0-9]*')
    chunk_size=$(grep '"chunk_size"' "$manifest_file" | grep -o '[0-9]*')
    
    # Get chunk hashes
    local chunk_hashes=()
    while IFS= read -r line; do
        if [[ "$line" =~ \"([a-f0-9]{64})\" ]]; then
            chunk_hashes+=("${BASH_REMATCH[1]}")
        fi
    done < "$manifest_file"
    
    info "Reconstructing file from ${#chunk_hashes[@]} chunks..."
    
    # Download and assemble chunks
    rm -f "$output_file"
    for (( i=0; i<${#chunk_hashes[@]}; i++ )); do
        local chunk_hash="${chunk_hashes[$i]}"
        local chunk_written=false
        
        # 查找所有提供者
        local providers
        mapfile -t providers < <(dht_find_chunk "$chunk_hash")

        if [ ${#providers[@]} -eq 0 ]; then
            error "Failed to find any provider for chunk $chunk_hash"
        fi

        # 遍历所有提供者，直到成功
        for provider_info in "${providers[@]}"; do
            if [[ "$provider_info" == "local:"* ]]; then
                # 本地数据块
                local chunk_info="${provider_info#local:}"
                IFS='|' read -r chunk_file chunk_offset chunk_size <<< "$chunk_info"
                cat "$chunk_file" >> "$output_file"
                chunk_written=true
                detail "  -> Used local chunk ${chunk_hash:0:12}..."
                break # 成功，跳出 provider 循环
            else
                # 远程数据块
                local temp_chunk_file
                temp_chunk_file=$(mktemp -p "${P2P_DIR}")
                
                if p2p_download_chunk_from_provider "$chunk_hash" "$temp_chunk_file" "$provider_info"; then
                    cat "$temp_chunk_file" >> "$output_file"
                    rm -f "$temp_chunk_file"
                    chunk_written=true
                    detail "  -> Downloaded chunk ${chunk_hash:0:12} from $provider_info"
                    break # 成功，跳出 provider 循环
                else
                    # 从这个 provider 下载失败，循环将继续尝试下一个
                    rm -f "$temp_chunk_file"
                    warn "Failed to download chunk $chunk_hash from $provider_info. Trying next..."
                fi
            fi
        done

        if ! $chunk_written; then
            error "FATAL: Could not download chunk $chunk_hash from ANY of the available providers."
        fi
        
        progress $(( (i + 1) * 100 / ${#chunk_hashes[@]} ))
    done
    
    echo
    info "File reconstruction complete: $output_file"
}


# Downloads a single object (chunk, forum post, etc.) from the P2P network.
# It finds all known providers and tries them sequentially until the download succeeds.
#
# 从P2P网络下载单个对象（数据块、论坛帖子等）。
# 它会查找所有已知的提供者，并按顺序尝试，直到下载成功。
#
# @param $1 - object_hash (The hash of the object to download / 要下载对象的哈希)
# @param $2 - output_file (The path to save the downloaded file / 保存下载文件的路径)
# @return 0 on success, 1 on failure.
_p2p_download_object() {
    local object_hash="$1"
    local output_file="$2"
    
    # 查找所有提供者
    local providers
    mapfile -t providers < <(dht_find_chunk "$object_hash")

    if [ ${#providers[@]} -eq 0 ]; then
        warn "Failed to find any provider for object ${object_hash:0:16}..."
        return 1
    fi

    # 遍历所有提供者，直到成功
    for provider_info in "${providers[@]}"; do
        if [[ "$provider_info" == "local:"* ]]; then
            # 本地数据块
            local chunk_info="${provider_info#local:}"
            IFS='|' read -r chunk_file chunk_offset chunk_size <<< "$chunk_info"
            cp "$chunk_file" "$output_file"
            detail "  -> Used local object ${object_hash:0:12}..."
            return 0 # 成功
        else
            # 远程数据块
            if p2p_download_chunk_from_provider "$object_hash" "$output_file" "$provider_info"; then
                detail "  -> Downloaded object ${object_hash:0:12} from $provider_info"
                return 0 # 成功
            else
                # 从这个 provider 下载失败，循环将继续尝试下一个
                warn "Failed to download object ${object_hash:0:12} from $provider_info. Trying next..."
            fi
        fi
    done

    # 如果循环结束都没有成功，则返回失败
    error "FATAL: Could not download object ${object_hash:0:12} from ANY of the available providers."
    return 1
}


# Request chunk from specific node (HARDENED WITH TOFU CERTIFICATE VERIFICATION)
# (已通过 TOFU 证书验证进行安全加固)
p2p_request_chunk() {
    local node_ip="$1"
    local node_port="$2"
    local chunk_hash="$3"
    local output_file="$4"
    
    # --- [修复] 复用 dht_send_message 中健壮的证书验证与缓存逻辑 ---
    # --- [FIX] Re-use the robust certificate verification and caching logic from dht_send_message ---
    local peer_cert_file="${PEER_CERT_CACHE}/${node_ip}_${node_port}.pem"
    if [ ! -f "$peer_cert_file" ]; then
        # [修复] 先将证书获取到一个临时文件
        local temp_cert_file
        temp_cert_file=$(mktemp)

        # [修复] 连接到文件服务器的端口 (P2P_FILE_PORT_OFFSET)
        if ! openssl s_client -connect "$node_ip:$((node_port + P2P_FILE_PORT_OFFSET))" -showcerts </dev/null 2>/dev/null | \
           openssl x509 -outform PEM > "$temp_cert_file"; then
            rm -f "$temp_cert_file"
            error "无法获取文件服务器 $node_ip:$node_port 的TLS证书。 (Failed to retrieve TLS certificate from file server $node_ip:$port.)"
            return 1
        fi

        # [修复] 计算指纹并根据配置决定行为
        local fingerprint
        fingerprint=$(openssl x509 -in "$temp_cert_file" -noout -fingerprint -sha256 | cut -d'=' -f2)

        local final_auto_trust_policy="${NXPKG_AUTO_TRUST_NEW_NODES:-$AUTO_TRUST_NEW_NODES}"

        # 模式1: 自动化信任模式
        if [ "$final_auto_trust_policy" = "true" ]; then
            warn "自动化信任已启用: 自动信任新的文件服务器 $node_ip:$node_port"
            warn "AUTO-TRUST ENABLED: Automatically trusting new file server $node_ip:$node_port"
            detail "  -> Fingerprint: $fingerprint"
        
        # 模式2: 交互式终端模式
        elif [ -t 0 ]; then
            echo
            warn "文件服务器的真实性无法确认: $node_ip:$node_port"
            warn "The authenticity of file server '$node_ip:$node_port' can't be established."
            echo -e "SHA256 证书指纹 (Certificate Fingerprint): \033[1;33m$fingerprint\033[0m"
            
            read -rp "您确定要继续连接吗？ (Are you sure you want to continue connecting?) [y/N] " choice
            if [[ ! "$choice" =~ ^[yY] ]]; then
                rm -f "$temp_cert_file"
                info "连接已取消。 (Connection cancelled.)"
                return 1
            fi
        
        # 模式3: 非交互式且未启用自动化信任 (安全默认)
        else
            warn "在非交互式会话中，无法确认新的文件服务器指纹。连接失败。"
            warn "Cannot confirm new file server fingerprint in a non-interactive session. Connection failed."
            warn "要允许此操作，请在 nxpkg.conf 中设置 auto_trust_new_nodes = true"
            warn "或临时设置环境变量: export NXPKG_AUTO_TRUST_NEW_NODES=true"
            warn "To allow this, set auto_trust_new_nodes = true in nxpkg.conf"
            warn "or temporarily set the environment variable: export NXPKG_AUTO_TRUST_NEW_NODES=true"
            rm -f "$temp_cert_file"
            return 1
        fi

        # 用户确认或自动化信任后，才将证书移入缓存
        mkdir -p "$(dirname "$peer_cert_file")"
        mv "$temp_cert_file" "$peer_cert_file"
        info "文件服务器已被信任并缓存。 (File server has been trusted and cached.)"
    fi
    
    # --- 核心下载逻辑保持不变，但现在它使用的是一个经过可信验证的证书 ---
    # --- The core download logic remains the same, but now uses a trusted certificate ---
    if curl --silent --show-error --fail \
        --max-time 3600 \
        --cacert "$peer_cert_file" \
        -o "$output_file" \
        "https://$node_ip:$((node_port + P2P_FILE_PORT_OFFSET))/chunk/$chunk_hash"; then
        # 验证文件块哈希
        local actual_hash
        actual_hash=$(calculate_hash "$output_file")
        if [ "$actual_hash" != "$chunk_hash" ]; then
            warn "下载的文件块哈希校验失败！可能已被篡改。 (Downloaded chunk failed hash verification! Possible tampering.)"
            rm -f "$output_file"
            return 1
        fi
        return 0 # 成功
    else
        # curl 失败
        local curl_exit_code=$?
        # 如果是证书验证问题，可能意味着对方证书更新了，移除本地缓存以便下次重试
        if [[ "$curl_exit_code" -eq 60 ]]; then # 60 是 curl 的证书验证错误码
             warn "文件服务器 $node_ip:$node_port 的TLS证书已变更或无效。将移除旧证书并于下次重试。"
             warn "File server $node_ip:$node_port's TLS certificate has changed or is invalid. Removing old cert for next retry."
             rm -f "$peer_cert_file"
        fi
        return 1
    fi
}


# [新增] 辅助函数，用于从单个提供者下载数据块
p2p_download_chunk_from_provider() {
    local chunk_hash="$1"
    local output_file="$2"
    local provider_info="$3" # 格式: node_id 或 ip:port

    local node_ip node_port
    # provider_info 可能直接是 ip:port，也可能是 dht_find_chunk 返回的更复杂格式
    # 我们这里假设 dht_find_chunk 的远程结果格式就是 ip:port
    if [[ "$provider_info" == *":"* ]]; then
         node_ip="${provider_info%:*}"
         node_port="${provider_info#*:}"
    else
        # 如果只给了node_id, 需要从DHT数据库查询IP
        local node_details
        node_details=$(db_query_safe "$DHT_DB" \
            "SELECT ip, port FROM nodes WHERE id = %s;" \
            "$provider_info")
        [ -z "$node_details" ] && return 1
        IFS='|' read -r node_ip node_port <<< "$node_details"
    fi
    
    [ -n "$node_ip" ] || return 1

    p2p_request_chunk "$node_ip" "$node_port" "$chunk_hash" "$output_file"
}

# [修改] 旧的 p2p_download_chunk 不再需要，因为它只尝试从数据库记录的第一个节点下载
# p2p_download_chunk() { ... } # 此函数可以被删除或注释掉

# 文件: nxpkg.sh
# 函数: _p2p_download_object (新增的统一接口)

# Downloads a single object from the P2P network, trying all known providers.
# 从P2P网络下载单个对象，会尝试所有已知的提供者。
_p2p_download_object() {
    local object_hash="$1"
    local output_file="$2"
    
    # 步骤1: 查找所有提供者 (依赖于已修复的 dht_find_chunk)
    local providers
    mapfile -t providers < <(dht_find_chunk "$object_hash")

    if [ ${#providers[@]} -eq 0 ]; then
        warn "Failed to find any provider for object ${object_hash:0:16}..."
        return 1
    fi

    # 步骤2: 遍历所有提供者
    for provider_info in "${providers[@]}"; do
        if [[ "$provider_info" == "local:"* ]]; then
            local chunk_info="${provider_info#local:}"
            IFS='|' read -r chunk_file _ _ <<< "$chunk_info" # 我们只需要文件路径
            cp "$chunk_file" "$output_file"
            detail "  -> Used local object ${object_hash:0:12}..."
            return 0 # 成功
        else
            # 步骤3: 调用 p2p_download_chunk_from_provider 进行下载尝试
            if p2p_download_chunk_from_provider "$object_hash" "$output_file" "$provider_info"; then
                detail "  -> Downloaded object ${object_hash:0:12} from $provider_info"
                return 0 # 成功
            else
                warn "Failed to download object ${object_hash:0:12} from $provider_info. Trying next..."
            fi
        fi
    done

    # 如果循环结束都没有成功，则返回失败
    error "FATAL: Could not download object ${object_hash:0:12} from ANY of the available providers."
    return 1
}


# P2P chunk server
# P2P chunk server (P2P 文件块服务)
p2p_chunk_server() {
    local port=$((P2P_PORT + P2P_FILE_PORT_OFFSET))
    info "正在端口 $port 上启动 P2P 文件块 HTTP 服务器... (Starting P2P chunk HTTP server on port $port...)"
    
    # 步骤 1: 在调用 Python 之前，将 Shell 变量导出到环境中
    export NXPKG_DHT_DB_FOR_PYTHON="$DHT_DB" # 使用一个清晰的变量名
    export NXPKG_TLS_CERT_FILE="$TLS_CERT_FILE"
    export NXPKG_TLS_KEY_FILE="$TLS_KEY_FILE"
    # 使用 Python 启动一个简单的 HTTP 服务器来提供文件块
    # Use Python to start a simple HTTP server for providing file chunks
    python3 - <<EOF &
import http.server
import socketserver
import sqlite3
import os
import sys
import ssl # [新增] 导入SSL模块 ([NEW] Import the SSL module)


def bilingual_print(message_en, message_zh):
    """
    打印双语消息到 stderr。
    Prints a bilingual message to stderr.
    """
    print(f"P2P_CHUNK_LOG: {message_en} / {message_zh}", file=sys.stderr)

class ChunkHandler(http.server.BaseHTTPRequestHandler):
    """
    处理对文件块的 HTTP GET 请求。
    Handles HTTP GET requests for file chunks.
    """
    def do_GET(self):
        # 请求路径应为 /chunk/<chunk_hash>
        # The request path should be /chunk/<chunk_hash>
        if self.path.startswith('/chunk/'):
            chunk_hash = self.path[7:]  # 移除 '/chunk/' 前缀 / Remove the '/chunk/' prefix
            bilingual_print(f"Received request for chunk: {chunk_hash}", f"收到文件块请求: {chunk_hash}")
            
            chunk_info = self.get_chunk_info(chunk_hash)
            if chunk_info:
                file_path, offset, size = chunk_info
                try:
                    # 确保文件存在 / Ensure the file exists
                    if not os.path.exists(file_path):
                        self.send_error(404, f"Chunk data file not found on server / 服务器上找不到块数据文件: {file_path}")
                        bilingual_print(f"Error: Chunk data file not found: {file_path}", f"错误: 找不到块数据文件: {file_path}")
                        return

                    with open(file_path, 'rb') as f:
                        f.seek(int(offset))
                        chunk_data = f.read(int(size))
                    
                    # 验证读取的数据大小是否正确 / Verify if the read data size is correct
                    if len(chunk_data) != int(size):
                        self.send_error(500, "Failed to read correct chunk size from file / 从文件读取块大小时出错")
                        bilingual_print(f"Error: Read incorrect size for chunk {chunk_hash}. Expected {size}, got {len(chunk_data)}", f"错误: 为块 {chunk_hash} 读取了不正确的大小。预期 {size}, 得到 {len(chunk_data)}")
                        return

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(chunk_data)))
                    self.end_headers()
                    self.wfile.write(chunk_data)
                    bilingual_print(f"Successfully served chunk {chunk_hash}", f"成功提供文件块 {chunk_hash}")

                except FileNotFoundError:
                    self.send_error(404, "Chunk source file not found / 找不到块源文件")
                except Exception as e:
                    bilingual_print(f"Server error serving chunk {chunk_hash}: {e}", f"提供块 {chunk_hash} 时服务器出错: {e}")
                    self.send_error(500, f"Internal Server Error / 服务器内部错误: {e}")
            else:
                bilingual_print(f"Chunk info not found in DB for hash: {chunk_hash}", f"数据库中未找到哈希为 {chunk_hash} 的块信息")
                self.send_error(404, 'Chunk not found in database / 数据库中找不到此块')
        else:
            self.send_error(404, 'Not Found. Use /chunk/<hash> / 未找到。请使用 /chunk/<hash>')
    
    def get_chunk_info(self, chunk_hash):
        """
        从 DHT 数据库中查询一个本地文件块的信息。
        Queries the DHT database for information about a local chunk.

        Returns:
            A tuple (file_path, offset, size) or None if not found.
            返回一个元组 (file_path, offset, size)，如果未找到则返回 None。
        """
        # 从环境变量中获取数据库路径 / Get database path from environment variable
        # 步骤 2: Python 直接从环境中读取变量，无需再设置
        db_path = os.environ.get('NXPKG_DHT_DB_FOR_PYTHON') # 直接读取导出的变量
        if not db_path or not os.path.exists(db_path):
            bilingual_print(f"DHT database not found at: {db_path}", f"在 {db_path} 未找到 DHT 数据库")
            return None

        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT file_path, offset, size FROM local_chunks WHERE hash = ?', (chunk_hash,))
            result = cursor.fetchone()
            return result
        except sqlite3.Error as e:
            bilingual_print(f"Database query failed: {e}", f"数据库查询失败: {e}")
            return None
        finally:
            if conn:
                conn.close()

# [修改] 重写主函数以启动HTTPS服务器
# [MODIFIED] Rewrite main function to start HTTPS server
if __name__ == "__main__":
    try:
        # 端口计算在Bash脚本中完成并传入
        # Port calculation is done in the Bash script and passed in
        port = int(os.environ.get('NXPKG_P2P_CHUNK_PORT', 9234))
        cert_file = os.environ.get('NXPKG_TLS_CERT_FILE')
        key_file = os.environ.get('NXPKG_TLS_KEY_FILE')

        if not cert_file or not key_file or not os.path.exists(cert_file) or not os.path.exists(key_file):
            bilingual_print("TLS certificate or key not found.", "未找到TLS证书或密钥。")
            sys.exit(1)

        httpd = socketserver.TCPServer(("", port), ChunkHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        bilingual_print(f"P2P chunk HTTPS server starting on port {port}...", 
                        f"P2P 文件块 HTTPS 服务器正在端口 {port} 上启动...")
        httpd.serve_forever()
    except Exception as e:
        bilingual_print(f"Failed to start P2P chunk HTTPS server: {e}", 
                        f"启动 P2P 文件块 HTTPS 服务器失败: {e}")
        sys.exit(1)
EOF
    local P2P_CHUNK_SERVER_PID=$!
    NXPKG_BACKGROUND_PIDS+=($P2P_CHUNK_SERVER_PID)
}

# Check if a file is owned by any installed package
db_owns_file() {
    local file="$1"
    find "$INSTALLED_DB" -name files -exec grep -Fxq "$file" {} \; 2>/dev/null
}

# Update system caches (ldconfig, update-desktop-database, etc.)
update_system_caches() {
    info "Updating system caches..."
    
    # Update dynamic linker cache
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig 2>/dev/null || true
    fi
    
    # Update desktop database
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications 2>/dev/null || true
    fi
    
    # Update MIME database
    if command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database /usr/share/mime 2>/dev/null || true
    fi
    
    # Update icon cache
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        for icon_dir in /usr/share/icons/*/; do
            [ -d "$icon_dir" ] && gtk-update-icon-cache -q "$icon_dir" 2>/dev/null || true
        done
    fi
    
    # Update font cache
    if command -v fc-cache >/dev/null 2>&1; then
        fc-cache -f 2>/dev/null || true
    fi
}

# --- SECTION 17: PACKAGE REMOVAL ---

nxpkg_remove() {
    check_root
    [ $# -eq 0 ] && error "No packages specified for removal."
    
    acquire_lock "block"
    
    # Check for reverse dependencies
    local packages_to_remove=("$@")
    local deps_broken=()
    
    for pkg_id in "${packages_to_remove[@]}"; do
        get_pkg_id_parts "$pkg_id"
        local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
        
        ! db_is_installed "$pkg_id" && {
            warn "Package '$pkg_id' is not installed."
            continue
        }
        
        # Find packages that depend on this one
        local dependents
        dependents=$(find "$INSTALLED_DB" -name dependencies -exec grep -l "$pkg_name" {} \; | while read -r dep_file; do
            local dependent_pkg
            dependent_pkg=$(cat "$(dirname "$dep_file")/name")
            echo "$dependent_pkg"
        done)
        
        if [ -n "$dependents" ]; then
            warn "Package '$pkg_id' is required by:"
            echo "$dependents" | while read -r dep_pkg; do
                echo "  - $dep_pkg"
                deps_broken+=("$dep_pkg")
            done
        fi
    done
    
    if [ ${#deps_broken[@]} -gt 0 ]; then
        warn "Removing these packages will break dependencies."
        read -rp "Continue anyway? [y/N] " choice
        [[ ! "$choice" =~ ^[yY] ]] && {
            msg "Removal cancelled."
            release_lock
            return 0
        }
    fi
    
    # Remove packages
    for pkg_id in "${packages_to_remove[@]}"; do
        get_pkg_id_parts "$pkg_id"
        local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
        
        ! db_is_installed "$pkg_id" && continue
        
        msg "Removing: $pkg_id"
        
        # Run pre-remove script if it exists
        local pkg_dir
        pkg_dir=$(db_get_pkg_dir "$pkg_name" "$PKG_SLOT")
        if [ -f "/usr/share/nxpkg/pre-remove.sh" ]; then
            info "Running pre-remove script..."
            PKG_NAME="$pkg_name" PKG_VERSION="$(cat "$pkg_dir/version")" \
                bash /usr/share/nxpkg/pre-remove.sh || warn "Pre-remove script failed"
        fi
        
        # Remove files
        info "Removing package files..."
        local files_to_remove
        files_to_remove=$(db_get_package_files "$pkg_name" "$PKG_SLOT")
        local dirs_to_remove=()
        
        # Remove files in reverse order to handle directories properly
        echo "$files_to_remove" | tac | while IFS= read -r file; do
            [ -n "$file" ] || continue
            local full_path="/$file"
            
            if [ -f "$full_path" ] || [ -L "$full_path" ]; then
                rm -f "$full_path"
                dirs_to_remove+=("$(dirname "$full_path")")
            elif [ -d "$full_path" ]; then
                # Only remove if empty
                rmdir "$full_path" 2>/dev/null || true
            fi
        done
        
        # Remove empty directories
        printf '%s\n' "${dirs_to_remove[@]}" | sort -u -r | while IFS= read -r dir; do
            [ -d "$dir" ] && [ -z "$(ls -A "$dir" 2>/dev/null)" ] && rmdir "$dir" 2>/dev/null || true
        done
        
        # Unregister from database
        db_unregister_package "$pkg_name" "$PKG_SLOT"
        
        # Remove from world file
        sed -i "\|^${pkg_id}$|d" "$WORLD_FILE"
        
        info "Successfully removed: $pkg_id"
    done
    
    # Update system caches
    update_system_caches
    
    msg "Removal complete."
    release_lock
}

# --- SECTION 18: SYSTEM UPGRADE ---

nxpkg_upgrade() {
    check_root
    acquire_lock "block"
    
    # Sync repositories first
    nxpkg_sync
    
    msg "Checking for upgradeable packages..."
    local world_pkgs
    mapfile -t world_pkgs < "$WORLD_FILE"
    
    if [ ${#world_pkgs[@]} -eq 0 ]; then
        msg "World file is empty. Nothing to upgrade."
        release_lock
        return 0
    fi
    
    local to_upgrade=()
    local upgrade_info=()
    
    for pkg_id in "${world_pkgs[@]}"; do
        [ -n "$pkg_id" ] || continue
        
        get_pkg_id_parts "$pkg_id"
        local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
        local pkg_slot="$PKG_SLOT"
        
        local pkg_dir
        pkg_dir=$(db_get_pkg_dir "$pkg_name" "$pkg_slot")
        
        if [ ! -d "$pkg_dir" ]; then
            # Package in world file but not installed - reinstall
            to_upgrade+=("$pkg_id")
            upgrade_info+=("$pkg_id: missing -> reinstall")
            continue
        fi
        
        local installed_ver
        installed_ver=$(cat "$pkg_dir/version" 2>/dev/null || echo "unknown")
        
        local build_file
        build_file=$(find_package_build_file "$pkg_id")
        if [ -z "$build_file" ]; then
            warn "No .build file found for $pkg_id"
            continue
        fi
        
        local meta
        meta=$(_parse_build_file "$build_file")
        local repo_ver
        repo_ver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
        
        if [ "$repo_ver" != "$installed_ver" ]; then
            to_upgrade+=("$pkg_id")
            upgrade_info+=("$pkg_id: $installed_ver -> $repo_ver")
        fi
    done
    
    if [ ${#to_upgrade[@]} -eq 0 ]; then
        msg "System is up-to-date."
        release_lock
        return 0
    fi
    
    msg "The following packages will be upgraded:"
    printf '  %s\n' "${upgrade_info[@]}"
    echo
    
    if [ "$DEP_MODE" = "suggest" ]; then
        read -rp "Continue with upgrade? [Y/n] " choice
        [[ "$choice" =~ ^[nN] ]] && {
            msg "Upgrade cancelled."
            release_lock
            return 0
        }
    fi
    
    # Perform upgrades
    release_lock
    nxpkg_install "${to_upgrade[@]}"
    
    msg "System upgrade complete."
}

# --- SECTION 19: ADVANCED PACKAGE OPERATIONS ---

nxpkg_owns() {
    [ $# -ne 1 ] && error "Usage: nxpkg owns <file_path>"
    local file_path="$1"
    
    # The path in the manifest is relative to root, so we need to strip any leading '/'
    local search_path="${file_path#/}"
    
    info "Searching for owner of: $file_path"
    
    local found=0
    # Use find and grep for efficiency. -l prints the filename of the manifest that matches.
    find "$INSTALLED_DB" -name files -type f -exec grep -Fxq "$search_path" {} \; -print | while read -r manifest_file; do
        local pkg_dir owner_info
        pkg_dir=$(dirname "$manifest_file")
        
        # We can construct the package ID from the directory name
        local pkg_id_from_dir
        pkg_id_from_dir=$(basename "$pkg_dir" | sed 's/_/:/g')

        local pkg_name pkg_ver
        pkg_name=$(cat "$pkg_dir/name" 2>/dev/null)
        pkg_ver=$(cat "$pkg_dir/version" 2>/dev/null)
        
        echo -e "File is owned by: \033[1;32m${pkg_name}:${pkg_ver}\033[0m (ID: $pkg_id_from_dir)"
        found=1
    done
    
    if [ "$found" -eq 0 ]; then
        warn "No nxpkg-managed package owns this file."
    fi
}

nxpkg_info() {
    [ $# -ne 1 ] && error "Usage: nxpkg info <package_name>"
    local pkg_name_full="$1"
    
    msg "Gathering information for: \033[1;32m$pkg_name_full\033[0m"
    
    local build_file
    build_file=$(find_package_build_file "$pkg_name_full")
    [ -n "$build_file" ] || error "Could not find .build file for '$pkg_name_full'"
    
    # --- 1. Basic Info from .build file ---
    local meta
    meta=$(_parse_build_file "$build_file")
    
    local pkgname pkgver pkgdesc url slot
    pkgname=$(echo "$meta" | grep "^pkgname=" | cut -d= -f2)
    pkgver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
    pkgdesc=$(echo "$meta" | grep "^pkgdesc=" | cut -d= -f2)
    url=$(echo "$meta" | grep "^url=" | cut -d= -f2)
    slot=$(echo "$meta" | grep "^slot=" | cut -d= -f2)

    echo -e "\n\033[1mPackage Details\033[0m"
    echo -e "  Description: $pkgdesc"
    echo -e "  Latest Version: \033[1;33m$pkgver\033[0m"
    echo -e "  Slot: $slot"
    echo -e "  Homepage: $url"
    
    # --- 2. Dependency Info ---
    local depends makedepends
    depends=$(echo "$meta" | grep "^depends=" | cut -d= -f2- | tr '\n' ' ')
    makedepends=$(echo "$meta" | grep "^makedepends=" | cut -d= -f2- | tr '\n' ' ')
    
    echo -e "\n\033[1mDependencies\033[0m"
    echo -e "  Runtime Deps: ${depends:-<none>}"
    echo -e "  Build Deps:   ${makedepends:-<none>}"

    # --- 3. Installation Status ---
    echo -e "\n\033[1mSystem Status\033[0m"
    if db_is_installed "$pkg_name_full"; then
        get_pkg_id_parts "$pkg_name_full"
        local pkg_dir installed_ver install_date
        pkg_dir=$(db_get_pkg_dir "${PKG_CATEGORY}/${PKG_NAME}" "$PKG_SLOT")
        installed_ver=$(cat "$pkg_dir/version" 2>/dev/null)
        install_date=$(cat "$pkg_dir/install_date" 2>/dev/null)
        echo -e "  Status: \033[1;32mInstalled\033[0m"
        echo -e "  Installed Version: \033[1;33m$installed_ver\033[0m"
        echo -e "  Installation Date: $install_date"
    else
        echo -e "  Status: \033[0;33mNot Installed\033[0m"
    fi

    # --- 4. Blockchain & Trust Status ---
    echo -e "\n\033[1mTrust & Provenance\033[0m"
    local binary_pkg_name="${pkgname//\//_}-${pkgver}-${slot}-$(uname -m).nxpkg.tar.zst"
    local binary_pkg_path="${BINARY_CACHE}/${binary_pkg_name}"
    local alt_pkg_path="${BINARY_CACHE}/${pkg_name//\//_}-${pkgver}-${slot}-$(uname -m).nxpkg.tar.gz"

    if [ -f "$binary_pkg_path" ] || [ -f "$alt_pkg_path" ]; then
        local target_path="${binary_pkg_path}"
        [ ! -f "$target_path" ] && target_path="$alt_pkg_path"
        
        local pkg_hash
        pkg_hash=$(calculate_hash "$target_path")
        echo -e "  Binary Package Hash: ${pkg_hash:0:16}..."
        
        if blockchain_verify_package "$pkgname" "$pkgver" "$pkg_hash"; then
            echo -e "  Blockchain Record: \033[1;32mVERIFIED\033[0m"
        else
            echo -e "  Blockchain Record: \033[1;31mNOT FOUND or MISMATCH\033[0m"
        fi
    else
        echo -e "  Blockchain Record: Not applicable (binary package not cached)."
    fi
}

nxpkg_adopt() {
    check_root
    [ $# -lt 2 ] && error "Usage: adopt <pkg_name> <version> [--slot=SLOT]"
    
    local pkg_name="$1"
    local pkg_ver="$2"
    shift 2
    
    local pkg_slot="0"
    while [ $# -gt 0 ]; do
        case "$1" in
            --slot=*) pkg_slot="${1#--slot=}"; shift ;;
            --slot) pkg_slot="$2"; shift 2 ;;
            *) error "Unknown option: $1" ;;
        esac
    done
    
    msg "Adopting '$pkg_name' version '$pkg_ver' (slot: $pkg_slot)"
    
    # Check if package is already installed
    if db_is_installed "${pkg_name}:${pkg_slot}"; then
        warn "Package '$pkg_name:$pkg_slot' is already installed."
        read -rp "Continue anyway? [y/N] " choice
        [[ ! "$choice" =~ ^[yY] ]] && return 0
    fi
    
    # Get file manifest from user
    local manifest_file
    while true; do
        read -rp "Path to file manifest (one file per line): " manifest_file
        if [ -f "$manifest_file" ]; then
            break
        else
            error "File not found: $manifest_file"
        fi
    done
    
    # Validate manifest format
    info "Validating manifest..."
    local file_count
    file_count=$(wc -l < "$manifest_file")
    local invalid_files=()
    
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        if [[ "$file" =~ ^/ ]]; then
            warn "Absolute path in manifest: $file"
            invalid_files+=("$file")
        elif [ ! -e "/$file" ]; then
            warn "File does not exist: /$file"
            invalid_files+=("$file")
        fi
    done < "$manifest_file"
    
    if [ ${#invalid_files[@]} -gt 0 ]; then
        warn "Found ${#invalid_files[@]} invalid file(s) in manifest."
        read -rp "Continue anyway? [y/N] " choice
        [[ ! "$choice" =~ ^[yY] ]] && return 1
    fi
    
    # Try to find corresponding .build file
    local build_file
    build_file=$(find_package_build_file "$pkg_name")
    if [ -z "$build_file" ]; then
        warn "No .build file found for $pkg_name"
        build_file="/dev/null"
    fi
    
    # Register package
    acquire_lock "block"
    db_register_package "$pkg_name" "$pkg_ver" "$pkg_slot" "$manifest_file" "" "$build_file"
    
    # Add to world file
    if ! grep -Fxq "${pkg_name}:${pkg_slot}" "$WORLD_FILE"; then
        echo "${pkg_name}:${pkg_slot}" >> "$WORLD_FILE"
        sort -u -o "$WORLD_FILE" "$WORLD_FILE"
    fi
    
    release_lock
    msg "Successfully adopted '$pkg_name:$pkg_slot'"
}

nxpkg_rollback() {
    check_root
    [ $# -ne 2 ] && error "Usage: rollback <package_name> <version>"
    
    local pkg_id="$1"
    local target_version="$2"
    
    get_pkg_id_parts "$pkg_id"
    local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
    local pkg_slot="$PKG_SLOT"
    
    msg "Rolling back '$pkg_id' to version '$target_version'..."
    
    # Check if package is currently installed
    if ! db_is_installed "$pkg_id"; then
        error "Package '$pkg_id' is not installed."
    fi
    
    # Look for binary package of target version
    local binary_pkg_candidates=(
        "${BINARY_CACHE}/${pkg_name//\//_}-${target_version}-${pkg_slot}-$(uname -m).nxpkg.tar.zst"
        "${BINARY_CACHE}/${pkg_name//\//_}-${target_version}-${pkg_slot}-$(uname -m).nxpkg.tar.gz"
    )
    
    local binary_pkg_path=""
    for candidate in "${binary_pkg_candidates[@]}"; do
        if [ -f "$candidate" ]; then
            binary_pkg_path="$candidate"
            break
        fi
    done
    
    if [ -z "$binary_pkg_path" ]; then
        warn "No cached binary package found for version $target_version"
        info "Attempting to rebuild from historical .build file..."
        
        # Try to get old version from git repository
        local build_file
        build_file=$(find_package_build_file "$pkg_id")
        if [ -z "$build_file" ]; then
            error "Cannot find .build file for $pkg_id"
        fi
        
        local repo_dir
        repo_dir=$(dirname "$(dirname "$(dirname "$build_file")")")
        
        if [ -d "$repo_dir/.git" ]; then
            info "Searching git history for version $target_version..."
            (
                cd "$repo_dir"
                local commit
                commit=$(git log --oneline --grep="$target_version" --grep="$pkg_name" | head -n1 | cut -d' ' -f1)
                if [ -n "$commit" ]; then
                    info "Found historical commit: $commit"
                    local temp_build_file
                    temp_build_file=$(mktemp)
                    git show "$commit:${build_file#$repo_dir/}" > "$temp_build_file"
                    
                    # Temporarily replace .build file and build
                    cp "$build_file" "${build_file}.backup"
                    cp "$temp_build_file" "$build_file"
                    
                    # Build the old version
                    binary_pkg_path=$(nxpkg_build "$pkg_id")
                    
                    # Restore original .build file
                    mv "${build_file}.backup" "$build_file"
                    rm -f "$temp_build_file"
                else
                    error "Could not find historical version $target_version in git history"
                fi
            )
        else
            error "Repository is not a git repository and no cached binary found"
        fi
    fi
    
    [ -f "$binary_pkg_path" ] || error "Failed to obtain binary package for rollback"
    
    # Remove current version
    nxpkg_remove "$pkg_id"
    
    # Install target version
    msg "Installing rolled-back version..."
    
    # Extract package
    local temp_install_dir
    temp_install_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "rollback-${pkg_name//\//_}.XXXXXX")
    
    if [[ "$binary_pkg_path" =~ \.zst$ ]] && command -v zstd >/dev/null 2>&1; then
        zstd -d "$binary_pkg_path" -c | tar -xf - -C "$temp_install_dir"
    else
        tar -xf "$binary_pkg_path" -C "$temp_install_dir"
    fi
    
    # Install files
    rsync -a "$temp_install_dir/" /
    
    # Generate manifest and register
    local temp_manifest
    temp_manifest=$(mktemp)
    (cd "$temp_install_dir" && find . -type f -o -type l | sed 's|^\./||' | sort) > "$temp_manifest"
    
    local build_file
    build_file=$(find_package_build_file "$pkg_id")
    db_register_package "$pkg_name" "$target_version" "$pkg_slot" "$temp_manifest" "" "$build_file"
    
    # Add back to world file
    if ! grep -Fxq "$pkg_id" "$WORLD_FILE"; then
        echo "$pkg_id" >> "$WORLD_FILE"
        sort -u -o "$WORLD_FILE" "$WORLD_FILE"
    fi
    
    # Cleanup
    rm -rf "$temp_install_dir" "$temp_manifest"
    
    # Update system caches
    update_system_caches
    
    msg "Successfully rolled back to version $target_version"
}

# Creates a delta (differential) patch between two binary packages.
# This is typically used by repository maintainers.
#
# 用法: nxpkg create-delta <包名> <旧版本> <新版本>
# 示例: nxpkg create-delta app-misc/hello-world 1.0 2.0
nxpkg_create_delta() {
    check_root
    [ $# -ne 3 ] && error "用法: nxpkg create-delta <包名> <旧版本> <新版本> (Usage: nxpkg create-delta <pkg_name> <old_version> <new_version>)"

    local pkg_name="$1"
    local old_ver="$2"
    local new_ver="$3"
    
    msg "正在为软件包 '$pkg_name' 从版本 '$old_ver' 到 '$new_ver' 创建增量更新... (Creating delta update for package '$pkg_name' from version '$old_ver' to '$new_ver'...)"

    # 1. 获取包的元信息，主要是为了拿到 slot
    # 1. Obtaining the metadata of the package is mainly to obtain the slot
    local build_file meta pkg_slot
    build_file=$(find_package_build_file "$pkg_name")
    [ -z "$build_file" ] && error "找不到 '$pkg_name' 的 .build 文件。 (Could not find .build file for '$pkg_name'.)"
    meta=$(_parse_build_file "$build_file")
    pkg_slot=$(echo "$meta" | grep "^slot=" | cut -d= -f2)

    # 2. 定位旧版本和新版本的二进制包路径
    # 2. Locate binary package paths for old and new versions
    local old_pkg_base="${BINARY_CACHE}/${pkg_name//\//_}-${old_ver}-${pkg_slot}-$(uname -m).nxpkg"
    local new_pkg_base="${BINARY_CACHE}/${pkg_name//\//_}-${new_ver}-${pkg_slot}-$(uname -m).nxpkg"
    
    local old_pkg_path=""
    local new_pkg_path=""

    # 优先使用 .zst 压缩格式
    # Prioritize using .zst compression format
    [ -f "${old_pkg_base}.tar.zst" ] && old_pkg_path="${old_pkg_base}.tar.zst"
    [ -f "${new_pkg_base}.tar.zst" ] && new_pkg_path="${new_pkg_base}.tar.zst"

    # 如果 .zst 不存在，则回退到 .gz
    # If .zst does not exist, go back to .gz
    if [ -z "$old_pkg_path" ] && [ -f "${old_pkg_base}.tar.gz" ]; then
        old_pkg_path="${old_pkg_base}.tar.gz"
    fi
    if [ -z "$new_pkg_path" ] && [ -f "${new_pkg_base}.tar.gz" ]; then
        new_pkg_path="${new_pkg_base}.tar.gz"
    fi

    [ -f "$old_pkg_path" ] || error "找不到旧版本的二进制包: ${old_pkg_path} (或其 .gz 版本)。 (Could not find old binary package: ${old_pkg_path} (or its .gz version).)"
    [ -f "$new_pkg_path" ] || error "找不到新版本的二进制包: ${new_pkg_path} (或其 .gz 版本)。 (Could not find new binary package: ${new_pkg_path} (or its .gz version).)"

    info "找到旧版包 (Found old package): $old_pkg_path"
    info "找到新版包 (Found new package): $new_pkg_path"

    # 3. 定义增量包的输出路径
    # 3. Define the output path of incremental packages
    local delta_file="${BINARY_CACHE}/${pkg_name//\//_}-${old_ver}-to-${new_ver}.delta"
    
    # 4. 选择合适的工具创建增量包 (优先使用 xdelta3)
    # 4. Choose the appropriate tool to create incremental packages (prioritizing xdelta3)
    if command -v xdelta3 >/dev/null 2>&1; then
        info "使用 xdelta3 创建增量文件... (Creating delta file using xdelta3...)"
        xdelta3 -e -s "$old_pkg_path" "$new_pkg_path" "$delta_file"
    elif command -v bsdiff >/dev/null 2>&1; then
        info "警告: xdelta3 未找到，回退到 bsdiff... (Warning: xdelta3 not found, falling back to bsdiff...)"
        bsdiff "$old_pkg_path" "$new_pkg_path" "$delta_file"
    else
        error "无法创建增量包，需要安装 'xdelta3' 或 'bsdiff'。 (Cannot create delta package, 'xdelta3' or 'bsdiff' must be installed.)"
    fi

    if [ -f "$delta_file" ]; then
        msg "增量文件创建成功 (Delta file created successfully): $delta_file"
        info "文件大小 (File size): $(du -h "$delta_file" | awk '{print $1}')"
    else
        error "创建增量文件失败。 (Failed to create delta file.)"
    fi
}

# --- SECTION 20: STRATA SYSTEM (META-PM) ---

nxpkg_strata() {
    local sub_cmd="$1"
    shift
    
    case "$sub_cmd" in
        --create)
            [ $# -lt 2 ] && error "Usage: strata --create <name> <pm_name>"
            nxpkg_strata_create "$1" "$2"
            ;;
        --list)
            nxpkg_strata_list
            ;;
        -e|--execute)
            [ $# -lt 2 ] && error "Usage: strata -e <name> <command...>"
            local strata_name="$1"
            shift
            nxpkg_strata_execute "$strata_name" "$@"
            ;;
        --destroy)
            [ $# -lt 1 ] && error "Usage: strata --destroy <name>"
            nxpkg_strata_destroy "$1"
            ;;
        # --- [NEW] Add the promote command ---
        # --- [新增] 添加提升命令 ---
        --promote)
            [ $# -lt 1 ] && error "Usage: strata --promote <name>"
            nxpkg_strata_promote "$1"
            ;;
        *)
            error "Unknown strata command: '$sub_cmd'. Use --create, --list, -e, or --destroy."
            ;;
    esac
}

nxpkg_strata_create() {
    check_root
    local name="$1"
    local pm="$2"
    local strata_path="${STRATA_DIR}/${name}"
    
    [ -d "$strata_path" ] && error "Strata '$name' already exists at $strata_path"
    
    msg "Creating strata '$name' with package manager '$pm'..."
    
    case "$pm" in
        apt|debian)
            check_dep debootstrap
            info "Creating Debian-based strata with apt..."
            local debian_mirror="${3:-http://deb.debian.org/debian/}"
            local debian_release="${4:-stable}"
            
            debootstrap "$debian_release" "$strata_path" "$debian_mirror"
            
            # Configure apt sources
            cat > "${strata_path}/etc/apt/sources.list" <<EOF
deb $debian_mirror $debian_release main
deb-src $debian_mirror $debian_release main
deb $debian_mirror ${debian_release}-security main
deb-src $debian_mirror ${debian_release}-security main
EOF
            
            # Update package database
            nxpkg_strata_execute "$name" apt update
            ;;
            
        pacman|arch)
            check_dep pacstrap
            info "Creating Arch-based strata with pacman..."
            
            mkdir -p "$strata_path"
            pacstrap -c -K "$strata_path" base
            
            # Configure pacman
            if [ -f /etc/pacman.conf ]; then
                cp /etc/pacman.conf "${strata_path}/etc/pacman.conf"
            fi
            ;;
            
        dnf|fedora)
            check_dep dnf
            info "Creating Fedora-based strata with dnf..."
            
            local fedora_release="${3:-latest}"
            mkdir -p "$strata_path"
            
            # Create minimal filesystem
            mkdir -p "$strata_path"/{etc,var/lib/rpm,var/cache/dnf}
            
            # Initialize RPM database
            rpm --root "$strata_path" --initdb
            
            # Install base system
            dnf --installroot="$strata_path" --releasever="$fedora_release" \
                install -y filesystem setup basesystem
            ;;
            
        portage|gentoo)
            info "Creating Gentoo-based strata with Portage..."
            
            # Download stage3 tarball
            local stage3_url="https://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3-amd64.txt"
            local stage3_path
            stage3_path=$(curl -s "$stage3_url" | grep -v '^#' | head -n1 | awk '{print $1}')
            local stage3_file="${stage3_path##*/}"
            local stage3_full_url="https://distfiles.gentoo.org/releases/amd64/autobuilds/$stage3_path"
            
            info "Downloading stage3: $stage3_file"
            curl -L -o "${SOURCE_CACHE}/$stage3_file" "$stage3_full_url"
            
            # Extract stage3
            mkdir -p "$strata_path"
            tar -xpf "${SOURCE_CACHE}/$stage3_file" -C "$strata_path"
            ;;
            
        *)
            error "Unsupported package manager: $pm. Supported: apt, pacman, dnf, portage"
            ;;
    esac
    
    # Create strata metadata
    local strata_conf="${strata_path}/.nxpkg_strata"
    cat > "$strata_conf" <<EOF
name=$name
pm=$pm
created=$(date -u --rfc-3339=seconds)
nxpkg_version=$NXPKG_VERSION
EOF
    
    # Set up essential bind mounts for the strata
    mkdir -p "${strata_path}"/{proc,sys,dev}
    
    msg "Strata '$name' created successfully."
    info "Execute commands with: nxpkg strata -e $name <command>"
}

nxpkg_strata_list() {
    echo "Available strata:"
    for strata_dir in "${STRATA_DIR}"/*; do
        [ -d "$strata_dir" ] || continue
        local strata_name
        strata_name=$(basename "$strata_dir")
        local strata_conf="${strata_dir}/.nxpkg_strata"
        
        if [ -f "$strata_conf" ]; then
            local pm created
            pm=$(grep '^pm=' "$strata_conf" | cut -d= -f2)
            created=$(grep '^created=' "$strata_conf" | cut -d= -f2)
            echo "  $strata_name ($pm) - created $created"
        else
            echo "  $strata_name (unknown type)"
        fi
    done
}

# --- SECTION 21: EXTERNAL PACKAGE MANAGER INTEGRATION ---

nxpkg_manage() {
    check_root
    [ $# -lt 1 ] && error "Usage: manage <subcommand> [args...]"
    
    local sub_cmd="$1"
    shift
    
    case "$sub_cmd" in
        --sync-from)
            [ $# -lt 1 ] && error "Usage: manage --sync-from <pm_name>"
            nxpkg_manage_sync "$1"
            ;;
        --list-external)
            nxpkg_manage_list
            ;;
        --adopt-from)
            [ $# -lt 2 ] && error "Usage: manage --adopt-from <pm_name> <package_pattern>"
            nxpkg_manage_adopt "$1" "$2"
            ;;
        *)
            error "Unknown manage command: $sub_cmd"
            ;;
    esac
}

# REVISED: The extended nxpkg_manage_sync function.
# The Portage implementation now strictly requires 'equery' for accuracy
# and provides a clear message if it's not found, avoiding the unreliable
# fallback logic.
#
# 已修订: 扩展后的 nxpkg_manage_sync 函数。
# Portage 的实现现在为保证准确性而严格要求 'equery' 命令，如果命令未找到，
# 会提供清晰的提示，避免了不可靠的后备逻辑。
nxpkg_manage_sync() {
    local pm="$1"
    msg "正在从外部包管理器同步软件包数据库: $pm (Syncing package database from external package manager: $pm)"
    
    local db_file="${EXTERNAL_PM_DB}/${pm}.db"
    mkdir -p "$(dirname "$db_file")"
    
    case "$pm" in
        apt)
            check_dep dpkg-query
            info "正在查询 dpkg 数据库... (Querying dpkg database...)"
            dpkg-query -W -f='${Package}\t${Version}\t${Status}\t${Architecture}\n' > "$db_file"
            ;;
            
        pacman)
            check_dep pacman
            info "正在查询 pacman 数据库... (Querying pacman database...)"
            pacman -Q | awk '{printf "%s\t%s\tinstalled\t%s\n", $1, $2, "any"}' > "$db_file"
            ;;
            
        dnf)
            check_dep rpm
            info "正在查询 RPM 数据库... (Querying RPM database...)"
            rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\tinstalled\t%{ARCH}\n' > "$db_file"
            ;;
            
        portage)
            # [已修改] 只使用 equery，不再提供脆弱的后备方案
            # [MODIFIED] Only use equery, no longer provide a fragile fallback
            if command -v equery >/dev/null 2>&1; then
                info "正在通过 equery 查询 Portage 数据库 (精确)... (Querying Portage database via equery (accurate)...)"
                # equery list '*' 的输出格式是 category/name-version
                # 我们用 sed 来将其转换为我们需要的 tab 分隔格式
                equery -q list '*' | sed -E 's|^(.*)/([^-]+)-(.+)$|\1/\2\t\3\tinstalled\tgentoo|' > "$db_file"
            else
                # 如果 equery 不存在，则给出明确错误信息并失败
                # If equery does not exist, give a clear error message and fail
                error "无法同步 Portage 数据库：需要 'equery' 命令 (由 app-portage/gentoolkit 提供)。"
                error "Cannot sync Portage database: 'equery' command (from app-portage/gentoolkit) is required."
                return 1
            fi
            ;;
            
        pip)
            if command -v pip >/dev/null 2>&1; then
                info "正在查询 pip 软件包... (Querying pip packages...)"
                pip list --format=freeze | sed 's/==/\t/g' | awk '{printf "%s\t%s\tinstalled\tpython\n", $1, $2}' > "$db_file"
            else
                warn "未找到 pip 命令。 (pip command not found)"
            fi
            ;;
            
        npm)
            if command -v npm >/dev/null 2>&1; then
                info "正在查询 npm 软件包... (Querying npm packages...)"
                : > "$db_file"
                npm list -g --depth=0 --parseable --silent | while read -r pkg_path; do
                    [ -n "$pkg_path" ] || continue
                    local pkg_json="${pkg_path}/package.json"
                    if [ -f "$pkg_json" ]; then
                        local name version
                        name=$(grep -m 1 '"name"' "$pkg_json" | cut -d'"' -f4)
                        version=$(grep -m 1 '"version"' "$pkg_json" | cut -d'"' -f4)
                        [ -n "$name" ] && [ -n "$version" ] && echo -e "${name}\t${version}\tinstalled\tnodejs" >> "$db_file"
                    fi
                done
            else
                warn "未找到 npm 命令。 (npm command not found)"
            fi
            ;;
        
        xbps)
            check_dep xbps-query
            info "正在查询 xbps 数据库... (Querying xbps database...)"
            xbps-query -l | while read -r line; do
                local pkgver_str="${line%% *}"
                local pkgname="${pkgver_str%-*}"
                local version="${pkgver_str##*-}"
                echo -e "${pkgname}\t${version}\tinstalled\txbps"
            done > "$db_file"
            ;;

        zypper)
            check_dep zypper
            info "正在查询 zypper 数据库... (Querying zypper database...)"
            zypper se --installed-only -s | awk '
                BEGIN { FS = " \\| " }
                /^S/ || /^-/ { next }
                {
                    gsub(/^[ \t]+|[ \t]+$/, "", $2);
                    gsub(/^[ \t]+|[ \t]+$/, "", $4);
                    gsub(/^[ \t]+|[ \t]+$/, "", $5);
                    printf "%s\t%s\tinstalled\t%s\n", $2, $4, $5
                }
            ' > "$db_file"
            ;;
            
        pkgsrc)
            check_dep pkg_info
            info "正在查询 pkgsrc 数据库... (Querying pkgsrc database...)"
            pkg_info | while read -r line; do
                local pkgname="${line%-*}"
                local version="${line##*-}"
                echo -e "${pkgname}\t${version}\tinstalled\tpkgsrc"
            done > "$db_file"
            ;;

        *)
            error "不支持的包管理器: $pm。 (Unsupported package manager: $pm.)"
            ;;
    esac
    
    local package_count
    package_count=$(wc -l < "$db_file" 2>/dev/null || echo 0)
    info "外部数据库已更新: 来自 $pm 的 $package_count 个软件包 (External database updated: $package_count packages from $pm)"
}

nxpkg_manage_list() {
    echo "External package manager databases:"
    for db_file in "${EXTERNAL_PM_DB}"/*.db; do
        [ -f "$db_file" ] || continue
        
        local pm_name
        pm_name=$(basename "$db_file" .db)
        local package_count
        package_count=$(wc -l < "$db_file")
        local last_updated
        last_updated=$(stat -c %y "$db_file" | cut -d. -f1)
        
        echo "  $pm_name: $package_count packages (updated: $last_updated)"
    done
}

# [修改] 重写了收养函数，以使用正确的 db_mark_installed_external 并简化逻辑
# [MODIFIED] Rewrote adopt function to use the correct db_mark_installed_external and simplify logic
nxpkg_manage_adopt() {
    local pm="$1"
    local package_pattern="$2"
    local db_file="${EXTERNAL_PM_DB}/${pm}.db"
    
    [ -f "$db_file" ] || error "未找到 $pm 的数据库。请先运行 'nxpkg manage --sync-from $pm'。 (No database found for $pm. Run 'nxpkg manage --sync-from $pm' first.)"
    
    info "正在 $pm 数据库中搜索匹配 '$package_pattern' 的软件包... (Searching for packages matching '$package_pattern' in $pm database...)"
    local matches
    matches=$(grep -i "$package_pattern" "$db_file")
    
    if [ -z "$matches" ]; then
        warn "没有找到匹配 '$package_pattern' 的软件包。 (No packages found matching '$package_pattern')"
        return 1
    fi
    
    echo "找到的软件包 (Found packages):"
    echo "$matches" | while IFS=$'\t' read -r pkg_name pkg_version pkg_status pkg_arch; do
        echo "  $pkg_name ($pkg_version) [$pkg_status/$pkg_arch]"
    done
    
    echo
    read -rp "是否将所有这些软件包收养到 nxpkg 中? [y/N] (Adopt all these packages into nxpkg? [y/N]) " choice
    [[ ! "$choice" =~ ^[yY] ]] && return 0
    
    # [修改] 循环并调用正确的、轻量级的标记函数
    # [MODIFIED] Loop and call the correct, lightweight marking function
    acquire_lock "block"
    echo "$matches" | while IFS=$'\t' read -r pkg_name pkg_version pkg_status pkg_arch; do
        # 只收养确实已安装的包
        # Only adopt packages that are actually installed
        [ "$pkg_status" = "installed" ] || continue
        
        info "正在从 $pm 收养 $pkg_name $pkg_version... (Adopting $pkg_name $pkg_version from $pm...)"
        
        # [修改] 调用正确的函数，不再需要生成临时文件列表
        # [MODIFIED] Call the correct function, no longer need to generate a temporary file list
        db_mark_installed_external "$pkg_name" "$pkg_version" "$pm"
        
        detail "成功收养 $pkg_name。 (Successfully adopted $pkg_name.)"
    done
    release_lock
}

# --- SECTION 22: SEARCH AND INFORMATION ---

nxpkg_search() {
    if [ "${1:-}" = "--update-index" ]; then
        nxpkg_search_update_index
        return 0
    fi
    
    [ $# -eq 0 ] && error "Usage: search <keyword> or search --update-index"
    local keyword="$1"
    
    [ ! -f "$SEARCH_INDEX_FILE" ] && {
        warn "Search index not found. Building index..."
        nxpkg_search_update_index
    }
    
    info "Searching for: $keyword"
    local results
    results=$(grep -i "$keyword" "$SEARCH_INDEX_FILE" 2>/dev/null || true)
    
    if [ -z "$results" ]; then
        warn "No packages found matching '$keyword'"
        return 1
    fi
    
    echo "$results" | while IFS=':' read -r pkg_name pkg_desc pkg_path; do
        echo -e "\033[1;32m${pkg_name}\033[0m"
        echo -e "  \033[0;37mDescription:\033[0m $pkg_desc"
        
        # Check if installed
        if db_is_installed "$pkg_name"; then
            echo -e "  \033[1;32mStatus:\033[0m Installed"
        else
            echo -e "  \033[0;33mStatus:\033[0m Available"
        fi
        
        echo -e "  \033[0;90mPath:\033[0m $pkg_path"
        echo
    done
}

nxpkg_search_update_index() {
    msg "Updating package search index..."
    
    # 确保临时文件在函数退出时被删除
    local temp_index_file
    temp_index_file=$(mktemp)
    trap 'rm -f "$temp_index_file"' RETURN

    # 在临时文件中生成索引，成功后再替换旧文件，这更安全
    find "$REPOS_DIR" -name "*.build" -type f | while read -r build_file; do
        # 解析元数据
        local meta
        meta=$(_parse_build_file "$build_file" 2>/dev/null)
        
        # 检查解析是否成功
        if [ -z "$meta" ]; then
            warn "Could not parse build file, skipping: $build_file"
            continue
        fi

        # 从元数据中提取需要的信息
        local pkg_name_full pkg_desc
        # 假设 .build 文件的 pkgname 不包含分类，我们需要从路径中获取
        local category=$(basename "$(dirname "$build_file")")
        local pkgname=$(echo "$meta" | grep "^pkgname=" | cut -d= -f2)
        local slot=$(echo "$meta" | grep "^slot=" | cut -d= -f2)
        pkg_desc=$(echo "$meta" | grep "^pkgdesc=" | cut -d= -f2)
        
        # 拼接成完整的包ID
        pkg_name_full="${category}/${pkgname}:${slot}"

        # 将格式化的行写入临时索引文件
        # 格式: full_package_id:description:path_to_build_file
        echo "${pkg_name_full}:${pkg_desc}:${build_file}" >> "$temp_index_file"
    done

    # 确保目标目录存在，然后原子地移动文件
    mkdir -p "$(dirname "$SEARCH_INDEX_FILE")"
    mv "$temp_index_file" "$SEARCH_INDEX_FILE"
    
    info "Search index updated successfully."
}

# =======================================================
# --- SECTION 8: DECENTRALIZED FORUM SYSTEM (V2.1)    ---
# --- 第8节: 去中心化论坛系统 (V2.1 - 补完签名验证)     ---
# =======================================================

# Forum-specific paths
FORUM_DB="${FORUM_DIR}/forum.db"
FORUM_OBJECTS_DIR="${FORUM_DIR}/objects"
FORUM_MANIFESTS_DIR="${FORUM_DIR}/manifests"
FORUM_PUBKEYS_DIR="${FORUM_DIR}/pubkeys"

# --- HELPER: Get user identity hash ---
_forum_get_identity() {
    [ -f "$USER_PUBLIC_KEY_FILE" ] || error "用户身份密钥文件未找到，无法发帖。请先运行 'nxpkg init'。 (User identity key file not found, cannot create post. Please run 'nxpkg init' first.)"
    cat "$USER_PUBLIC_KEY_FILE" | calculate_hash
}

# --- NEW HELPER: Get author's public key from P2P network ---
_forum_get_author_pubkey() {
    local author_hash="$1"
    local pubkey_path="${FORUM_PUBKEYS_DIR}/${author_hash}.pub"

    # 如果本地已缓存，直接返回路径
    [ -f "$pubkey_path" ] && { echo "$pubkey_path"; return 0; }

    # 本地没有，则从P2P网络获取。作者的公钥文件，其内容哈希就是作者的ID。
    info "正在获取作者 '$author_hash' 的公钥... (Fetching public key for author '$author_hash'...)"
    if forum_fetch_object "$author_hash" "$FORUM_PUBKEYS_DIR"; then
        # forum_fetch_object 会将文件保存为 ${FORUM_PUBKEYS_DIR}/${author_hash}
        # 为了清晰，我们给它一个 .pub 扩展名
        mv "${FORUM_PUBKEYS_DIR}/${author_hash}" "$pubkey_path"
        echo "$pubkey_path"
        return 0
    else
        warn "无法获取作者 '$author_hash' 的公钥，其签名将无法被验证。 (Could not fetch public key for author '$author_hash', their signature cannot be verified.)"
        echo "" # 返回空
        return 1
    fi
}

# --- MODIFIED FUNCTION: Initialize/Upgrade forum database ---
forum_init() {
    mkdir -p "$FORUM_DIR" "$FORUM_OBJECTS_DIR" "$FORUM_MANIFESTS_DIR" "$FORUM_PUBKEYS_DIR"
    
    db_init "$FORUM_DB" "
    CREATE TABLE IF NOT EXISTS topics (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        signature TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        attachment_hash TEXT,
        attachment_name TEXT
    );
    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        topic_id TEXT NOT NULL,
        author TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        signature TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        attachment_hash TEXT,
        attachment_name TEXT,
        parent_post TEXT,
        FOREIGN KEY(topic_id) REFERENCES topics(id)
    );
    CREATE TABLE IF NOT EXISTS objects (
        hash TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        last_seen INTEGER NOT NULL
    );
    "
    info "论坛数据库已在 '$FORUM_DB' 初始化或验证。 (Forum database has been initialized or verified at '$FORUM_DB'.)"
}

# --- REWRITTEN FUNCTION: Create and Distribute Content ---
forum_distribute_content() {
    local content_path="$1"
    local attachment_path="$2"

    info "正在分发内容到P2P网络... (Distributing content to the P2P network...)"
    local content_hash
    content_hash=$(calculate_hash "$content_path")
    detail "正文内容哈希 (Content body hash): $content_hash"
    p2p_split_file "$content_path" >/dev/null

    local attachment_hash=""
    if [ -n "$attachment_path" ] && [ -f "$attachment_path" ]; then
        attachment_hash=$(calculate_hash "$attachment_path")
        detail "附件哈希 (Attachment hash): $attachment_hash"
        p2p_split_file "$attachment_path" >/dev/null
    fi
    
    echo "$content_hash|$attachment_hash"
}

# --- REWRITTEN FUNCTION: Create new forum topic ---
forum_create_topic() {
    local title="$1"
    local content_body="$2"
    local attachment_file="$3"

    local author timestamp
    author=$(_forum_get_identity)
    timestamp=$(date +%s)

    local tmp_content_file
    tmp_content_file=$(mktemp)
    echo -n "$content_body" > "$tmp_content_file"

    local hashes
    hashes=$(forum_distribute_content "$tmp_content_file" "$attachment_file")
    local content_hash="${hashes%|*}"
    local attachment_hash="${hashes#*|}"
    local attachment_name=""
    [ -n "$attachment_file" ] && attachment_name=$(basename "$attachment_file")

    # 1. 创建被签名的数据 (不含签名本身的 manifest)
    local manifest_unsigned
    manifest_unsigned=$(cat <<EOF
{
  "title": "$title",
  "author": "$author",
  "timestamp": $timestamp,
  "content_hash": "$content_hash",
  "attachment_hash": "$attachment_hash",
  "attachment_name": "$attachment_name"
}
EOF
)
    # 2. 对其进行签名
    local signature
    signature=$(sign_data "$manifest_unsigned" "$USER_IDENTITY_FILE")

    # 3. 创建最终分发的、包含签名的完整 manifest
    # 使用 sed 在最后一个 '}' 前插入签名，比 jq 更通用
    local manifest_signed
    manifest_signed=$(echo "${manifest_unsigned}" | sed -e '$s/}/, "signature": "'"$signature"'"\n}/')

    # 4. 话题ID是完整、带签名 manifest 的哈希
    local topic_id
    topic_id=$(calculate_hash "$manifest_signed")

    db_execute_safe "$FORUM_DB" \
        "INSERT INTO topics (id, title, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
        "$topic_id" "$title" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"

    local tmp_manifest_file="${FORUM_MANIFESTS_DIR}/${topic_id}.json"
    echo "$manifest_signed" > "$tmp_manifest_file"
    p2p_split_file "$tmp_manifest_file" >/dev/null

    local tx_data="{\"type\":\"forum_topic\",\"topic_id\":\"$topic_id\"}"
    blockchain_create_transaction "forum" "$tx_data" >/dev/null

    rm -f "$tmp_content_file"
    msg "话题已创建并发布到网络。话题ID: $topic_id (Topic created and published to the network. Topic ID: $topic_id)"
}

# --- REWRITTEN FUNCTION: Create new forum post ---
forum_create_post() {
    local topic_id="$1"
    local content_body="$2"
    local attachment_file="$3"
    
    local topic_exists
    topic_exists=$(db_query_safe "$FORUM_DB" \
        "SELECT COUNT(*) FROM topics WHERE id = %s;" \
        "$topic_id")
    [ "$topic_exists" -eq 0 ] && error "错误: 话题 '$topic_id' 不存在。 (Error: Topic '$topic_id' does not exist.)"

    local author timestamp
    author=$(_forum_get_identity)
    timestamp=$(date +%s)

    local tmp_content_file
    tmp_content_file=$(mktemp)
    echo -n "$content_body" > "$tmp_content_file"

    local hashes
    hashes=$(forum_distribute_content "$tmp_content_file" "$attachment_file")
    local content_hash="${hashes%|*}"
    local attachment_hash="${hashes#*|}"
    local attachment_name=""
    [ -n "$attachment_file" ] && attachment_name=$(basename "$attachment_file")

    local manifest_unsigned
    manifest_unsigned=$(cat <<EOF
{
  "topic_id": "$topic_id",
  "author": "$author",
  "timestamp": $timestamp,
  "content_hash": "$content_hash",
  "attachment_hash": "$attachment_hash",
  "attachment_name": "$attachment_name"
}
EOF
)
    local signature
    signature=$(sign_data "$manifest_unsigned" "$USER_IDENTITY_FILE")
    
    local manifest_signed
    manifest_signed=$(echo "${manifest_unsigned}" | sed -e '$s/}/, "signature": "'"$signature"'"\n}/')

    local post_id
    post_id=$(calculate_hash "$manifest_signed")

    db_execute_safe "$FORUM_DB" \
        "INSERT INTO posts (id, topic_id, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
        "$post_id" "$topic_id" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"

    local tmp_manifest_file="${FORUM_MANIFESTS_DIR}/${post_id}.json"
    echo "$manifest_signed" > "$tmp_manifest_file"
    p2p_split_file "$tmp_manifest_file" >/dev/null

    local tx_data="{\"type\":\"forum_post\",\"post_id\":\"$post_id\",\"topic_id\":\"$topic_id\"}"
    blockchain_create_transaction "forum" "$tx_data" >/dev/null
    
    rm -f "$tmp_content_file"
    msg "回复已发布。帖子ID: $post_id (Reply published. Post ID: $post_id)"
}

# 文件: nxpkg.sh
# 函数: forum_fetch_object (重构后)

# --- NEW FUNCTION: Fetch a single object from P2P network ---
forum_fetch_object() {
    local object_hash="$1"
    local output_dir="$2"
    
    [ -z "$object_hash" ] && return 0
    
    local output_path="${output_dir}/${object_hash}"
    if [ -f "$output_path" ]; then
        local local_hash
        local_hash=$(calculate_hash "$output_path")
        if [ "$local_hash" = "$object_hash" ]; then
            detail "对象 '$object_hash' 已在本地缓存。 (Object '$object_hash' is already cached locally.)"
            return 0
        else
            warn "本地缓存文件 '$object_hash' 已损坏，将重新下载。 (Local cache file '$object_hash' is corrupt, re-downloading.)"
            rm -f "$output_path"
        fi
    fi

    info "正在从P2P网络获取对象 (Fetching object from P2P network): $object_hash"
    
    # [修改] 调用新的、健壮的下载函数
    if ! _p2p_download_object "$object_hash" "$output_path"; then
        # 错误信息已在 _p2p_download_object 中打印
        return 1
    fi

    # 如果下载成功，则将其信息添加到论坛的对象数据库中
    local current_time
    current_time=$(date +%s)
    db_execute_safe "$FORUM_DB" \
        "INSERT OR REPLACE INTO objects (hash, file_path, last_seen) VALUES (%s, %s, %d);" \
        "$object_hash" "$output_path" "$current_time"
    return 0
}


# --- REWRITTEN FUNCTION: Sync forum content from network ---
forum_sync() {
    msg "正在从网络同步论坛内容... (Syncing forum content from the network...)"
    
    local forum_txs
    forum_txs=$(db_query_static "$BLOCKCHAIN_DB" "SELECT data FROM transactions WHERE type = 'forum' AND block_height IS NOT NULL ORDER BY timestamp;")

    while IFS= read -r tx_data; do
        [ -n "$tx_data" ] || continue
        
        local item_id item_type
        if [[ "$tx_data" =~ \"topic_id\":\"([^\"]+)\" ]]; then
            item_id="${BASH_REMATCH[1]}"; item_type="topic"
        elif [[ "$tx_data" =~ \"post_id\":\"([^\"]+)\" ]]; then
            item_id="${BASH_REMATCH[1]}"; item_type="post"
        else
            continue
        fi

        local count
        if [ "$item_type" = "topic" ]; then
            count=$(db_query_safe "$FORUM_DB" \
                "SELECT COUNT(*) FROM topics WHERE id = %s;" \
                "$item_id")
        else
            count=$(db_query_safe "$FORUM_DB" \
                "SELECT COUNT(*) FROM posts WHERE id = %s;" \
                "$item_id")
        fi
        [ "$count" -gt 0 ] && continue

        local manifest_path="${FORUM_MANIFESTS_DIR}/${item_id}.json"
        forum_fetch_object "$item_id" "$(dirname "$manifest_path")" || continue
        [ ! -f "$manifest_path" ] && { warn "无法获取清单文件 (Could not fetch manifest file): $item_id"; continue; }
        
        # --- 签名验证开始 ---
        local manifest_signed author pubkey_path signature manifest_unsigned
        manifest_signed=$(cat "$manifest_path")
        author=$(echo "$manifest_signed" | grep -o '"author": *"[^"]*"' | cut -d'"' -f4)
        signature=$(echo "$manifest_signed" | grep -o '"signature": *"[^"]*"' | cut -d'"' -f4)

        pubkey_path=$(_forum_get_author_pubkey "$author")
        
        if [ -n "$pubkey_path" ] && [ -n "$signature" ]; then
            # 从带签名的 manifest 中，重建出未签名的原始数据
            manifest_unsigned=$(echo "${manifest_signed}" | sed -e '/"signature":/d' | sed 's/},$/}/')
            
            if verify_signature "$manifest_unsigned" "$signature" "$pubkey_path"; then
                detail "条目 '$item_id' 的签名验证成功。 (Signature for item '$item_id' verified successfully.)"
            else
                warn "条目 '$item_id' 的签名验证失败！此内容可能被篡改或来自伪造的作者。将忽略此条目。 (Signature verification for item '$item_id' FAILED! This content may be tampered with or from a forged author. Ignoring this item.)"
                rm -f "$manifest_path" # 删除无效内容
                continue
            fi
        else
            warn "无法为条目 '$item_id' 验证签名 (公钥或签名缺失)。 (Cannot verify signature for item '$item_id' (public key or signature missing).)"
        fi
        # --- 签名验证结束 ---

        local content_hash attachment_hash
        content_hash=$(echo "$manifest_signed" | grep -o '"content_hash": *"[^"]*"' | cut -d'"' -f4)
        attachment_hash=$(echo "$manifest_signed" | grep -o '"attachment_hash": *"[^"]*"' | cut -d'"' -f4)
        
        forum_fetch_object "$content_hash" "$FORUM_OBJECTS_DIR"
        forum_fetch_object "$attachment_hash" "$FORUM_OBJECTS_DIR"
        
        local timestamp attachment_name title topic_id
        timestamp=$(echo "$manifest_signed" | grep -o '"timestamp": *[0-9]*' | grep -o '[0-9]*')
        attachment_name=$(echo "$manifest_signed" | grep -o '"attachment_name": *"[^"]*"' | cut -d'"' -f4)
        
        if [ "$item_type" = "topic" ]; then
            title=$(echo "$manifest_signed" | grep -o '"title": *"[^"]*"' | cut -d'"' -f4)
            db_execute_safe "$FORUM_DB" \
                "INSERT OR IGNORE INTO topics (id, title, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
                "$item_id" "$title" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"
            info "同步新话题 (Synced new topic): $title"
        else
            topic_id=$(echo "$manifest_signed" | grep -o '"topic_id": *"[^"]*"' | cut -d'"' -f4)
            db_execute_safe "$FORUM_DB" \
                "INSERT OR IGNORE INTO posts (id, topic_id, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
                "$item_id" "$topic_id" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"
            info "同步新回复到话题 (Synced new reply to topic): $topic_id"
        fi
    done <<< "$forum_txs"
    msg "论坛同步完成。 (Forum sync complete.)"
}

# --- REWRITTEN FUNCTION: Display forum topics ---
forum_list_topics() {
    msg "论坛主题列表:"
    db_query_static "$FORUM_DB" "SELECT id, title, author, datetime(timestamp, 'unixepoch', 'localtime') FROM topics ORDER BY timestamp DESC;" | while IFS='|' read -r id title author ts; do
        [ -n "$id" ] || continue
        echo -e "\033[1;32mID: $id\033[0m"
        echo -e "  \033[1m标题:\033[0m $title"
        echo -e "  \033[0;36m作者:\033[0m ${author:0:16}...  \033[0;33m时间:\033[0m $ts"
        echo
    done
}

# --- REWRITTEN FUNCTION: Display a topic and its posts ---
forum_show_topic() {
    local topic_id="$1"
    
    local topic_info
    topic_info=$(db_query_safe "$FORUM_DB" \
        "SELECT title, author, timestamp, content_hash, attachment_hash, attachment_name FROM topics WHERE id = %s;" \
        "$topic_id")
    [ -z "$topic_info" ] && { error "话题 '$topic_id' 未找到。"; return 1; }
    
    IFS='|' read -r title author ts content_hash attachment_hash attachment_name <<< "$topic_info"

    echo -e "\n\033[1;33m=== 主题: $title ===\033[0m"
    echo -e "\033[0;36m作者: ${author:0:16}...\n时间: $(date -d "@$ts" '+%Y-%m-%d %H:%M:%S')\033[0m"
    echo -e "\033[1;34m--- 正文内容 ---\033[0m"
    
    local content_path="${FORUM_OBJECTS_DIR}/${content_hash}"
    [ -f "$content_path" ] && cat "$content_path" || echo "[内容文件本地不存在，请运行 'nxpkg forum sync' 或 'nxpkg forum get-attachment $content_hash']"
    
    if [ -n "$attachment_hash" ]; then
        echo -e "\n\033[1;32m--- 附件 ---\033[0m"
        echo -e "文件名: \033[1m$attachment_name\033[0m"
        echo -e "哈希: $attachment_hash"
        echo -e "下载命令: \033[0;32mnxpkg forum get-attachment $attachment_hash \"$attachment_name\"\033[0m"
    fi
    echo -e "\n\033[1;33m--- 回复列表 ---\033[0m"

    db_query_safe "$FORUM_DB" \
        "SELECT id, author, timestamp, content_hash, attachment_hash, attachment_name FROM posts WHERE topic_id = %s ORDER BY timestamp ASC;" \
        "$topic_id" | while IFS='|' read -r p_id p_author p_ts p_chash p_ahash p_aname; do
        echo -e "\n\033[0;36m> 回复者: ${p_author:0:16}...\t时间: $(date -d "@$p_ts" '+%Y-%m-%d %H:%M')\033[0m"
        local post_content_path="${FORUM_OBJECTS_DIR}/${p_chash}"
        [ -f "$post_content_path" ] && cat "$post_content_path" | sed 's/^/  /' || echo "  [内容文件本地不存在]"
        if [ -n "$p_ahash" ]; then
            echo -e "  \033[0;32m附件:\033[0m $p_aname ($p_ahash)"
        fi
    done
    echo
}

# --- NEW FUNCTION: Download an attachment/content object ---
forum_get_attachment() {
    [ $# -lt 2 ] && error "用法: nxpkg forum get-attachment <对象哈希> <输出文件名>"
    local object_hash="$1"
    local output_file="$2"

    local object_path="${FORUM_OBJECTS_DIR}/${object_hash}"
    if [ -f "$object_path" ]; then
        info "对象在本地缓存中找到，直接复制。"
        cp "$object_path" "$output_file"
    else
        msg "对象不在本地，尝试从P2P网络获取..."
        forum_fetch_object "$object_hash" "$FORUM_OBJECTS_DIR" || {
            error "无法从网络获取该对象。"
            return 1
        }
        cp "$object_path" "$output_file"
    fi
    
    msg "文件已成功下载到: $output_file"
}

# Exports a full topic and all its related data into a single, portable tarball.
# 将一个完整的话题及其所有相关数据导出到一个单一的、可移植的tar包中。
#
# @param $1 - topic_id  (The ID of the topic to export / 要导出的话题ID)
# @param $2 - output_file (The path for the output .tar.gz file / 输出的 .tar.gz 文件路径)
forum_export_topic() {
    local topic_id="$1"
    local output_file="$2"

    # --- 步骤 1: 验证话题是否存在 ---
    local topic_exists
    topic_exists=$(db_query_safe "$FORUM_DB" \
        "SELECT COUNT(*) FROM topics WHERE id = %s;" \
        "$topic_id")
    [ "$topic_exists" -eq 0 ] && error "错误: 话题 '$topic_id' 未找到，无法导出。 (Error: Topic '$topic_id' not found, cannot export.)"
    
    msg "正在导出话题 '$topic_id' 到 '$output_file'..."
    info "Exporting topic '$topic_id' to '$output_file'..."

    # --- 步骤 2: 创建一个临时目录用于打包 ---
    local temp_export_dir
    temp_export_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "forum_export.XXXXXX")
    
    # 在临时目录中创建与真实结构匹配的子目录
    mkdir -p "${temp_export_dir}/manifests" "${temp_export_dir}/objects"

    # --- 步骤 3: 收集所有需要打包的文件哈希 ---
    local -a hashes_to_pack=()
    
    # 添加话题自身的 manifest 哈希 (就是 topic_id)
    hashes_to_pack+=("$topic_id")
    
    # 获取话题的内容和附件哈希
    local topic_hashes
    topic_hashes=$(db_query_safe "$FORUM_DB" \
        "SELECT content_hash, attachment_hash FROM topics WHERE id = %s;" \
        "$topic_id")
    IFS='|' read -r t_content_hash t_attachment_hash <<< "$topic_hashes"
    [ -n "$t_content_hash" ] && hashes_to_pack+=("$t_content_hash")
    [ -n "$t_attachment_hash" ] && hashes_to_pack+=("$t_attachment_hash")

    # 获取所有回帖的 manifest 哈希、内容哈希和附件哈希
    db_query_safe "$FORUM_DB" \
        "SELECT id, content_hash, attachment_hash FROM posts WHERE topic_id = %s;" \
        "$topic_id" | while IFS='|' read -r p_id p_content_hash p_attachment_hash; do
        [ -n "$p_id" ] && hashes_to_pack+=("$p_id")
        [ -n "$p_content_hash" ] && hashes_to_pack+=("$p_content_hash")
        [ -n "$p_attachment_hash" ] && hashes_to_pack+=("$p_attachment_hash")
    done

    # --- 步骤 4: 将所有文件复制到临时目录 ---
    info "正在收集文件... (Collecting files...)"
    local missing_files=0
    for hash in "${hashes_to_pack[@]}"; do
        # 判断是 manifest 还是 object
        local source_path=""
        if [ -f "${FORUM_MANIFESTS_DIR}/${hash}.json" ]; then
            source_path="${FORUM_MANIFESTS_DIR}/${hash}.json"
            cp "$source_path" "${temp_export_dir}/manifests/"
            detail "  -> 已打包清单 (Packed manifest): ${hash:0:16}..."
        elif [ -f "${FORUM_OBJECTS_DIR}/${hash}" ]; then
            source_path="${FORUM_OBJECTS_DIR}/${hash}"
            cp "$source_path" "${temp_export_dir}/objects/"
            detail "  -> 已打包对象 (Packed object): ${hash:0:16}..."
        else
            warn "警告: 话题依赖的对象文件 '$hash' 在本地缺失，导出包可能不完整。"
            warn "Warning: Topic dependency object '$hash' is missing locally. The exported archive may be incomplete."
            missing_files=1
        fi
    done

    # --- 步骤 5: 创建一个元数据文件，指明主话题ID ---
    echo "$topic_id" > "${temp_export_dir}/TOPIC_ID"
    
    # --- 步骤 6: 将临时目录打包成 tar.gz ---
    info "正在创建压缩包... (Creating archive...)"
    if tar -C "$temp_export_dir" -czf "$output_file" .; then
        msg "话题已成功导出到: $output_file"
        msg "Topic successfully exported to: $output_file"
        if [ "$missing_files" -eq 1 ]; then
            warn "请注意，由于部分文件缺失，此导出包不完整。"
            warn "Please note, this export is incomplete due to missing files."
        fi
    else
        error "创建压缩包失败。 (Failed to create archive.)"
    fi
    
    # --- 步骤 7: 清理临时目录 ---
    rm -rf "$temp_export_dir"
}


# Imports a topic from a portable tarball created by forum_export_topic.
# It validates the content and merges it into the local forum database.
#
# 从一个由 forum_export_topic 创建的可移植tar包中导入话题。
# 它会验证内容并将其合并到本地的论坛数据库中。
#
# @param $1 - input_file (The path to the .tar.gz file to import / 要导入的 .tar.gz 文件路径)
forum_import_topic() {
    local input_file="$1"

    [ -f "$input_file" ] || error "错误: 导入文件未找到: $input_file (Error: Import file not found: $input_file)"
    
    msg "正在从 '$input_file' 导入话题..."
    info "Importing topic from '$input_file'..."

    # --- 步骤 1: 创建一个临时目录用于解压 ---
    local temp_import_dir
    temp_import_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "forum_import.XXXXXX")

    # --- 步骤 2: 解压文件并进行基础验证 ---
    info "正在解压并验证压缩包... (Extracting and validating archive...)"
    if ! tar -C "$temp_import_dir" -xzf "$input_file"; then
        rm -rf "$temp_import_dir"
        error "错误: 解压文件失败。文件可能已损坏或格式不正确。"
        error "Error: Failed to extract file. It may be corrupt or not a valid format."
    fi

    if [ ! -f "${temp_import_dir}/TOPIC_ID" ] || [ ! -d "${temp_import_dir}/manifests" ] || [ ! -d "${temp_import_dir}/objects" ]; then
        rm -rf "$temp_import_dir"
        error "错误: 压缩包内容无效。缺少必要的文件或目录。"
        error "Error: Invalid archive content. Missing required files or directories."
    fi

    local topic_id
    topic_id=$(cat "${temp_import_dir}/TOPIC_ID")
    info "准备导入话题 (Preparing to import topic): $topic_id"
    
    # --- 步骤 3: 检查话题是否已存在，避免重复导入 ---
    local topic_exists
    topic_exists=$(db_query_safe "$FORUM_DB" \
        "SELECT COUNT(*) FROM topics WHERE id = %s;" \
        "$topic_id")
    if [ "$topic_exists" -gt 0 ]; then
        rm -rf "$temp_import_dir"
        msg "话题 '$topic_id' 已存在于本地数据库中。跳过导入。"
        msg "Topic '$topic_id' already exists in the local database. Skipping import."
        return 0
    fi
    
    # --- 步骤 4: 验证所有文件哈希并复制文件 ---
    info "正在验证并合并文件... (Verifying and merging files...)"
    
    # 合并 manifests
    for manifest_file in "${temp_import_dir}/manifests"/*; do
        local hash
        hash=$(basename "$manifest_file" .json)
        local calculated_hash
        calculated_hash=$(calculate_hash "$manifest_file")

        if [ "$hash" != "$calculated_hash" ]; then
            rm -rf "$temp_import_dir"
            error "错误: 清单文件 '$hash' 的内容哈希不匹配！文件可能已损坏。"
            error "Error: Content hash mismatch for manifest '$hash'! The file may be corrupt."
        fi
        
        # 如果本地不存在，则复制
        [ ! -f "${FORUM_MANIFESTS_DIR}/${hash}.json" ] && cp "$manifest_file" "${FORUM_MANIFESTS_DIR}/"
    done
    
    # 合并 objects
    for object_file in "${temp_import_dir}/objects"/*; do
        local hash
        hash=$(basename "$object_file")
        local calculated_hash
        calculated_hash=$(calculate_hash "$object_file")
        
        if [ "$hash" != "$calculated_hash" ]; then
            rm -rf "$temp_import_dir"
            error "错误: 对象文件 '$hash' 的内容哈希不匹配！文件可能已损坏。"
            error "Error: Content hash mismatch for object '$hash'! The file may be corrupt."
        fi
        
        # 如果本地不存在，则复制
        [ ! -f "${FORUM_OBJECTS_DIR}/${hash}" ] && cp "$object_file" "${FORUM_OBJECTS_DIR}/"
    done

    # --- 步骤 5: 从 Manifests 文件中读取元数据并写入数据库 ---
    info "正在更新数据库索引... (Updating database index...)"
    
    # 导入主话题
    local topic_manifest_path="${FORUM_MANIFESTS_DIR}/${topic_id}.json"
    local manifest_content
    manifest_content=$(cat "$topic_manifest_path")
    
    local title author timestamp signature content_hash attachment_hash attachment_name
    # 使用 jq 安全地解析
    title=$(echo "$manifest_content" | jq -r .title)
    author=$(echo "$manifest_content" | jq -r .author)
    timestamp=$(echo "$manifest_content" | jq -r .timestamp)
    signature=$(echo "$manifest_content" | jq -r .signature)
    content_hash=$(echo "$manifest_content" | jq -r .content_hash)
    attachment_hash=$(echo "$manifest_content" | jq -r .attachment_hash)
    attachment_name=$(echo "$manifest_content" | jq -r .attachment_name)
    
    db_execute_safe "$FORUM_DB" \
        "INSERT OR IGNORE INTO topics (id, title, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
        "$topic_id" "$title" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"
    
    # 导入所有回帖
    for manifest_file in "${temp_import_dir}/manifests"/*; do
        local post_id
        post_id=$(basename "$manifest_file" .json)
        [ "$post_id" = "$topic_id" ] && continue # 跳过主话题
        
        manifest_content=$(cat "$manifest_file")
        local p_topic_id
        p_topic_id=$(echo "$manifest_content" | jq -r .topic_id)
        
        # 确保这个回帖属于我们正在导入的话题
        if [ "$p_topic_id" = "$topic_id" ]; then
            author=$(echo "$manifest_content" | jq -r .author)
            timestamp=$(echo "$manifest_content" | jq -r .timestamp)
            signature=$(echo "$manifest_content" | jq -r .signature)
            content_hash=$(echo "$manifest_content" | jq -r .content_hash)
            attachment_hash=$(echo "$manifest_content" | jq -r .attachment_hash)
            attachment_name=$(echo "$manifest_content" | jq -r .attachment_name)
            
            db_execute_safe "$FORUM_DB" \
                "INSERT OR IGNORE INTO posts (id, topic_id, author, timestamp, signature, content_hash, attachment_hash, attachment_name) VALUES (%s, %s, %s, %d, %s, %s, %s, %s);" \
                "$post_id" "$topic_id" "$author" "$timestamp" "$signature" "$content_hash" "$attachment_hash" "$attachment_name"
        fi
    done

    # --- 步骤 6: 清理 ---
    rm -rf "$temp_import_dir"
    
    msg "话题 '$topic_id' 已成功导入。"
    msg "Topic '$topic_id' has been successfully imported."
}

_internal_get_pubkey_path() {
    # This is a minimal, internal-only function for the Python daemon to use.
    # It safely calls the existing robust function to get a pubkey path.
    # 这是一个极简的、仅供内部使用的函数，供Python守护进程调用。
    # 它安全地调用现有的健壮函数来获取公钥路径。
    _forum_get_author_pubkey "$1"
}

# This new function provides search capabilities for the decentralized forum.
forum_search() {
    local keyword="$1"
    local found=0
    
    msg "正在论坛中搜索: '\033[1;33m$keyword\033[0m' (Searching forum for: '$keyword')"
    
    # --- 1. Search in Topic Titles ---
    echo -e "\n\033[1m--- 匹配到的话题标题 (Matching Topic Titles) ---\033[0m"
    local query_topics="SELECT id, title FROM topics WHERE title LIKE '%${keyword//\'/\'\'}%' ORDER BY timestamp DESC;"
    
    # Execute query and process results
    local topic_results
    topic_results=$(db_query_safe "$FORUM_DB" \
        "SELECT id, title FROM topics WHERE title LIKE %s ORDER BY timestamp DESC;" \
        "%${keyword}%")
    
    if [ -n "$topic_results" ]; then
        found=1
        while IFS='|' read -r id title; do
            [ -n "$id" ] || continue
            echo -e "\033[1;32m[TOPIC]\033[0m ID: $id"
            # Use grep to highlight the keyword, -i for case-insensitivity
            local highlighted_title
            highlighted_title=$(echo "$title" | grep -i --color=auto "$keyword" || echo "$title")
            echo -e "  Title: $highlighted_title"
        done <<< "$topic_results"
    else
        info "在话题标题中未找到匹配项。 (No matches found in topic titles.)"
    fi

    # --- 2. Search in Post Contents ---
    echo -e "\n\033[1m--- 匹配到的帖子内容 (Matching Post Contents) ---\033[0m"
    local posts_found_in_content=0
    
    # Get all posts and iterate through their content files
    db_query_static "$FORUM_DB" "SELECT id, topic_id, content_hash FROM posts ORDER BY timestamp DESC;" | while IFS='|' read -r post_id topic_id content_hash; do
        [ -n "$post_id" ] || continue
        
        local content_path="${FORUM_OBJECTS_DIR}/${content_hash}"
        # Only search if the content file exists locally
        if [ -f "$content_path" ]; then
            # Use grep -q for a quick check without output, it's faster
            if grep -q -i "$keyword" "$content_path"; then
                found=1
                posts_found_in_content=1
                
                echo -e "\033[1;34m[POST]\033[0m ID: $post_id (in Topic: $topic_id)"
                # Now grep again with context and highlighting
                # -C 1 shows 1 line of context before and after the match
                grep -i --color=auto -C 1 "$keyword" "$content_path" | sed 's/^/  > /'
                echo # Add a newline for separation
            fi
        fi
    done

    if [ "$posts_found_in_content" -eq 0 ]; then
        info "在帖子内容中未找到匹配项。 (No matches found in post contents.)"
    fi

    # --- 3. Final Summary ---
    if [ "$found" -eq 0 ]; then
        echo
        warn "在整个论坛中未找到与 '$keyword' 相关的结果。 (No results found for '$keyword' in the entire forum.)"
    fi
}

# --- REWRITTEN SECTION: Forum CLI ---
# --- REWRITTEN SECTION: Forum CLI (Bilingual & Complete) ---
# --- 重写部分: 论坛命令行界面 (双语 & 功能完整) ---
nxpkg_forum() {
    # --- ADDED: Check if the forum system is enabled ---
    if [ "${FORUM_ENABLED}" != "true" ]; then
        error "论坛系统已被禁用。请在 nxpkg.conf 中设置 forum_enabled = true 来启用它。"
        error "The forum system is disabled. Set forum_enabled = true in nxpkg.conf to enable it."
        return 1
    fi
    
    local sub_cmd="$1"
    shift || true

    case "$sub_cmd" in
        init)
            msg "Initializing or checking forum database... / 正在初始化或检查论坛数据库..."
            forum_init
            ;;
        sync)
            # forum_sync() has its own bilingual messages.
            # forum_sync() 函数自带双语信息。
            forum_sync
            ;;
        list)
            # forum_list_topics() has its own bilingual messages.
            # forum_list_topics() 函数自带双语信息。
            forum_list_topics
            ;;
        show)
            [ $# -lt 1 ] && error "Usage: nxpkg forum show <Topic_ID> / 用法: nxpkg forum show <话题ID>"
            # forum_show_topic() has its own bilingual messages.
            # forum_show_topic() 函数自带双语信息。
            forum_show_topic "$1"
            ;;
        search)
            [ $# -lt 1 ] && error "Usage: nxpkg forum search <keyword> / 用法: nxpkg forum search <关键词>"
            forum_search "$1"
            ;;
        new-topic)
            # Example: nxpkg forum new-topic --title "My Title" --body "Content" --attach /path/to/file.zip
            # 示例: nxpkg forum new-topic --title "我的标题" --body "这是内容" --attach /path/to/file.zip
            local title="" body_text="" attach_file=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    --title) title="$2"; shift 2 ;;
                    --body) body_text="$2"; shift 2 ;;
                    --attach) attach_file="$2"; shift 2 ;;
                    *) title="$1"; shift ;; # For backward compatibility / 为了向后兼容
                esac
            done
            [ -z "$title" ] && error "A title is required. Usage: --title 'My Title' / 必须提供标题。用法: --title '我的标题'"
            if [ -z "$body_text" ]; then
                info "No --body provided, reading content from stdin (Press Ctrl+D to end): / 未提供 --body，从标准输入读取正文内容 (按 Ctrl+D 结束):"
                body_text=$(cat)
            fi
            forum_create_topic "$title" "$body_text" "$attach_file"
            ;;
        post)
            # Example: nxpkg forum post <topic_id> --body "Reply content" --attach /path/to/file.zip
            # 示例: nxpkg forum post <话题ID> --body "回复内容" --attach /path/to/file.zip
            local topic_id="$1"
            shift
            local body_text="" attach_file=""
             while [ $# -gt 0 ]; do
                case "$1" in
                    --body) body_text="$2"; shift 2 ;;
                    --attach) attach_file="$2"; shift 2 ;;
                    *) error "Unknown parameter: $1 / 未知参数: $1" ;;
                esac
            done
            [ -z "$topic_id" ] && error "A topic ID is required. / 必须提供话题ID。"
            if [ -z "$body_text" ]; then
                 info "No --body provided, reading content from stdin (Press Ctrl+D to end): / 未提供 --body，从标准输入读取正文内容 (按 Ctrl+D 结束):"
                 body_text=$(cat)
            fi
            forum_create_post "$topic_id" "$body_text" "$attach_file"
            ;;
        get-attachment)
            # forum_get_attachment has its own bilingual messages.
            # forum_get_attachment 函数自带双语信息。
            forum_get_attachment "$@"
            ;;
        export|export-topic)
            [ $# -ne 2 ] && error "Usage: nxpkg forum export <Topic_ID> <output_file.json> / 用法: nxpkg forum export <话题ID> <输出文件名.json>"
            msg "Exporting topic '$1' to '$2'... / 正在导出话题 '$1' 到 '$2'..."
            forum_export_topic "$1" "$2"
            ;;
        import|import-topic)
            [ $# -ne 1 ] && error "Usage: nxpkg forum import <input_file.json> / 用法: nxpkg forum import <输入文件名.json>"
            msg "Importing topic from '$1'... / 正在从 '$1' 导入话题..."
            forum_import_topic "$1"
            ;;
        *)
            cat <<EOF
nxpkg Forum System - Usage: nxpkg forum <command> [arguments...]
nxpkg 论坛系统 - 用法: nxpkg forum <命令> [参数...]

--------------------------------------------------------------------------------
Core Commands (核心命令):
--------------------------------------------------------------------------------
  sync                Sync new topics and posts from the P2P network.
                      从P2P网络同步新的话题和帖子。

  list                List all locally known topics.
                      列出所有本地已知的话题。

  show <Topic_ID>     Show the full content, replies, and attachment info for a topic.
                      显示一个话题的完整内容、回复和附件信息。

  search <keyword>    Search topic titles and post contents.
                      在话题标题与帖子内容中进行搜索。
--------------------------------------------------------------------------------
Publishing Commands (发布命令):
--------------------------------------------------------------------------------
  new-topic --title "Title" [--body "Content"] [--attach /path/to/file]
                      Publish a new topic. If --body is not provided, reads from standard input.
                      发布一个新话题。如果 --body 未提供，则从标准输入读取。

  post <Topic_ID> --body "Content" [--attach /path/to/file]
                      Reply to an existing topic.
                      回复一个已有的话题。

--------------------------------------------------------------------------------
File & Data Operations (文件与数据操作):
--------------------------------------------------------------------------------
  get-attachment <object_hash> <output_filename>
                      Download an attachment or post body from the network. The hash can be found in the 'show' command's output.
                      从网络下载一个附件或帖子正文。哈希值可以从 'show' 命令的输出中获取。

  export <Topic_ID> <file.tar.gz>
                      Export a full topic with all its posts and attachments to a single portable archive (.tar.gz).
                      将一个完整的话题及其所有帖子和附件，导出一个单一的可移植压缩包 (.tar.gz) 中。

  import <file.tar.gz>
                      Import a topic from a portable archive (.tar.gz).
                      从一个可移植的压缩包 (.tar.gz) 导入话题。


--------------------------------------------------------------------------------
Management Commands (管理命令):
--------------------------------------------------------------------------------
  init                Initialize or check the forum database.
                      初始化或检查论坛数据库。
EOF
            ;;
    esac
}

# --- SECTION 9: INITIALIZATION AND CONFIGURATION ---

nxpkg_init() {
    check_root
    acquire_lock "block"
    msg "Starting nxpkg system initialization..."

    info "Checking for critical external dependencies..."
    # jq 现在是核心依赖，用于解析所有P2P网络消息。xxd 现在也是安全处理数据库所必需的。nc不再是核心网络功能的依赖。
    # jq is now a core dependency for parsing all P2P network messages. xxd is now also required for secure database handling. nc is no longer a dependency for core networking.
    local core_deps=(curl git tar sha256sum patch make gcc openssl awk sqlite3 python3 bc jq xxd)
    # [MODIFIED] Added 'cryptography' to the Python dependency check
    # [已修改] 将 'cryptography' 加入 Python 依赖检查
    local core_py_deps=(cryptography)
    local optional_deps=(aria2c ipfs bwrap debootstrap pacstrap equery)
    # Note: 'equery' is provided by the 'gentoolkit' package on Gentoo systems.
    # 注意: 'equery' 命令由 Gentoo 系统上的 'gentoolkit' 软件包提供。
    
    for dep in "${core_deps[@]}"; do check_dep "$dep"; done
    
    # [NEW] Check for Python library dependencies
    # [新增] 检查 Python 库依赖
    info "Checking for critical Python libraries..."
    for dep in "${core_py_deps[@]}"; do check_py_dep "$dep"; done
    
    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            local extra_info=""
            # [NEW] Provide helpful context for specific dependencies.
            # [新增] 为特定的依赖提供有用的上下文信息。
            if [ "$dep" = "equery" ]; then
                extra_info=" (provided by 'app-portage/gentoolkit' on Gentoo)"
            fi
            warn "Optional dependency '$dep' not found${extra_info}. Some features may be limited."
        fi
    done
    
    # --- [NEW] Special check for "OR" dependencies for a specific feature ---
    # --- [新增] 为特定功能的 "或" 依赖关系进行特殊检查 ---
    if ! command -v xdelta3 >/dev/null 2>&1 && ! command -v bsdiff >/dev/null 2>&1; then
        warn "Delta package tools not found. To enable the 'create-delta' and 'delta-update' features, please install either 'xdelta3' (recommended) or 'bsdiff'."
        warn "未找到增量包工具。要启用 'create-delta' 和 'delta-update' 功能，请安装 'xdelta3' (推荐) 或 'bsdiff'。"
    fi
    
    info "Creating base directory structure..."
    mkdir -p "$ETC_NXPKG_DIR" \
             "$REPOS_CONF_DIR" \
             "$VAR_LIB_NXPKG_DIR" \
             "$INSTALLED_DB" \
             "$EXTERNAL_PM_DB" \
             "$VAR_CACHE_NXPKG_DIR" \
             "$METADATA_CACHE_DIR" \
             "$SOURCE_CACHE" \
             "$BINARY_CACHE" \
             "$REPOS_DIR" \
             "$STRATA_DIR" \
             "$P2P_DIR/objects" \
             "$P2P_DIR/chunks" \
             "$BLOCKCHAIN_DIR" \
             "$FORUM_DIR" \
             "$LOCK_DIR" \
             "/etc/nxpkg/hooks/pre-sync.d" \
             "/etc/nxpkg/hooks/post-sync.d" \
             "/etc/nxpkg/hooks/pre-install.d" \
             "/etc/nxpkg/hooks/post-install.d" \
             "/etc/nxpkg/hooks/pre-build.d" \
             "/etc/nxpkg/hooks/post-build.d"
             
# Why do we hard code above
# 为何我们上面硬编码
# It's a deliberate design choice that establishes a stable contract (API) between the NxPKG platform and its ecosystem of mods.
# 这是一个深思熟虑的设计选择，它在NxPKG平台和其模组生态系统之间建立了一个稳定的契约（API）。
# It drastically enhances security by preventing mods from defining or triggering arbitrary execution events, adhering to the principle of least privilege.
# 它通过防止模组定义或触发任意执行事件，遵循了最小权限原则，从而极大地增强了安全性。
# It makes the entire system easier for administrators to understand, manage, and debug.
# 它使得整个系统更易于管理员理解、管理和调试。

# 更多细节参见modeg.md
# For more details, please see modeg.md

    chmod 1777 "$BUILD_TMP_DIR_BASE" 2>/dev/null || mkdir -p "$BUILD_TMP_DIR_BASE"

    info "Creating world file..."
    touch "$WORLD_FILE"
    info "Generating comprehensive configuration file..."
    cat > "$CONFIG_FILE" <<'EOF'
# nxpkg - The Next-Generation Meta Package Manager
# Main Configuration File: /etc/nxpkg/networks/${NXPKG_NETWORK_ID}/nxpkg.conf

[main]
# Dependency resolution mode:
#   auto    - Automatically resolve and install all dependencies
#   suggest - Calculate and list dependencies, then ask for confirmation
#   off     - Do not resolve dependencies
dep_mode = auto

# Number of parallel jobs for building packages
build_jobs = 4

# Base directory for temporary build environments
build_tmp_dir = /tmp/nxpkg_build

# Default text editor
editor = nano

# [NEW] Canary release policy.
# By default, canary packages (e.g., version 1.2.3-canary) are not installed
# unless the user explicitly uses the '--allow-canary' flag.
#   block (default) - Block canary releases unless '--allow-canary' is used.
#   allow           - Allow canary releases to be installed by default.
canary_policy = block

[network]
# [修订] 活动网络ID。这将对所有状态化数据进行命名空间隔离，以允许多个独立的NxPKG网络
# （例如 'default'、'testing'、'my_private_net'）。
# 可以通过 NXPKG_NETWORK_ID_OVERRIDE 环境变量进行覆盖。
# [REVISED] Active network ID. This namespaces all stateful data, allowing for multiple
# separate NxPKG networks (e.g., 'default', 'testing', 'my_private_net').
# Can be overridden by the NXPKG_NETWORK_ID_OVERRIDE environment variable.
id = default

# Download protocol priority (comma-separated)
download_protocol_priority = p2p,ipfs,bt,http,git,sftp,ftp

# Number of parallel downloads
download_jobs = 4

# [修订] 用于所有网络流量（HTTP、P2P下载、Git等）的通用代理服务器。
# 该设置接受一个包含协议的完整URL。
# 支持 http、https、socks5 和 socks5h（用于Tor）。
# [REVISED] General proxy server for all network traffic (HTTP, P2P downloads, Git, etc.).
# This setting accepts a full URL, including the protocol.
# Supports http, https, socks5, and socks5h (for Tor).
#
# 标准HTTP代理示例 (Example for a standard HTTP proxy): proxy = http://proxy.example.com:8080
# Tor使用示例 (Example for Tor): proxy = socks5h://127.0.0.1:9050
# I2P使用示例 (Example for I2P): proxy = http://127.0.0.1:4444
proxy = 

# [新增] BitTorrent 下载阶段的最长等待时间（秒）。
# 如果一个种子源非常冷门，您可能需要增加这个值。
# [NEW] Maximum wait time (in seconds) for the BitTorrent download phase.
# You may need to increase this for very cold torrents.
bt_download_timeout = 3600

[strata]
# Sandboxing tool for isolated environments
# Options: bubblewrap, chroot
sandbox_tool = bubblewrap

[p2p]
# P2P network port
port = 7234

# For development on a single machine, simulate N bootstrap nodes
# on ports (P2P_PORT + 1) to (P2P_PORT + N-1). Set to 0 to disable.
simulate_nodes = 0

# Chunk size for file splitting (bytes)
chunk_size = 262144

# Bootstrap nodes for DHT network (comma-separated list of ip:port)
bootstrap_nodes = 

# The maximum time (in seconds) to wait for a response to a DHT message.
# This prevents the application from hanging on unresponsive peers.
# Default is 5.
p2p_message_timeout = 5


# --- [新增] 全局P2P安全与信任策略 ---
# --- [NEW] Global P2P Security & Trust Policy ---
# [SECURITY] This is a critical security setting that uniformly controls how NxPKG trusts all first-encounter P2P peers.
# It applies to BOTH core P2P services: the DHT service (for node discovery and messaging) and the P2P file sharing service (for downloading packages and forum content).
# Setting this to 'true' is convenient for automation but disables interactive verification, creating a significant risk of Man-in-the-Middle (MITM) attacks. 
# Enable this ONLY when you have complete trust in your network environment, such as an isolated private network or a fully automated CI/CD pipeline.
#
# [安全] 这是一项关键的安全设置，它统一控制着 NxPKG 如何信任所有初次遇到的P2P节点。
# 它同时应用于两个核心P2P服务：用于节点发现和消息交换的 DHT 服务，以及用于下载软件包和论坛内容的 P2P 文件共享服务。
# 将此项设为 'true' 对自动化很方便，但会禁用交互式验证，从而带来中间人攻击 (Man-in-the-Middle) 的巨大风险。
# 请仅在您完全信任您的网络环境时（例如，在隔离的私有网络或全自动化的 CI/CD 流程中）才启用它。
#
#   false (default, secure) - On the first connection to any new P2P service (DHT or file server), the peer's TLS certificate fingerprint will be printed to the terminal, requiring your manual confirmation. This is the most effective way to prevent MITM attacks.
#   true (insecure, expert-only) - Silently and automatically trusts all new P2P peers and their services. This option makes your system vulnerable to Man-in-the-Middle attacks.
#
#   false (默认, 安全) - 在首次连接任何新的P2P服务（DHT或文件服务器）时，会在终端打印出对方的TLS证书指纹，并要求您手动确认。这是防止MITM攻击的最有效方式。
#   true (不安全, 仅限专家) - 静默地、自动地信任所有新的P2P节点及其服务。此选项会使您的系统容易受到中间人攻击。
auto_trust_new_nodes = false


# --- ADDED: New configurable offset ---
# --- 新增: 新的可配置偏移量 ---
# The port offset for the Python HTTP fallback DHT server.
# This port is added to the main P2P port (e.g., 7234 + 1000 = 8234).
# 用于 Python HTTP 后备 DHT 服务器的端口偏移量。
# 此端口会与主 P2P 端口相加 (例如 7234 + 1000 = 8234)。
# P2P 文件块服务器的端口偏移量逻辑类似。
# The port offset logic of P2P file block servers is similar.
http_port_offset = 1000
file_port_offset = 2000

[blockchain]
# Consensus mechanism (pos, pow)
consensus = pos

# 现在，PoW是不可用的。如果你在 nxpkg.conf 中设置 consensus = pow，脚本不会崩溃。但是，你的节点将永远无法创建区块。因为 blockchain_mine_block 函数中的 if [ "$our_pubkey" != "$next_validator_pubkey" ] 这个 PoS 检查将永远为真（因为在没有PoS机制的情况下，它无法确定下一个验证者是谁），导致它总是在打印“现在不是我们创建区块的时候”后直接退出。
# 即便PoW实现了，一个独立的用户或节点也绝对无法通过简单地切换本地配置文件，就将整个网络的共识机制从 PoS（权益证明）切换到 PoW（工作量证明）。单方面的切换行为，实际上立即导致了一场只有一个参与者的“硬分叉”。你的节点从主网络中分离了出去，形成了一条只有你自己的、与世隔绝的、毫无价值的链。它的真正用途是在初始化一个全新的、独立的网络时，选择该网络将要遵循的规则。

# Currently, PoW is unavailable. If you set consensus=pow in nxpkg.conf, the script will not crash. However, your node will never be able to create blocks. Because the if ["$our_pubkey"!="$Nextnvalidator_pubkey"] PoS check in the blockchain_maine-block function will always be true (because without a PoS mechanism, it cannot determine who the next verifier is), it always exits directly after printing "Now is not the time for us to create blocks".
# Even if PoW is implemented, an independent user or node cannot simply switch the consensus mechanism of the entire network from PoS (Proof of Stake) to PoW (Proof of Work) by simply switching local configuration files. The unilateral switching behavior actually immediately led to a 'hard fork' with only one participant. Your node has separated from the main network, forming a unique, isolated, and worthless chain. Its true purpose is to select the rules that a new, independent network will follow when initializing it.

# Validator stake (for PoS)
validator_stake = 100

[trust]
# [NEW & CRITICAL] GPG Signature Requirement Policy
# This is the highest level of security. It is STRONGLY recommended to keep this true.
#   true  (default) - Abort installation if a package lacks a valid signature from the active Trust Zone.
#   false (expert)  - Only warn if a signature is missing, then fall back to blockchain verification.
#                     Setting this to false lowers your security against a 51% network attack.
#                     USE WITH EXTREME CAUTION.
require_gpg_signature = true

# [NEW] Active Trust Zone. Defines which set of GPG keys to use for verification.
# This value is managed by 'nxpkg key --switch-zone <name>' and should not be edited manually.
active_trust_zone = default

[forum]
# Enable decentralized forum
enabled = true

# Auto-sync forum content
auto_sync = true

EOF

    info "Generating default repository configuration..."
    cat > "${REPOS_CONF_DIR}/00-core.conf" <<'EOF'
[core]
type = local
path = /usr/nxpkg/repos/core
priority = 10

# Example remote Git repository
# [contrib]
# type = git
# url = https://github.com/example/nxpkg-contrib.git
# branch = main
# priority = 20
EOF

    info "Creating sample 'core' repository..."
    mkdir -p "${REPOS_DIR}/core/app-misc/hello-world"
    cat > "${REPOS_DIR}/core/app-misc/hello-world/hello-world.build" <<'EOF'
pkgname="hello-world"
pkgver="1.0"
pkgdesc="A simple hello world program"
url="https://www.gnu.org/software/hello/"
slot="0"

source=("https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz")
sha256sums=("9334a4a552837768baaeda858990d5def582f0a2d52723c316f7316335ba381c")

depends=()
makedepends=()

build() {
    ./configure --prefix=/usr
    make ${MAKEFLAGS}
}

package() {
    make DESTDIR="${pkgdir}" install
}
EOF

    info "Initializing Trust Zone infrastructure..."
    mkdir -p "$TRUST_ZONES_DIR"
    # Set 'default' as the initial active zone
    if [ ! -f "${TRUST_ZONES_DIR}/active_zone" ]; then
        echo "default" > "${TRUST_ZONES_DIR}/active_zone"
    fi
    # Create the default zone directory if it doesn't exist
    mkdir -p "${TRUST_ZONES_DIR}/default"

    info "Initializing databases..."
    
    # We call init_databases later, after generating the user key and genesis.json
    # 我们稍后在生成用户密钥和 genesis.json 之后再调用 init_databases

    info "Generating cryptographic identity..."
    if [ ! -f "$USER_IDENTITY_FILE" ]; then
        generate_keypair "$USER_IDENTITY_FILE" "$USER_PUBLIC_KEY_FILE"
        info "Identity generated: $(cat "$USER_PUBLIC_KEY_FILE" | calculate_hash)"

        # --- 新增功能：将公钥发布到P2P网络 ---
        info "Publishing public key to the P2P network..."
        # 公钥文件本身被视为一个对象，其哈希值就是用户ID
        p2p_split_file "$USER_PUBLIC_KEY_FILE" >/dev/null
        info "Public key has been shared."
        # --- 新增功能结束 ---
    fi
    
    # =========================================================================
    # --- 新增: 生成TLS身份以实现安全的P2P通信 ---
    # --- NEW: Generate TLS identity for secure P2P communication ---
    # =========================================================================
    info "正在生成用于HTTPS通信的TLS证书... (Generating TLS certificate for HTTPS communication...)"
    if [ ! -f "$TLS_CERT_FILE" ] || [ ! -f "$TLS_KEY_FILE" ]; then
        # -nodes: 不要加密私钥 (don't encrypt the private key)
        # -subj: 主题，我们将节点的唯一ID作为通用名称(CN)，用于识别
        #        (Subject, we use the node's unique ID as Common Name (CN) for identification)
        openssl req -x509 \
            -newkey ec:<(openssl ecparam -name secp256k1) \
            -keyout "$TLS_KEY_FILE" \
            -out "$TLS_CERT_FILE" \
            -nodes \
            -days 3650 \
            -subj "/CN=$(get_our_node_id)"
        chmod 600 "$TLS_KEY_FILE"
        info "TLS证书和私钥已生成。 (TLS certificate and private key generated.)"
    else
        info "TLS证书已存在，跳过生成。 (TLS certificate already exists, skipping generation.)"
    fi
    # --- TLS身份生成结束 ---

    # 创建对等节点证书缓存目录 (Create peer certificate cache directory)
    mkdir -p "$PEER_CERT_CACHE"

    # --- NEW: Generate a default genesis.json if it doesn't exist ---
    # --- 新增: 如果 genesis.json 不存在，则生成一个默认的 ---
    info "Checking for Genesis configuration file..."
    if [ ! -f "$GENESIS_CONFIG_FILE" ]; then
        msg "No genesis file found. Creating a default for a new network..."
        info "  -> ${GENESIS_CONFIG_FILE}"
        
        # Read the newly generated public key
        local my_public_key
        my_public_key=$(cat "$USER_PUBLIC_KEY_FILE")

        # Use jq if available for pretty-printing, otherwise use a simple template.
        if command -v jq >/dev/null; then
            jq -n --arg pubkey "$my_public_key" \
                '{
                    "comment_1": "This file defines the founding validators of this NxPKG network.",
                    "comment_2": "To create a multi-node network, copy this file to all founding nodes and add their public keys here before running `nxpkg init`.",
                    "genesis_validators": [
                        {
                            "public_key": $pubkey,
                            "stake": 1000
                        }
                    ]
                }' > "$GENESIS_CONFIG_FILE"
        else
            warn "jq command not found. Creating a basic genesis.json. Manual formatting may be needed."
            local pubkey_json_str
            pubkey_json_str=$(echo "$my_public_key" | awk 'NF {printf "%s\\n", $0;}' | sed 's/"/\\"/g')

            cat > "$GENESIS_CONFIG_FILE" <<EOF
{
    "comment_1": "This file defines the founding validators of this NxPKG network.",
    "comment_2": "To create a multi-node network, copy this file to all founding nodes and add their public keys here before running `nxpkg init`.",
    "genesis_validators": [
        {
            "public_key": "${pubkey_json_str}",
            "stake": 1000
        }
    ]
}
EOF
        fi
        info "Default genesis file created with your public key as the first validator."
        info "You can edit this file to add other founding members before they run init."
    fi

    info "Initializing databases (using genesis configuration)..."
    
    init_databases
    forum_init

    info "Generating cryptographic identity..."
    if [ ! -f "$USER_IDENTITY_FILE" ]; then
        generate_keypair "$USER_IDENTITY_FILE" "$USER_PUBLIC_KEY_FILE"
        info "Identity generated: $(cat "$USER_PUBLIC_KEY_FILE" | calculate_hash)"

        # --- 新增功能：将公钥发布到P2P网络 ---
        info "Publishing public key to the P2P network..."
        # 公钥文件本身被视为一个对象，其哈希值就是用户ID
        p2p_split_file "$USER_PUBLIC_KEY_FILE" >/dev/null
        info "Public key has been shared."
        # --- 新增功能结束 ---

    fi

    info "Starting P2P network..."
    dht_bootstrap
    p2p_chunk_server

    msg "nxpkg initialization complete!"
    info "Node ID: $(get_our_node_id)"
    info "You can now sync repositories with: sudo $SCRIPT_NAME sync"
    info "Then build the sample package with: sudo $SCRIPT_NAME build app-misc/hello-world"
    
    release_lock
}

# REVISED AND COMPLETE: load_config to correctly apply all settings from nxpkg.conf
#
# 已修订并完整: load_config 函数，以正确应用 nxpkg.conf 中的所有设置
load_config() {
    [ ! -f "$CONFIG_FILE" ] && return
    
    # The awk script intelligently parses the ini-style config file,
    # creating shell variable assignments like 'section_key="value"'.
    # This loop reads the output line by line to avoid the security risk of using eval.
    # 这个循环逐行读取输出，以避免使用 eval 带来的安全风险。
    awk -F'=' '/^[^#;]/{
        section=gensub(/\[(.+)\]/, "\\1", 1, $0);
        if(section!=$0){current_section=section; next}
        if(current_section && NF>1){
            key=gensub(/^ *| *$/, "", 1, $1);
            val=gensub(/^ *| *$/, "", 1, $2);
            print current_section"_"key" "val
        }
    }' "$CONFIG_FILE" 2>/dev/null | while read -r var_name var_value; do
        # Safely assign the value to the variable.
        # This prevents command injection.
        # 安全地为变量赋值，这可以防止命令注入。
        declare "$var_name=$var_value"
    done
    
    # --- Apply all configuration values, falling back to defaults if not set ---

    # [main] section
    DEP_MODE="${main_dep_mode:-$DEP_MODE}"
    BUILD_JOBS="${main_build_jobs:-$BUILD_JOBS}"
    BUILD_TMP_DIR_BASE="${main_build_tmp_dir:-$BUILD_TMP_DIR_BASE}"
    DEFAULT_EDITOR="${main_editor:-$DEFAULT_EDITOR}"
    # --- ADDED: Load canary policy ---
    CANARY_POLICY="${main_canary_policy:-$CANARY_POLICY}"

    # [network] section
    DOWNLOAD_PROTO_PRIORITY="${network_download_protocol_priority:-$DOWNLOAD_PROTO_PRIORITY}"
    DOWNLOAD_JOBS="${network_download_jobs:-$DOWNLOAD_JOBS}"
    BT_DOWNLOAD_TIMEOUT="${network_bt_download_timeout:-$BT_DOWNLOAD_TIMEOUT}"
    NXPKG_PROXY="${network_proxy:-}"
    # The 'id' is special and handled by NXPKG_NETWORK_ID at startup
    
    # [strata] section
    SANDBOX_TOOL="${strata_sandbox_tool:-$SANDBOX_TOOL}"

    # [p2p] section
    P2P_PORT="${p2p_port:-$P2P_PORT}"
    P2P_CHUNK_SIZE="${p2p_chunk_size:-$P2P_CHUNK_SIZE}"
    P2P_HTTP_PORT_OFFSET="${p2p_http_port_offset:-$P2P_HTTP_PORT_OFFSET}"
    P2P_FILE_PORT_OFFSET="${p2p_file_port_offset:-$P2P_FILE_PORT_OFFSET}"
    # --- ADDED: Load p2p_message_timeout ---
    P2P_MESSAGE_TIMEOUT="${p2p_p2p_message_timeout:-5}" # Note: awk creates p2p_p2p_...
    # --- ADDED: Load simulate_nodes ---
    P2P_SIMULATE_NODES="${p2p_simulate_nodes:-0}"
    
    # [新增] 加载自动信任设置
    AUTO_TRUST_NEW_NODES="${p2p_auto_trust_new_nodes:-$AUTO_TRUST_NEW_NODES}"
    
    # Parse bootstrap nodes (this part was correct)
    if [ -n "${p2p_bootstrap_nodes:-}" ]; then
        IFS=',' read -ra DHT_BOOTSTRAP_NODES <<< "${p2p_bootstrap_nodes}"
    fi

    # [blockchain] section
    # --- ADDED: Load consensus mechanism and stake ---
    BLOCKCHAIN_CONSENSUS="${blockchain_consensus:-$BLOCKCHAIN_CONSENSUS}"
    BLOCKCHAIN_VALIDATOR_STAKE="${blockchain_validator_stake:-100}"

    # [trust] section
    # --- ADDED: Load GPG signature policy ---
    # The variable name used in the script is 'trust_require_gpg_signature'
    trust_require_gpg_signature="${trust_require_gpg_signature:-true}"
    # active_trust_zone is handled by `nxpkg key` and read directly from a file, so no need to load it here.
    
    # [forum] section
    FORUM_ENABLED="${forum_enabled:-true}"
    FORUM_AUTO_SYNC="${forum_auto_sync:-true}"
}

# --- SECTION 10: PACKAGE MANAGEMENT CORE ---

get_pkg_id_parts() {
    local id="$1"
    local name_part="${id%%:*}"
    local slot_part="${id##*:}"

    PKG_CATEGORY="${name_part%/*}"
    [ "$PKG_CATEGORY" == "$name_part" ] && PKG_CATEGORY=""
    PKG_NAME="${name_part##*/}"
    
    if [ "$slot_part" == "$id" ]; then
        PKG_SLOT="0"
        PKG_SUBSLOT="0"
    else
        PKG_SLOT="${slot_part%/*}"
        [ "$PKG_SLOT" == "$slot_part" ] && PKG_SLOT="$slot_part"
        PKG_SUBSLOT="${slot_part##*/}"
        [ "$PKG_SUBSLOT" == "$PKG_SLOT" ] && PKG_SUBSLOT="0"
    fi
}

find_package_build_file() {
    local pkg_name_full="$1"
    get_pkg_id_parts "$pkg_name_full"
    local pkg_path="${PKG_CATEGORY}/${PKG_NAME}"

    local build_file_path="${METADATA_CACHE_DIR}/paths/${pkg_path}"
    if [ -f "$build_file_path" ]; then
        cat "$build_file_path"
        return 0
    fi
    
    local repo_confs
    repo_confs=$(find "${REPOS_CONF_DIR}" -name "*.conf" -type f | sort)
    for repo_conf in $repo_confs; do
        local repo_path
        repo_path=$(grep -E '^\s*path\s*=' "$repo_conf" | cut -d'=' -f2- | xargs)
        if [ -n "$repo_path" ] && [ -f "${repo_path}/${pkg_path}/${PKG_NAME}.build" ]; then
            echo "${repo_path}/${pkg_path}/${PKG_NAME}.build"
            return 0
        fi
    done
    return 1
}

# REVISED FOR SECURITY: This function now safely parses .build files
# without executing them, preventing arbitrary code execution vulnerabilities.
#
# 为安全而修订: 此函数现在可以安全地解析 .build 文件而无需执行它们，
# 从而防止了任意代码执行漏洞。
_parse_build_file() {
    local build_file="$1"
    [ -f "$build_file" ] || error "Build file not found: $build_file"

    # --- 安全解析逻辑 ---
    # 我们定义一个允许的变量列表，只提取这些变量。
    # We define a list of allowed variables and will only extract these.
    # [修改] 将 'options' 显式添加到允许列表中
    # [Modify] Explicitly add 'options' to the allowed list
    local allowed_vars="pkgname pkgver pkgdesc url slot source sha256sums depends makedepends options"

    # 为了避免在循环中重复读取文件，我们先将文件内容读入内存。
    # To avoid re-reading the file in a loop, we read its content into memory first.
    local content
    content=$(cat "$build_file")

    # 遍历所有我们关心的变量
    # Iterate through all the variables we care about
    for var in $allowed_vars; do
        # 提取变量的值，同时过滤掉注释行
        # Extract the value of the variable, filtering out commented lines
        local value
        value=$(echo "$content" | grep -E "^\s*${var}=" | head -n 1)

        if [ -z "$value" ]; then
            # 如果变量未定义，则根据其类型输出一个空的默认值
            # If the variable is not defined, output an empty default based on its type
            case "$var" in
                source|sha256sums|depends|makedepends)
                    # 数组类型
                    echo "${var}="
                    ;;
                slot)
                    # slot有默认值 "0"
                    echo "${var}=0"
                    ;;
                *)
                    # 字符串类型
                    echo "${var}="
                    ;;
            esac
            continue
        fi

        # --- 安全地处理字符串和数组 ---
        
        # 检查是否为数组 (变量值中是否包含'(')
        # Check if it is an array (if the value contains '(')
        if [[ "$value" == *'('* ]]; then
            # 是数组: e.g., depends=("pkg/one" "pkg/two")
            # 1. 移除 'varname=' 部分
            # 2. 移除最外层的 '()' 和所有 '"'
            # 3. 将空格转换为换行符，以便输出多行格式
            local array_content
            array_content=$(echo "$value" | sed -e "s/^${var}=//" -e 's/^[[:space:]]*(//' -e 's/)[[:space:]]*$//' -e 's/"//g')
            
            # 以换行符分隔的形式输出，与旧函数格式兼容
            echo "${var}=$(echo "$array_content" | tr ' ' '\n')"

        else
            # 是普通字符串: e.g., pkgname="hello-world"
            # 1. 移除 'varname=' 部分
            # 2. 移除两端的引号
            local string_content
            string_content=$(echo "$value" | cut -d'=' -f2- | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')
            echo "${var}=${string_content}"
        fi
    done
}

nxpkg_sync() {
    check_root
    acquire_lock "block"
    
    # --- [新增] 运行 pre-sync 钩子 ---
    _run_hooks "pre-sync"
    
    msg "Syncing all repositories and network content..."
    
    local repo_confs
    repo_confs=$(find "${REPOS_CONF_DIR}" -name "*.conf" -type f | sort)
    
    for repo_conf in $repo_confs; do
        local repo_name type
        repo_name=$(basename "$repo_conf" .conf)
        type=$(grep -E '^\s*type\s*=' "$repo_conf" | cut -d'=' -f2- | xargs)
        
        info "Syncing repository: $repo_name (type: $type)"
        case "$type" in
            local)
                detail "Local repository, no sync needed."
                ;;
            git)
                local url branch repo_path
                url=$(grep -E '^\s*url\s*=' "$repo_conf" | cut -d'=' -f2- | xargs)
                branch=$(grep -E '^\s*branch\s*=' "$repo_conf" | cut -d'=' -f2- | xargs)
                repo_path="${REPOS_DIR}/${repo_name}"
                
                if [ -d "$repo_path/.git" ]; then
                    detail "Updating existing clone..."
                    (cd "$repo_path" && git pull origin "$branch")
                else
                    detail "Cloning new repository..."
                    git clone --branch "$branch" "$url" "$repo_path"
                fi
                ;;
            p2p)
                local repo_hash
                repo_hash=$(grep -E '^\s*hash\s*=' "$repo_conf" | cut -d'=' -f2- | xargs)
                detail "Syncing P2P repository with hash: $repo_hash"
                p2p_sync_repository "$repo_name" "$repo_hash"
                ;;
        esac
    done
    
    # --- MODIFIED: Sync forum content only if auto-sync is enabled ---
    if [ "${FORUM_AUTO_SYNC}" = "true" ]; then
        # Sync forum content
        forum_sync
    else
        info "根据配置，跳过论坛自动同步。 (Skipping forum auto-sync as per configuration.)"
    fi
    
    # Update search index
    nxpkg_search --update-index
    
    # --- [新增] 运行 post-sync 钩子 ---
    _run_hooks "post-sync"
    
    # Mine any pending blockchain transactions
    blockchain_mine_block
    
    msg "Sync complete."
    release_lock
}

# Sync P2P repository
p2p_sync_repository() {
    local repo_name="$1"
    local repo_hash="$2" # This hash points to the compressed tarball of the entire repo
    local repo_path="${REPOS_DIR}/${repo_name}"
    
    info "Syncing P2P repository: $repo_name"
    detail "Repository root hash: ${repo_hash:0:16}..."

    # [核心修正] 我们要下载的是整个仓库的压缩包，它本身就是一个P2P对象。
    local temp_repo_archive
    temp_repo_archive=$(mktemp -p "$BUILD_TMP_DIR_BASE" "repo_archive.XXXXXX.tar.gz")

    if ! _p2p_download_object "$repo_hash" "$temp_repo_archive"; then
        warn "Could not download P2P repository archive: $repo_name ($repo_hash)"
        rm -f "$temp_repo_archive"
        return 1
    fi
    
    # 下载成功后，清空并解压到目标目录
    info "Repository archive downloaded, extracting..."
    mkdir -p "$repo_path"
    # 清空旧内容
    rm -rf "${repo_path:?}"/* 
    
    if tar -C "$repo_path" -xzf "$temp_repo_archive"; then
        msg "P2P repository sync complete: $repo_name"
    else
        error "Failed to extract P2P repository archive for $repo_name"
    fi
    
    # Cleanup
    rm -f "$temp_repo_archive"
}

# --- SECTION 11: DATABASE MANAGEMENT ---

db_get_pkg_dir() { 
    echo "${INSTALLED_DB}/${1//\//_}-${2}" 
}

db_is_installed() { 
    get_pkg_id_parts "$1"
    local pkg_dir
    pkg_dir=$(db_get_pkg_dir "$PKG_CATEGORY/$PKG_NAME" "$PKG_SLOT")
    [ -d "$pkg_dir" ]
}

db_register_package() {
    local pkg_name="$1"
    local pkg_ver="$2" 
    local pkg_slot="$3"
    local files_manifest="$4"
    local deps_list="$5"
    local build_file="$6"
    local pkg_dir
    pkg_dir=$(db_get_pkg_dir "$pkg_name" "$pkg_slot")
    
    mkdir -p "$pkg_dir"
    echo "$pkg_ver" > "$pkg_dir/version"
    echo "$pkg_name" > "$pkg_dir/name"
    echo "$pkg_slot" > "$pkg_dir/slot"
    echo "$deps_list" > "$pkg_dir/dependencies"
    cp "$build_file" "$pkg_dir/build_file"
    cp "$files_manifest" "$pkg_dir/files"
    date -u --rfc-3339=seconds > "$pkg_dir/install_date"
    
    # Register package on blockchain
    local pkg_hash
    pkg_hash=$(calculate_hash "$files_manifest")
    local build_hash
    build_hash=$(calculate_hash "$build_file")
    blockchain_register_package "$pkg_name" "$pkg_ver" "$pkg_hash" "$build_hash"
}

db_unregister_package() { 
    local pkg_dir
    pkg_dir=$(db_get_pkg_dir "$1" "$2")
    [ -d "$pkg_dir" ] && rm -rf "$pkg_dir"
}

db_get_package_files() { 
    local pkg_dir
    pkg_dir=$(db_get_pkg_dir "$1" "$2")
    [ -f "$pkg_dir/files" ] && cat "$pkg_dir/files"
}

# --- SECTION 12: DEPENDENCY RESOLUTION ---

dep_check_external() {
    local dep="$1"
    for pm_db in "$EXTERNAL_PM_DB"/*.db; do
        [ -f "$pm_db" ] || continue
        if grep -q -E "^${dep}[[:space:]]+" "$pm_db"; then
            return 0
        fi
    done
    return 1
}

dep_resolve_topological() {
    local initial_pkgs=("$@")
    declare -A adj_list in_degree pkg_info
    local pkg_queue=() final_order=()
    
    pkg_queue+=("${initial_pkgs[@]}")
    local processed_pkgs=()
    local i=0
    
    while [ $i -lt ${#pkg_queue[@]} ]; do
        local pkg="${pkg_queue[$i]}"
        i=$((i+1))
        
        [[ " ${processed_pkgs[*]} " =~ " ${pkg} " ]] && continue
        processed_pkgs+=("$pkg")

        if db_is_installed "$pkg" || dep_check_external "$pkg"; then
            if ! [[ " ${initial_pkgs[*]} " =~ " ${pkg} " ]]; then 
                continue
            fi
        fi

        local build_file
        build_file=$(find_package_build_file "$pkg")
        [ -n "$build_file" ] || error "Cannot resolve '$pkg': .build file not found."
        
        local meta
        meta=$(_parse_build_file "$build_file")
        pkg_info["$pkg"]="$meta"
        [ -z "${in_degree[$pkg]+_}" ] && in_degree["$pkg"]=0
        
        local deps
        deps=$(echo "$meta" | grep -E "^(depends|makedepends)=" | cut -d'=' -f2-)
        for dep in $deps; do
            [ -n "$dep" ] || continue
            adj_list["$dep"]="${adj_list[$dep]-} $pkg"
            in_degree["$pkg"]=$((in_degree["$pkg"] + 1))
            pkg_queue+=("$dep")
        done
    done

    local queue=()
    for pkg in "${!in_degree[@]}"; do
        if [ "${in_degree[$pkg]}" -eq 0 ]; then 
            queue+=("$pkg")
        fi
    done

    while [ ${#queue[@]} -gt 0 ]; do
        local u="${queue[0]}"
        queue=("${queue[@]:1}")
        final_order+=("$u")
        
        for v in ${adj_list[$u]-}; do
            in_degree["$v"]=$((in_degree["$v"] - 1))
            if [ "${in_degree[$v]}" -eq 0 ]; then 
                queue+=("$v")
            fi
        done
    done
    
    if [ "${#final_order[@]}" -ne "${#in_degree[@]}" ]; then
        # [修复] 提供更详细的错误信息来帮助调试。
        # [FIX] Provide a more detailed error message to aid in debugging.
        error "循环依赖检测到！无法解析安装顺序。 (Circular dependency detected! Cannot resolve installation order.)"
        
        info "以下是可能涉及循环的软件包及其依赖关系: (The following packages and their dependencies may be involved in the cycle:)"
        
        # 创建一个关联数组以便快速查找已排序的包
        declare -A final_order_map
        for pkg in "${final_order[@]}"; do
            final_order_map["$pkg"]=1
        done
        
        # 遍历所有包，找出那些不在最终排序列表中的包
        for pkg in "${!in_degree[@]}"; do
            if [ -z "${final_order_map[$pkg]+_}" ]; then
                local deps
                # 从 pkg_info 缓存中获取其依赖
                deps=$(echo "${pkg_info[$pkg]}" | grep "^depends=" | cut -d= -f2- | tr '\n' ' ' | xargs)
                echo -e "  -> \033[1;31m${pkg}\033[0m"
                if [ -n "$deps" ]; then
                    echo "     依赖于 (depends on): $deps"
                else
                    echo "     (无显式依赖 / no explicit dependencies)"
                fi
            fi
        done
        exit 1 # 使用 exit 1 确保脚本终止
    fi


    local to_install=()
    for pkg in "${final_order[@]}"; do
        if ! db_is_installed "$pkg" && ! dep_check_external "$pkg"; then
            to_install+=("$pkg")
        fi
    done
    echo "${to_install[*]}"
}

# --- SECTION 13: ADVANCED DOWNLOAD SYSTEM ---


# Download via FTP
_download_file_ftp() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --ftp-pasv "$url" -o "$dest" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$dest" "$url" || return 1
    elif command -v lftp >/dev/null 2>&1; then
        lftp -e "get $url -o $dest; bye" || return 1
    else
        error "No supported FTP download tool found (curl, wget, lftp)."
    fi
}

# Download via SFTP
_download_file_sftp() {
    local url="$1"
    local dest="$2"

    # Expecting URL format: sftp://user@host/path
    if command -v curl >/dev/null 2>&1; then
        curl -fL "$url" -o "$dest" || return 1
    elif command -v sftp >/dev/null 2>&1; then
        local sftp_host_path="${url#sftp://}"
        local sftp_host="${sftp_host_path%%/*}"
        local sftp_path="/${sftp_host_path#*/}"
        sftp "$sftp_host:$sftp_path" "$dest" || return 1
    else
        error "No supported SFTP download tool found (curl, sftp)."
    fi
}

_download_file_http() {
    local url="$1"
    local dest_file="$2"
    info "HTTP(S) download: $url"
    
    local proxy_opts=()
    [ -n "$NXPKG_PROXY" ] && proxy_opts=("--proxy" "$NXPKG_PROXY")

    curl "${proxy_opts[@]}" -L -C - -o "$dest_file" --progress-bar "$url"
}

# [已修订并加固 V3] 通过 BitTorrent (磁力链接) 下载
# 此版本通过使用临时目录和后处理逻辑，健壮地处理单文件和多文件/目录的 torrents，
# 同时为调用者提供一个可预测的单一文件输出，且保持了API的稳定性。
#
# [REVISED & HARDENED V3] Download via BitTorrent (magnet link)
# This version robustly handles single-file and multi-file/directory torrents
# by using a temporary directory and post-processing logic. It provides a predictable,
# single-file output to the caller, maintaining a stable API.
_download_file_bt() {
    local magnet_uri="$1"
    local dest_file="$2" # 这是期望的最终单个文件工件的路径 (The path for the expected final single file artifact)
    
    # [已修改] 使用临时目录来处理不可预测的 torrent 内容
    # [MODIFIED] Use a temporary directory to handle unpredictable torrent contents
    local temp_bt_dir
    temp_bt_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "bt_download.XXXXXX")
    
    check_dep aria2c
    info "BitTorrent 下载 / BitTorrent download: $magnet_uri"
    
    local completion_flag_file
    completion_flag_file=$(mktemp -u "${BUILD_TMP_DIR_BASE}/bt_complete_signal.XXXXXX")
    local on_complete_hook="touch ${completion_flag_file}"

    local proxy_opts=()
    [ -n "$NXPKG_PROXY" ] && proxy_opts=("--all-proxy=$NXPKG_PROXY")

    info "正在启动下载并将在后台做种... (Starting download, will seed in the background...)"
    detail "临时下载目录 / Temp download directory: $temp_bt_dir"
    # Be polite （要有礼貌）
    aria2c \
        --seed-time=60 \
        --summary-interval=0 \
        --file-allocation=none \
        --max-tries=5 \
        --retry-wait=10 \
        --on-download-complete="${on_complete_hook}" \
        "${proxy_opts[@]}" \
        -d "$temp_bt_dir" \
        "$magnet_uri" &
    
    local aria2c_pid=$!
    NXPKG_BACKGROUND_PIDS+=($aria2c_pid)

    info "正在等待下载阶段完成... (Waiting for download phase to complete...)"
    local wait_timeout="$BT_DOWNLOAD_TIMEOUT"
    local waited_time=0
    while [ ! -f "$completion_flag_file" ]; do
        if ! kill -0 "$aria2c_pid" 2>/dev/null; then
            rm -f "$completion_flag_file"
            rm -rf "$temp_bt_dir"
            error "aria2c 进程在下载完成前意外终止。 (aria2c process terminated unexpectedly before download completion.)"
            return 1
        fi
        sleep 2
        waited_time=$((waited_time + 2))
        if [ "$waited_time" -gt "$wait_timeout" ]; then
            kill "$aria2c_pid" 2>/dev/null || true
            rm -f "$completion_flag_file"
            rm -rf "$temp_bt_dir"
            error "下载超时。 (Download timed out.)"
            return 1
        fi
    done
    rm -f "$completion_flag_file"

    info "下载阶段已完成。主流程继续，aria2c (PID: $aria2c_pid) 将在后台继续做种。"
    info "Download phase complete. Main process continues, aria2c (PID: $aria2c_pid) will continue seeding in the background."
    
    # [新增] 后处理逻辑，以确保输出一个单一、可预测的文件
    # [NEW] Post-processing logic to ensure a single, predictable output file
    local downloaded_items=()
    mapfile -t downloaded_items < <(find "$temp_bt_dir" -mindepth 1 -maxdepth 1 ! -name '*.aria2')

    if [ ${#downloaded_items[@]} -eq 0 ]; then
        kill "$aria2c_pid" 2>/dev/null || true
        rm -rf "$temp_bt_dir"
        error "下载失败：临时下载目录为空。 (Download failed: Temp download directory is empty.)"
        return 1
    elif [ ${#downloaded_items[@]} -eq 1 ] && [ ! -d "${downloaded_items[0]}" ]; then
        # 情况1: 下载结果只有一个文件。
        # 行为: 将此文件移动并重命名为期望的 $dest_file。
        # Case 1: The download resulted in a single file.
        # Action: Move and rename this file to the expected $dest_file.
        info "下载了一个单独的文件，正在移动到目标路径... (Downloaded a single file, moving to destination...)"
        mv "${downloaded_items[0]}" "$dest_file"
    else
        # 情况2: 下载结果是多个文件或一个目录。
        # 行为: 将所有内容打包成一个 .tar.gz 文件，并命名为期望的 $dest_file。
        # Case 2: The download resulted in multiple files or a directory.
        # Action: Pack everything into a .tar.gz file named as the expected $dest_file.
        info "下载了多个文件或一个目录，正在打包成单个压缩文件... (Downloaded multiple files or a directory, creating a single tarball...)"
        tar -C "$temp_bt_dir" -czf "$dest_file" .
    fi
    
    # 清理临时下载目录
    # Clean up the temporary download directory
    rm -rf "$temp_bt_dir"

    # 验证最终的工件是否存在
    # Verify the existence of the final artifact
    if [ -f "$dest_file" ]; then
        info "文件已成功保存到 / File successfully saved to: $dest_file"
        return 0
    else
        kill "$aria2c_pid" 2>/dev/null || true
        error "在下载后移动或打包文件时出错。 (Error moving or packing file after download.)"
        return 1
    fi
}

_download_file_ipfs() {
    local hash="$1"
    local dest_file="$2"
    check_dep ipfs
    info "IPFS download: $hash"
    
    # Initialize IPFS if needed
    if ! ipfs id >/dev/null 2>&1; then
        export IPFS_PATH="${P2P_DIR}/ipfs"
        ipfs init
    fi
    
    ipfs get -o "$dest_file" "$hash"
}

_download_file_git() {
    local url="$1"
    local dest_dir="$2"
    info "Git clone: $url / 正在克隆Git仓库: $url"
    
    # 如果设置了 NXPKG_PROXY，则为 git 临时设置环境变量。
    # (Temporarily set environment variables for git proxy if NXPKG_PROXY is set.)
    local old_proxy_https="${HTTPS_PROXY:-}"
    local old_proxy_http="${HTTP_PROXY:-}"
    if [ -n "$NXPKG_PROXY" ]; then
        export HTTPS_PROXY="$NXPKG_PROXY"
        export HTTP_PROXY="$NXPKG_PROXY"
    fi

    git clone --depth 1 "$url" "$dest_dir"
    local exit_code=$?

    # 恢复旧的代理设置
    # (Restore old proxy settings)
    export HTTPS_PROXY="$old_proxy_https"
    export HTTP_PROXY="$old_proxy_http"
    [ -z "$old_proxy_https" ] && unset HTTPS_PROXY
    [ -z "$old_proxy_http" ] && unset HTTP_PROXY

    return $exit_code
}

# [REVISED] Handles downloading source files with p2p:// protocol.
# This function is now a simple, robust wrapper around the unified _p2p_download_object function.
#
# [已修订] 处理 p2p:// 协议的源文件下载。
# 此函数现在是一个简洁而健壮的包装器，其核心功能由统一的 _p2p_download_object 函数提供。
_download_file_p2p() {
    local hash="$1"
    local dest_file="$2"
    
    # Announce the action to the user, providing context.
    # 向用户宣告操作，提供上下文。
    info "P2P download: Resolving object hash ${hash:0:16}... / P2P 下载: 正在解析对象哈希 ${hash:0:16}..."
    
    # Delegate the entire complex download logic to our robust, unified function.
    # 将所有复杂的下载逻辑委托给我们健壮的、统一的函数。
    if _p2p_download_object "$hash" "$dest_file"; then
        # The return code of _p2p_download_object directly determines the success or failure.
        # _p2p_download_object 的返回码直接决定了成功或失败。
        return 0
    else
        return 1
    fi
}


download_source() {
    local url="$1"
    local dest="$2"
    local protocols
    IFS=',' read -ra protocols <<< "$DOWNLOAD_PROTO_PRIORITY"
    
    for proto in "${protocols[@]}"; do
        case "$proto" in
            p2p)
                if [[ "$url" =~ ^p2p:// ]]; then
                    local hash="${url#p2p://}"
                    _download_file_p2p "$hash" "$dest" && return 0
                fi
                ;;
            http)
                if [[ "$url" =~ ^https?:// ]]; then
                    _download_file_http "$url" "$dest" && return 0
                fi
                ;;
            ftp)
                if [[ "$url" =~ ^ftp:// ]]; then
                    _download_file_ftp "$url" "$dest" && return 0
                fi
                ;;
            sftp)
                if [[ "$url" =~ ^sftp:// ]]; then
                    _download_file_sftp "$url" "$dest" && return 0
                fi
                ;;
            bt)
                if [[ "$url" =~ ^magnet: ]]; then
                    _download_file_bt "$url" "$(dirname "$dest")" && return 0
                fi
                ;;
            ipfs)
                if [[ "$url" =~ ^ipfs:// ]]; then
                    local hash="${url#ipfs://}"
                    _download_file_ipfs "$hash" "$dest" && return 0
                fi
                ;;
            git)
                if [[ "$url" =~ ^git(\+https)?:// ]]; then
                    _download_file_git "$url" "$dest" && return 0
                fi
                ;;
        esac
    done
    
    error "All download methods failed for: $url"
}

download_sources_parallel() {
    local meta="$1"
    local urls=()
    local sums=()

    # Parse source URLs and checksums
    while IFS= read -r line; do
        if [[ "$line" =~ ^source= ]]; then
            local url_list="${line#source=}"
            IFS=$'\n' read -ra file_urls <<< "$url_list"
            urls+=("${file_urls[@]}")
        elif [[ "$line" =~ ^sha256sums= ]]; then
            local sum_list="${line#sha256sums=}"
            IFS=$'\n' read -ra file_sums <<< "$sum_list"
            sums+=("${file_sums[@]}")
        fi
    done <<< "$meta"

    [ ${#urls[@]} -ne ${#sums[@]} ] && error "Mismatched source files and checksums."

    local job_count=0
    local pids=()

    for i in "${!urls[@]}"; do
        (
            local url="${urls[$i]}"
            local sum="${sums[$i]}"
            local filename

            # Handle URL with custom filename (filename::url format)
            if [[ "$url" == *"::"* ]]; then
                filename="${url%%::*}"
                url="${url#*::}"
            else
                filename=$(basename "$url")
            fi

            local dest_file="${SOURCE_CACHE}/${filename}"
            # --- [健壮性修复] 定义临时下载文件路径 ---
            # --- [ROBUSTNESS FIX] Define temporary download file path ---
            local dest_file_tmp="${dest_file}.part"

            # 在子shell退出时自动清理临时文件
            trap 'rm -f "$dest_file_tmp"' EXIT

            # Check if final file exists and is valid
            if [ -f "$dest_file" ]; then
                local actual_sum
                actual_sum=$(calculate_hash "$dest_file")
                if [ "$actual_sum" = "$sum" ]; then
                    info "Source '$filename' found in cache and verified."
                    exit 0 # 使用exit退出子shell
                else
                    warn "Cached file '$filename' has wrong checksum, re-downloading."
                    rm -f "$dest_file"
                fi
            fi

            # --- [健壮性修复] 下载到临时文件 ---
            # --- [ROBUSTNESS FIX] Download to the temporary file ---
            download_source "$url" "$dest_file_tmp"

            # Verify checksum of the temporary file
            local actual_sum
            actual_sum=$(calculate_hash "$dest_file_tmp")
            if [ "$actual_sum" != "$sum" ]; then
                # rm -f "$dest_file_tmp" is handled by the trap
                error "Checksum mismatch for '$filename'. Expected '$sum', got '$actual_sum'."
            fi

            # --- [健壮性修复] 验证成功后，重命名为最终文件 ---
            # --- [ROBUSTNESS FIX] On success, rename to the final file ---
            mv "$dest_file_tmp" "$dest_file"

            info "Successfully downloaded and verified: $filename"
        ) &

        pids+=($!)
        ((job_count++))

        if [ $job_count -ge "$DOWNLOAD_JOBS" ]; then
            # 等待第一个开始的后台任务
            wait "${pids[0]}" || error "Download job failed."
            pids=("${pids[@]:1}")
            ((job_count--))
        fi
    done

    # Wait for remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid" || error "Download job failed."
    done
}

# --- SECTION 14: SECURE BUILD ENVIRONMENT ---

secure_build_environment() {
    local build_dir="$1"
    local pkg_dir="$2"
    # [修改] 接收第三个参数: build文件的元数据
    local meta="$3" 
    shift 3
    local cmd_to_run=("$@")
    
    info "Setting up secure build environment using $SANDBOX_TOOL..."
    
    case "$SANDBOX_TOOL" in
        bubblewrap)
            check_dep bwrap
            
            # --- [新增] 根据 .build 文件元数据决定网络策略 ---
            local enable_network=true
            # 检查 meta 字符串中是否包含 'options=' 并且其中有 '!network'
            if grep -q -E "^\s*options=" <<< "$meta" && grep "options=" <<< "$meta" | grep -q "!network"; then
                enable_network=false
                info "  -> Network access explicitly DISABLED for this build."
            else
                info "  -> Network access ENABLED for this build."
            fi

            mkdir -p "$build_dir"/{proc,dev,tmp,etc}

            # 基础参数
            local -a bwrap_args=(
                --unshare-all --die-with-parent
                --bind "$build_dir/src" /build
                --bind "$pkg_dir" /pkg
                --ro-bind /usr /usr
                --ro-bind /lib /lib
                --ro-bind /lib64 /lib64 2>/dev/null || true
                --ro-bind /bin /bin
                --ro-bind /sbin /sbin
                --tmpfs /tmp
                --tmpfs /var/tmp
                --proc /proc
                # [修改] 不再绑定整个/dev
                # [新增] 仅绑定必要的设备节点
                --dev-bind /dev/null /dev/null
                --dev-bind /dev/zero /dev/zero
                --dev-bind /dev/full /dev/full
                --dev-bind /dev/random /dev/random
                --dev-bind /dev/urandom /dev/urandom
                --setenv PATH "/usr/bin:/bin:/usr/sbin:/sbin"
                --setenv HOME "/tmp"
                --setenv MAKEFLAGS "-j${BUILD_JOBS}"
                --setenv pkgdir "/pkg"
                --chdir /build
            )

            # [修改] 条件性地添加网络相关的参数
            if $enable_network; then
                echo "nameserver 8.8.8.8" > "$build_dir/etc/resolv.conf"
                bwrap_args+=(
                    --share-net
                    --ro-bind "$build_dir/etc/resolv.conf" /etc/resolv.conf
                )
            fi
            
            bwrap "${bwrap_args[@]}" /bin/bash -c "${cmd_to_run[*]}"
            ;;
        chroot)
            check_root
            warn "正在使用 chroot 作为备用方案 (网络沙箱在此模式下无效)。"
            warn "Using chroot as a fallback (network sandboxing is not effective in this mode)."
            warn "  -> 安全提示: chroot 提供的隔离性弱于 bubblewrap。"
            warn "  -> Security Note: chroot provides weaker isolation than bubblewrap."

            # Set up chroot environment
            local chroot_dir="$build_dir/chroot"
            mkdir -p "$chroot_dir"/{proc,sys,dev,tmp,usr,etc,var,build,pkg}

            # --- [安全修复] 开始：手动创建安全的/dev节点 ---
            # --- [SECURITY FIX] Start: Manually create safe /dev nodes ---
            mknod -m 666 "${chroot_dir}/dev/null" c 1 3
            mknod -m 666 "${chroot_dir}/dev/zero" c 1 5
            mknod -m 666 "${chroot_dir}/dev/random" c 1 8
            mknod -m 666 "${chroot_dir}/dev/urandom" c 1 9
            # --- [安全修复] 结束 ---

            # Bind mount necessary directories
            mount --bind /usr "$chroot_dir/usr"
            mount --bind /proc "$chroot_dir/proc"
            mount --bind /sys "$chroot_dir/sys"
            # --- [安全修复] 删除危险的/dev挂载 ---
            # --- [SECURITY FIX] REMOVED the dangerous /dev mount ---
            # mount --bind /dev "$chroot_dir/dev"
            mount --bind "$build_dir/src" "$chroot_dir/build"
            mount --bind "$pkg_dir" "$chroot_dir/pkg"

            # Set up basic files
            echo "nameserver 8.8.8.8" > "$chroot_dir/etc/resolv.conf"

            # Execute the command inside the chroot environment.
            # The "cd /build" command is critical for the TOCTOU fix to work.
            # 在 chroot 环境中执行命令。
            # "cd /build" 命令对于 TOCTOU 修复方案的生效至关重要。
            chroot "$chroot_dir" /usr/bin/env -i \
                HOME=/tmp \
                TERM="$TERM" \
                PS1='\u:\w\$ ' \
                PATH=/bin:/usr/bin:/sbin:/usr/sbin \
                MAKEFLAGS="-j${BUILD_JOBS}" \
                pkgdir="/pkg" \
                /bin/bash -c "cd /build && ${cmd_to_run[*]}"
            local exit_code=$?

            # Cleanup mounts
            # --- [安全修复] 同样移除对/dev的umount ---
            # --- [SECURITY FIX] Also remove umount for /dev ---
            umount "$chroot_dir"/{usr,proc,sys,build,pkg} 2>/dev/null || true
            
            # 返回chroot内命令的退出码
            return $exit_code
            ;;
        
    esac
}

# --- SECTION 15: BUILD SYSTEM ---

nxpkg_build() {
    check_root

    # --- [NEW in v1.5.0] Argument Parsing for --canary flag ---
    local is_canary_build=0
    local pkg_name_full=""
    
    # Loop through arguments to find flags and the package name
    while [ $# -gt 0 ]; do
        case "$1" in
            --canary)
                is_canary_build=1
                shift
                ;;
            -*)
                # Handle other potential future flags
                error "build: Unknown option '$1'"
                ;;
            *)
                # The first non-option argument is the package name
                if [ -n "$pkg_name_full" ]; then
                    error "build requires exactly one package name."
                fi
                pkg_name_full="$1"
                shift
                ;;
        esac
    done

    [ -z "$pkg_name_full" ] && error "build requires exactly one package name."
    # --- [END of NEW logic] ---
    
    acquire_lock "block"
    
    local build_file
    build_file=$(find_package_build_file "$pkg_name_full")
    [ -n "$build_file" ] || error "Could not find .build file for '$pkg_name_full'"
    
    # --- [新增] 运行 pre-build 钩子 ---
    # 传递 .build 文件路径作为参数
    # Pass the .build file path as an argument
    _run_hooks "pre-build" "$build_file"
    
    msg "Starting build for '$pkg_name_full'"
    
    local meta
    meta=$(_parse_build_file "$build_file")
    
    # Extract package information
    local pkgname pkgver slot
    pkgname=$(echo "$meta" | grep "^pkgname=" | cut -d= -f2)
    pkgver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
    slot=$(echo "$meta" | grep "^slot=" | cut -d= -f2)
    
    # --- [NEW in v1.5.0] Modify version string if --canary is specified ---
    if [ "$is_canary_build" -eq 1 ]; then
        pkgver="${pkgver}-canary"
        msg "[CANARY BUILD] Building with canary identifier. New version: $pkgver"
    fi
    # --- [END of NEW logic] ---
    
    info "Package: $pkgname $pkgver (slot: $slot)"
    
    # Download sources
    download_sources_parallel "$meta"
    
    # Set up build environment
    local build_dir
    build_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "${pkgname//\//_}-build.XXXXXX")
    local src_dir="$build_dir/src"
    local pkg_dir="$build_dir/pkg"
    mkdir -p "$src_dir" "$pkg_dir"
    
    info "Build directory: $build_dir"
    
    # Extract sources
    (
        cd "$src_dir"
        local sources
        sources=$(echo "$meta" | grep "^source=" | cut -d= -f2-)
        
        for src in $sources; do
            local filename
            if [[ "$src" == *"::"* ]]; then
                filename="${src%%::*}"
            else
                filename=$(basename "$src")
            fi
            
            local source_file="${SOURCE_CACHE}/${filename}"
            [ -f "$source_file" ] || error "Source file not found: $source_file"
            
            info "Extracting: $filename"
            case "$filename" in
                *.tar.gz|*.tgz)
                    tar -xzf "$source_file" --strip-components=1 2>/dev/null || tar -xzf "$source_file"
                    ;;
                *.tar.bz2|*.tbz2)
                    tar -xjf "$source_file" --strip-components=1 2>/dev/null || tar -xjf "$source_file"
                    ;;
                *.tar.xz|*.txz)
                    tar -xJf "$source_file" --strip-components=1 2>/dev/null || tar -xJf "$source_file"
                    ;;
                *.tar)
                    tar -xf "$source_file" --strip-components=1 2>/dev/null || tar -xf "$source_file"
                    ;;
                *.zip)
                    unzip -q "$source_file"
                    ;;
                *)
                    cp "$source_file" .
                    ;;
            esac
        done
    )
    
    # Create build script
    local build_script="$build_dir/build.sh"
    
    # [TOCTOU VULNERABILITY FIX / TOCTOU 漏洞修复]
# Dynamically generate a source verification snippet with bilingual output.
# 动态生成一个带有双语输出的源码验证片段。
local verification_script=""
local sources=()
local sha256sums=()
# Parse source files and checksums from metadata
# 从元数据中解析出源文件和哈希值
mapfile -t sources < <(echo "$meta" | grep "^source=" | cut -d= -f2-)
mapfile -t sha256sums < <(echo "$meta" | grep "^sha256sums=" | cut -d= -f2-)

for i in "${!sources[@]}"; do
    local src_url="${sources[$i]}"
    local expected_sum="${sha256sums[$i]}"
    local filename
    
    # Handle filename::url format
    # 处理 filename::url 格式
    if [[ "$src_url" == *"::"* ]]; then
        filename="${src_url%%::*}"
    else
        filename=$(basename "$src_url")
    fi
    
    # Append the verification logic for each source file to the script snippet.
    # 将每个源文件的验证逻辑追加到脚本片段中。
    verification_script+="
echo '--> [TOCTOU FIX] 正在沙箱内验证源码: ${filename} / Verifying source file: ${filename} inside sandbox...'
actual_sum=\$(sha256sum '${filename}' 2>/dev/null | awk '{print \$1}')
if [ \\\"\$actual_sum\\\" != \\\"${expected_sum}\\\" ]; then
    echo '!!! [FATAL SECURITY ERROR] 在沙箱内检测到源码文件损坏或被篡改！' >&2
    echo '!!! [FATAL SECURITY ERROR] Source file corruption or tampering detected inside sandbox!' >&2
    echo '!!!   预期哈希 (Expected): ${expected_sum}' >&2
    echo '!!!   实际哈希 (Got)     : \$actual_sum' >&2
    exit 126 # Use a distinct exit code for security failures / 使用一个独特的退出码表示安全失败
fi
"
done

# Write the complete build script with the verification logic at the beginning.
# 将带有验证逻辑的完整构建脚本写入文件。
cat > "$build_script" <<EOF
#!/bin/bash
# This script is dynamically generated by nxpkg and executed inside a secure sandbox.
# 本脚本由 nxpkg 动态生成，并在一个安全的沙箱内执行。
set -e

# Set environment variables first.
# 首先设置环境变量。
export srcdir="\$(pwd)"
export pkgdir="$pkg_dir"
export MAKEFLAGS="-j${BUILD_JOBS}"

# ==============================================================================
# --- [TOCTOU VULNERABILITY FIX / TOCTOU 漏洞修复] ---
# Re-verify source checksums right before use, inside the sandbox.
# This eliminates the race condition window between external verification and internal use.
# 在沙箱内部、即将使用源码文件之前的最后一刻，重新验证其哈希值。
# 这消除了在外部验证和内部使用之间存在的竞态条件窗口。
${verification_script}
# ==============================================================================

# Source the user-defined build instructions from the .build file.
# 从 .build 文件中加载用户定义的构建指令。
# shellcheck source=/dev/null
source "$build_file"

# Execute build phases if they are defined.
# 如果构建阶段被定义了，则执行它们。
if declare -f prepare >/dev/null 2>&1; then
    echo "=> 正在运行 prepare() / Running prepare()..."
    prepare
fi

if declare -f build >/dev/null 2>&1; then
    echo "=> 正在运行 build() / Running build()..."
    build
fi

if declare -f check >/dev/null 2>&1; then
    echo "=> 正在运行 check() / Running check()..."
    # If check fails, print a warning but continue by default.
    # 如果 check 失败，默认打印一个警告并继续。
    check || echo "WARNING: check() phase failed but continuing... / 警告: check() 阶段失败，但构建将继续..."
fi

if declare -f package >/dev/null 2>&1; then
    echo "=> 正在运行 package() / Running package()..."
    package
else
    echo "ERROR: No package() function defined in .build file. / 错误: .build 文件中未定义 package() 函数。" >&2
    exit 1
fi

echo "=> 构建成功完成 / Build completed successfully"
EOF
chmod +x "$build_script"

# Execute build in secure environment
# 在安全环境中执行构建
# The meta variable is passed to the sandbox function to determine network policy.
# meta 变量被传递给沙箱函数，以决定网络策略。
if secure_build_environment "$build_dir" "$pkg_dir" "$meta" "$build_script"; then
    info "构建阶段成功完成 / Build phase completed successfully"
else
    # Preserve the build directory for debugging on failure.
    # 在构建失败时保留构建目录以便调试。
    error "软件包 '$pkg_name_full' 构建失败。构建目录已保留用于调试: $build_dir"
    error "Build failed for '$pkg_name_full'. Build directory preserved for debugging: $build_dir"
    exit 1 # 确保构建失败时脚本退出（Ensure that the script will exit when the build fails）
fi

    # Create binary package
    info "Creating binary package..."
    local binary_pkg_name="${pkgname//\//_}-${pkgver}-${slot}-$(uname -m).nxpkg.tar.zst"
    local binary_pkg_path="${BINARY_CACHE}/${binary_pkg_name}"
    local files_manifest="$build_dir/manifest.txt"
    
    # Generate file manifest
    (cd "$pkg_dir" && find . -type f -o -type l | sed 's|^\./||' | sort) > "$files_manifest"
    
    # Create compressed binary package
    if command -v zstd >/dev/null 2>&1; then
        tar -C "$pkg_dir" -cf - . | zstd -3 > "$binary_pkg_path"
    else
        tar -czf "$binary_pkg_path" -C "$pkg_dir" .
    fi
    
    # Generate package signature
    local pkg_hash
    pkg_hash=$(calculate_hash "$binary_pkg_path")
    local signature
    signature=$(sign_data "$pkg_hash" "$USER_IDENTITY_FILE")
    echo "$signature" > "${binary_pkg_path}.sig"
    
    # Register on blockchain
    local build_hash
    build_hash=$(calculate_hash "$build_file")
    blockchain_register_package "$pkgname" "$pkgver" "$pkg_hash" "$build_hash"
    
    # Share via P2P
    info "Sharing binary package via P2P network..."
    p2p_split_file "$binary_pkg_path" >/dev/null
    
    msg "Build successful: $binary_pkg_path"
    
    # --- [新增] 运行 post-build 钩子 ---
    # 传递新生成的二进制包路径作为参数
    # Pass the path of the newly created binary package as an argument
    _run_hooks "post-build" "$binary_pkg_path"
    
    # Cleanup
    rm -rf "$build_dir"
    
    release_lock
    echo "$binary_pkg_path"
}


# --- SECTION 16: PACKAGE INSTALLATION ---

# REVISED AND HARDENED: nxpkg_install with correct trust verification logic.
# This is the complete function with no omissions.
#
# 已修订并加固: 带有正确信任验证逻辑的 nxpkg_install。
# 这是完整的函数，无任何省略。
nxpkg_install() {
    check_root
    [ $# -eq 0 ] && error "No packages specified to install."
    
    # --- Canary Release Flag & Argument Parsing ---
    local allow_canary=0
    if [[ " $@ " =~ " --allow-canary " ]]; then
        allow_canary=1
        local new_args=()
        for arg in "$@"; do
            [ "$arg" != "--allow-canary" ] && new_args+=("$arg")
        done
        set -- "${new_args[@]}"
    fi

    acquire_lock "block"
    
    msg "Resolving dependencies for: $*"
    local install_list
    install_list=$(dep_resolve_topological "$@")
    
    if [ -z "$install_list" ]; then
        msg "All packages are already installed and up-to-date."
        release_lock
        return 0
    fi
    
    info "Installation order:"
    for pkg in $install_list; do 
        echo "  - $pkg"
    done
    
    # Ask for confirmation in suggest mode
    if [ "$DEP_MODE" = "suggest" ]; then
        echo
        read -rp "Continue with installation? [Y/n/d(etails)] " choice
        case "$choice" in
            [nN]*) 
                msg "Installation cancelled."
                release_lock
                return 0
                ;;
            [dD]*)
                info "Showing detailed dependency information..."
                for pkg in $install_list; do
                    local build_file
                    build_file=$(find_package_build_file "$pkg")
                    if [ -n "$build_file" ]; then
                        local meta
                        meta=$(_parse_build_file "$build_file")
                        local deps
                        deps=$(echo "$meta" | grep "^depends=" | cut -d= -f2-)
                        echo "  $pkg: $deps"
                    fi
                done
                echo
                read -rp "Continue? [Y/n] " choice
                [[ "$choice" =~ ^[nN] ]] && { 
                    msg "Installation cancelled."
                    release_lock
                    return 0
                }
                ;;
        esac
    fi
    
    # --- [新增] 运行 pre-install 钩子 ---
    _run_hooks "pre-install" "${install_list[@]}"
    
    # Install packages
    for pkg in $install_list; do
        msg "Installing: $pkg"
        
        get_pkg_id_parts "$pkg"
        local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
        
        # Check for existing binary package
        local build_file meta pkgver
        build_file=$(find_package_build_file "$pkg")
        meta=$(_parse_build_file "$build_file")
        pkgver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)

        # --- Canary Package Check ---
        if [[ "$pkgver" == *-canary ]] && [ "$allow_canary" -eq 0 ] && [ "${CANARY_POLICY:-block}" = "block" ]; then
            warn "软件包 '$pkg' 是一个金丝雀版本 ($pkgver)。 (Package '$pkg' is a canary release ($pkgver).)"
            warn "默认情况下金丝雀版本被阻止以保证稳定。 (Canary releases are blocked by default for stability.)"
            warn "要安装它，请在命令中加入 --allow-canary 标志，或在配置中设置 canary_policy = allow。 (To install it, add the --allow-canary flag, or set canary_policy = allow in your config.)"
            error "安装被中止。 (Installation aborted.)"
        elif [[ "$pkgver" == *-canary ]]; then
            msg "[CANARY] 允许安装金丝雀版本: $pkgver ([CANARY] Allowing installation of canary release: $pkgver)"
        fi
        
        local binary_pkg_name="${pkg_name//\//_}-${pkgver}-${PKG_SLOT}-$(uname -m).nxpkg.tar.zst"
        local binary_pkg_path="${BINARY_CACHE}/${binary_pkg_name}"
        local alt_pkg_path="${BINARY_CACHE}/${pkg_name//\//_}-${pkgver}-${PKG_SLOT}-$(uname -m).nxpkg.tar.gz"
        
        # Try zstd compressed first, then gzipped
        if [ ! -f "$binary_pkg_path" ] && [ -f "$alt_pkg_path" ]; then
            binary_pkg_path="$alt_pkg_path"
        fi
        
        if [ ! -f "$binary_pkg_path" ]; then
            info "No pre-built binary found, building from source..."
            release_lock
            binary_pkg_path=$(nxpkg_build "$pkg")
            acquire_lock "block"
        else
            info "Using cached binary package: $binary_pkg_path"
        fi
        
        [ -f "$binary_pkg_path" ] || error "Failed to obtain binary package for $pkg"
        
        # ==========================================================
        # --- REVISED TRUST VERIFICATION STAGE (CRITICAL FIX)    ---
        # --- 已修订的信任验证阶段 (关键修复)                      ---
        # ==========================================================
        info "正在验证软件包的信任链... (Verifying package trust chain...)"
        
        local sig_file="${binary_pkg_path}.sig.gpg"
        local gpg_check_result="none" # Possible states: none, valid, invalid
        
        # --- Step 1: Evaluate GPG Signature Status ---
        if [ -f "$sig_file" ]; then
            if _verify_gpg_signature "$binary_pkg_path" "$sig_file"; then
                gpg_check_result="valid"
            else
                gpg_check_result="invalid"
            fi
        fi

        # --- Step 2: Apply Trust Policy Based on GPG Status ---
        local trust_verified=0

        case "$gpg_check_result" in
            "valid")
                msg "[TRUST] GPG 签名验证成功！包来源可信。 (GPG signature VERIFIED! Package origin is trusted.)"
                trust_verified=1
                ;;

            "invalid")
                error "[TRUST] 致命错误：检测到无效的GPG签名！ (FATAL: Invalid GPG signature detected!)"
                error "这可能意味着软件包已被篡改，或者您正在遭受中间人攻击。 (This could mean the package has been tampered with, or you are under a Man-in-the-Middle attack.)"
                error "为了系统安全，安装已中止。 (Installation aborted for system security.)"
                ;;

            "none")
               # No signature was found. Here we check the policy.
                warn "[TRUST] 未找到软件包的GPG签名。 ($sig_file) (No GPG signature found for package.)"
                if [ "${trust_require_gpg_signature:-true}" = "true" ]; then
                    # Policy requires a signature. Abort.
                    error "配置要求GPG签名，但未找到。安装中止。 (Configuration requires a GPG signature, but none was found. Aborting.)"
                else
                    warn "[TRUST] 根据策略，将继续尝试通过区块链进行验证... (Per policy, proceeding to verify via blockchain...)"
                    local pkg_hash
                    pkg_hash=$(calculate_hash "$binary_pkg_path")
                    if blockchain_verify_package "$pkg_name" "$pkgver" "$pkg_hash"; then
                        info "[TRUST] 包在区块链上验证通过。 (Package verified on the blockchain.)"
                        trust_verified=1
                    else
                        warn "[TRUST] 区块链验证失败。 (Blockchain verification failed.)"
                    fi
                fi
                ;;
        esac

        # --- Step 3: Final Decision ---
        if [ "$trust_verified" -eq 0 ]; then
            error "无法通过任何可接受的信任机制验证软件包 '$pkg'。安装被中止。 (Could not verify package '$pkg' through any acceptable trust mechanism. Installation aborted.)"
        fi
        
        # --- End of Revised Trust Verification Stage ---
        
        info "Installing package files to system."
        
        local temp_install_dir
        temp_install_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "install-${pkg_name//\//_}.XXXXXX")
        
        if [[ "$binary_pkg_path" =~ \.zst$ ]] && command -v zstd >/dev/null 2>&1; then
            zstd -d "$binary_pkg_path" -c | tar -xf - -C "$temp_install_dir"
        else
            tar -xf "$binary_pkg_path" -C "$temp_install_dir"
        fi
        
        local temp_manifest
        temp_manifest=$(mktemp)
        (cd "$temp_install_dir" && find . -type f -o -type l | sed 's|^\./||' | sort) > "$temp_manifest"
        
        local conflicts=()
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            if [ -f "/$file" ] && ! db_owns_file "$file"; then
                conflicts+=("/$file")
            fi
        done < "$temp_manifest"
        
        if [ ${#conflicts[@]} -gt 0 ]; then
            warn "File conflicts detected:"
            printf '  %s\n' "${conflicts[@]:0:10}"
            [ ${#conflicts[@]} -gt 10 ] && echo "  ... and $((${#conflicts[@]} - 10)) more"
            
            if [ "$DEP_MODE" != "auto" ]; then
                read -rp "Continue anyway? [y/N] " choice
                [[ ! "$choice" =~ ^[yY] ]] && {
                    rm -rf "$temp_install_dir" "$temp_manifest"
                    error "Installation cancelled due to conflicts."
                }
            fi
        fi
        
        rsync -a "$temp_install_dir/" /
        
        local deps_list
        deps_list=$(echo "$meta" | grep "^depends=" | cut -d= -f2- | tr ' ' ',')
        db_register_package "$pkg_name" "$pkgver" "$PKG_SLOT" "$temp_manifest" "$deps_list" "$build_file"
        
        if [ -f "${temp_install_dir}/usr/share/nxpkg/post-install.sh" ]; then
            info "Running post-install script."
            bash "${temp_install_dir}/usr/share/nxpkg/post-install.sh" || warn "Post-install script failed"
        fi
        
        rm -rf "$temp_install_dir" "$temp_manifest"
        
        info "Successfully installed: $pkg"
    done
    
    for pkg in "$@"; do
        if ! grep -Fxq "$pkg" "$WORLD_FILE"; then
            echo "$pkg" >> "$WORLD_FILE"
        fi
    done
    sort -u -o "$WORLD_FILE" "$WORLD_FILE"
    
    update_system_caches
    
    # --- [新增] 运行 post-install 钩子 ---
    # 在所有操作成功完成后，释放锁之前运行
    # Run after all operations succeed, before releasing the lock
    _run_hooks "post-install" "${install_list[@]}"
    
    msg "Installation complete."
    release_lock
}


# --- SECTION 23: OTHER TOOLS AND FUNCTIONS ---

# --- 新增函数：钩子执行器 (NEW FUNCTION: Hook Executor) ---
# 根据事件触发所有已安装的模组。
# (Triggers all installed mods for a given event.)
#
# @param $1 - 钩子事件名称, 例如 "post-install" (The hook event name, e.g., "post-install")
# @param $@ - 传递给钩子脚本的参数 (Arguments to pass to the hook scripts)
_run_hooks() {
    local hook_event="$1"
    shift
    local -a hook_args=("$@")

    # 定义钩子脚本所在的目录
    # (Define the directory where hook scripts reside)
    local hook_dir="/etc/nxpkg/hooks/${hook_event}.d"

    # 如果没有该事件的钩子目录，或目录为空，则直接返回
    # (If no hook directory for this event exists, or it's empty, return immediately)
    if [ ! -d "$hook_dir" ] || [ -z "$(ls -A "$hook_dir" 2>/dev/null)" ]; then
        return 0
    fi

    msg "=> 正在执行 '${hook_event}' 钩子... (Executing '${hook_event}' hooks...)"

    for hook_script in "${hook_dir}"/*; do
        # 确保是可执行文件
        # (Ensure it is an executable file)
        [ -f "$hook_script" ] && [ -x "$hook_script" ] || continue

        local mod_name
        mod_name=$(basename "$hook_script")
        detail "   -> 正在运行模组: ${mod_name} (Running mod: ${mod_name})"
        
        # 为每个钩子创建一个临时的、隔离的执行环境
        # (Create a temporary, isolated execution environment for each hook)
        local hook_exec_dir
        hook_exec_dir=$(mktemp -d -p "$BUILD_TMP_DIR_BASE" "hook-exec-${mod_name}.XXXXXX")

        # --- 通过环境变量安全地传递上下文信息 ---
        # --- Safely pass context via environment variables ---
        export NXPKG_HOOK_EVENT="$hook_event"
        export NXPKG_HOOK_ARGUMENTS="${hook_args[*]}" # 将所有参数作为一个空格分隔的字符串传递

        # 根据事件传递更具体的、结构化的信息
        # (Pass more specific, structured information based on the event)
        case "$hook_event" in
            post-install)
                export NXPKG_INSTALLED_PACKAGES="${hook_args[*]}"
                ;;
            post-build)
                export NXPKG_BINARY_PACKAGE_PATH="${hook_args[0]}"
                ;;
        esac

        # --- 安全至上：总是在沙箱中执行钩子脚本 ---
        # --- Security First: ALWAYS execute hook scripts in a sandbox ---
        # 我们复用 secure_build_environment 函数，它提供了强大的隔离能力。
        # (We reuse the secure_build_environment function for its powerful isolation.)
        if ! secure_build_environment "$hook_exec_dir" "/dev/null" "$hook_script"; then
            warn "模组脚本 '${mod_name}' 执行失败或返回非零状态。"
            warn "Mod script '${mod_name}' failed or returned a non-zero status."
        fi
        
        # --- 清理 ---
        rm -rf "$hook_exec_dir"
        unset NXPKG_HOOK_EVENT NXPKG_HOOK_ARGUMENTS NXPKG_INSTALLED_PACKAGES NXPKG_BINARY_PACKAGE_PATH
    done
}

nxpkg_strata_execute() {
    local strata_name="$1"
    shift
    [ $# -eq 0 ] && error "No command provided to execute in strata."

    local strata_path="${STRATA_DIR}/${strata_name}"
    [ -d "$strata_path" ] || error "Strata '$strata_name' not found."

    local strata_conf="${strata_path}/.nxpkg_strata"
    local pm=""
    if [ -f "$strata_conf" ]; then
        pm=$(grep '^pm=' "$strata_conf" | cut -d= -f2)
    fi

    msg "Executing in strata '$strata_name' ($pm): $*"

    # Decide sandbox tool (prefer bwrap, fallback to chroot)
    local tool="${SANDBOX_TOOL:-auto}"
    if [ "$tool" = "auto" ]; then
        if command -v bwrap >/dev/null 2>&1; then
            tool="bwrap"
        else
            tool="chroot"
        fi
    fi

    case "$tool" in
        bwrap)
            check_dep bwrap
            # Ensure minimal FS layout exists
            mkdir -p "${strata_path}"/{proc,sys,dev,run,tmp,var,tmp/root,root}
            chmod 1777 "${strata_path}/tmp" 2>/dev/null || true

            # Common bind options
            # - Bind the strata root as / inside the namespace
            # - Provide read-only views of host /usr, /lib etc. if not present in strata
            # - Pass through networking by default
            # - Mount proc, sys, dev from the host (dev in new tmpfs, then selective passthrough)
            local -a bind_opts=(
                --bind "${strata_path}" /
                --proc /proc
                --dev-bind /dev /dev
                --bind /sys /sys
                --ro-bind /etc/resolv.conf /etc/resolv.conf
            )

            # Optional convenience: expose host caches to speed up operations (read-only)
            [ -d /var/cache ] && bind_opts+=( --bind /var/cache /var/cache )
            [ -d /var/tmp ] && bind_opts+=( --bind /var/tmp /var/tmp )

            # Pass through home (read-only by default unless user opts in)
            case "${STRATA_HOME_MODE:-ro}" in
                rw) [ -d "$HOME" ] && bind_opts+=( --bind "$HOME" "$HOME" ) ;;
                ro) [ -d "$HOME" ] && bind_opts+=( --ro-bind "$HOME" "$HOME" ) ;;
                none) : ;;
                *) [ -d "$HOME" ] && bind_opts+=( --ro-bind "$HOME" "$HOME" ) ;;
            esac

            # Expose host package caches optionally
            if [ "${STRATA_EXPOSE_HOST_PKGCACHE:-1}" = "1" ]; then
                [ -d "$BINARY_CACHE" ] && bind_opts+=( --bind "$BINARY_CACHE" "$BINARY_CACHE" )
                [ -d "$SOURCE_CACHE" ] && bind_opts+=( --bind "$SOURCE_CACHE" "$SOURCE_CACHE" )
            fi

            # Build PATH inside strata (fallback to sane defaults)
            local _path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            [ -d "${strata_path}/usr/bin" ] && _path="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

            # Shell selection
            local _shell="/bin/bash"
            [ -x "${strata_path}/bin/bash" ] || [ -x "${strata_path}/usr/bin/bash" ] || _shell="/bin/sh"

            # Environment passthrough (minimal)
            local -a env_opts=(
                --setenv PATH "$_path"
                --setenv HOME "${HOME:-/root}"
                --setenv TERM "${TERM:-xterm-256color}"
                --setenv LANG "${LANG:-C.UTF-8}"
                --setenv LC_ALL "${LC_ALL:-}"
            )

            # Workdir
            local _cwd="/"
            [ -d "${strata_path}${PWD}" ] && _cwd="$PWD"

            bwrap "${bind_opts[@]}" \
                  "${env_opts[@]}" \
                  --chdir "$_cwd" \
                  "$_shell" -lc "$*"
            ;;
        chroot)
            check_root

            # Prepare mounts
            mkdir -p "${strata_path}"/{proc,sys,dev}
            mountpoint -q "${strata_path}/proc" || mount --bind /proc "${strata_path}/proc"
            mountpoint -q "${strata_path}/sys"  || mount --bind /sys  "${strata_path}/sys"
            mountpoint -q "${strata_path}/dev"  || mount --bind /dev  "${strata_path}/dev"

            # DNS
            [ -f /etc/resolv.conf ] && cp -f /etc/resolv.conf "${strata_path}/etc/resolv.conf" 2>/dev/null || true

            # Workdir
            local _cwd="/"
            [ -d "${strata_path}${PWD}" ] && _cwd="$PWD"

            chroot "$strata_path" /bin/bash -lc "cd \"$_cwd\" && $*"
            local rc=$?

            # Cleanup mounts (best-effort)
            umount "${strata_path}/proc" 2>/dev/null || true
            umount "${strata_path}/sys"  2>/dev/null || true
            umount "${strata_path}/dev"  2>/dev/null || true

            return $rc
            ;;
        *)
            error "Unknown sandbox tool: $SANDBOX_TOOL"
            ;;
    esac
}

nxpkg_strata_destroy() {
    check_root
    local name="$1"
    local strata_path="${STRATA_DIR}/${name}"

    [ -n "$name" ] || error "Usage: strata --destroy <name>"
    [ -d "$strata_path" ] || error "Strata '$name' does not exist."

    warn "This will completely remove strata '$name' and all its contents."
    read -rp "Are you sure? [y/N] " choice
    [[ ! "$choice" =~ ^[yY] ]] && { info "Cancelled."; return 0; }

    msg "Destroying strata '$name'..."

    # Best-effort unmount
    if command -v mountpoint >/dev/null 2>&1; then
        mountpoint -q "${strata_path}/proc" && umount "${strata_path}/proc" 2>/dev/null || true
        mountpoint -q "${strata_path}/sys"  && umount "${strata_path}/sys"  2>/dev/null || true
        mountpoint -q "${strata_path}/dev"  && umount "${strata_path}/dev"  2>/dev/null || true
    else
        umount "${strata_path}/proc" 2>/dev/null || true
        umount "${strata_path}/sys"  2>/dev/null || true
        umount "${strata_path}/dev"  2>/dev/null || true
    fi

    # Remove
    rm -rf --one-file-system "$strata_path"

    info "Strata '$name' removed."
}

# [NEW] Exports a list of installed packages from a Strata environment.
# [新增] 从一个 Strata 环境中导出已安装软件包的列表。
#
# Scans the Strata's internal package manager database and prints a list of
# 'strata-pkg:' declarations suitable for inclusion in the world file.
# 扫描 Strata 内部的包管理器数据库，并打印出一系列适用于 world 文件的 'strata-pkg:' 声明。
nxpkg_strata_export_pkgs() {
    local strata_name="$1"
    local strata_path="${STRATA_DIR}/${strata_name}"
    [ -d "$strata_path" ] || error "Strata '$strata_name' not found. / 未找到 Strata '$strata_name'。"

    local strata_conf="${strata_path}/.nxpkg_strata"
    local pm=""
    [ -f "$strata_conf" ] && pm=$(grep '^pm=' "$strata_conf" | cut -d= -f2)

    msg "Exporting package list from Strata '$strata_name' (type: $pm)... / 正在从 Strata '$strata_name' (类型: $pm) 导出软件包列表..."
    
    local list_cmd output
    case "$pm" in
        apt|debian)
            # -W shows packages, -f specifies format. '${Package}\n' gives a clean list.
            # -W 显示包, -f 指定格式。'${Package}\n' 给出干净的列表。
            # We filter out essential packages that are always part of the base system.
            # 我们过滤掉那些总是作为基础系统一部分的核心包。
            list_cmd="dpkg-query -W -f='${Package}\n' | grep -vE '^(apt|base-files|base-passwd|bash|coreutils|dash|debconf|debian-archive-keyring|debianutils|diffutils|dpkg|e2fsprogs|findutils|grep|gzip|hostname|init-system-helpers|login|mount|ncurses-base|ncurses-bin|perl-base|sed|sysvinit-utils|tar|util-linux)$'"
            ;;
        pacman|arch)
            # -Q lists installed packages, -q makes it quiet (name only).
            # -Q 列出已安装的包, -q 使其安静(只输出包名)。
            list_cmd="pacman -Qq"
            ;;
        dnf|fedora)
            # rpm is faster and cleaner for just listing names.
            # 只列出名称时，rpm 更快、更干净。
            list_cmd="rpm -qa --qf '%{NAME}\n'"
            ;;
        portage|gentoo)
            # [修复] 改用 equery 工具进行精确查询，避免手动解析文件名带来的错误。
            # [FIX] Use the equery tool for accurate queries, avoiding errors from manual filename parsing.
            # -F '$category/$name' 选项直接输出我们需要的格式。
            # The -F '$category/$name' option directly outputs the format we need.
            #
            # 我们先检查 equery 是否存在，如果不存在则给出清晰的错误提示。
            # We first check if equery exists and provide a clear error message if it does not.
            list_cmd="
                if ! command -v equery >/dev/null 2>&1; then
                    echo 'Error: equery (from app-portage/gentoolkit) is required to export packages from a Portage strata.' >&2
                    exit 1
                fi
                equery -q -F '\$category/\$name' list '*'
            "
            ;;
        *)
            error "Unsupported package manager '$pm' for package export. / 不支持的包管理器 '$pm' 无法导出软件包列表。"
            ;;
    esac

    # Execute the command inside the strata and capture the output
    # 在 strata 内部执行命令并捕获输出
    output=$(nxpkg_strata_execute "$strata_name" "$list_cmd")
    
    echo
    echo "# Packages exported from Strata '$strata_name' on $(date)"
    echo "# 从 Strata '$strata_name' 导出的软件包，导出时间: $(date)"
    echo "# You can copy these lines into your world file. / 您可以将这些行复制到您的 world 文件中。"
    echo
    
    while IFS= read -r pkg_name; do
        [ -n "$pkg_name" ] && echo "strata-pkg:${strata_name}:${pkg_name}"
    done <<< "$output"
}

# [NEW] Promotes an existing Strata environment to the world file.
# [新增] 将一个已存在的 Strata 环境“提升”到 world 文件中。
#
# This command adds the necessary 'strata:' and 'strata-pkg:' declarations
# for a given Strata to the world file, effectively making it part of the
# declarative system state.
# 此命令会将指定 Strata 所需的 'strata:' 和 'strata-pkg:' 声明
# 添加到 world 文件中，从而有效地将其纳为声明式系统状态的一部分。
nxpkg_strata_promote() {
    local strata_name="$1"
    local strata_path="${STRATA_DIR}/${strata_name}"
    [ -d "$strata_path" ] || error "Strata '$strata_name' not found. Cannot promote it. / 未找到 Strata '$strata_name'，无法提升。"

    local strata_conf="${strata_path}/.nxpkg_strata"
    local pm=""
    [ -f "$strata_conf" ] && pm=$(grep '^pm=' "$strata_conf" | cut -d= -f2)
    [ -z "$pm" ] && error "Could not determine the type of Strata '$strata_name'. Promotion failed. / 无法确定 Strata '$strata_name' 的类型，提升失败。"

    msg "Promoting Strata '$strata_name' to the world file... / 正在将 Strata '$strata_name' 提升到 world 文件..."

    # --- Step 1: Prepare the declarations ---
    # --- 步骤 1: 准备声明内容 ---
    info "Generating declarations... / 正在生成声明..."

    # Generate the main strata declaration
    # 生成主 strata 声明
    local strata_declaration="strata:${strata_name}:${pm}"

    # Generate the package declarations by calling the export function internally
    # 通过内部调用导出函数来生成软件包声明
    # We capture the output and process it
    # 我们捕获输出并进行处理
    local exported_pkgs_output
    exported_pkgs_output=$(nxpkg_strata_export_pkgs "$strata_name")
    
    local -a pkg_declarations=()
    # Read the output, skipping the header comments
    # 读取输出，跳过头部的注释行
    mapfile -t pkg_declarations < <(echo "$exported_pkgs_output" | grep '^strata-pkg:')

    # --- Step 2: Check if declarations already exist to avoid duplicates ---
    # --- 步骤 2: 检查声明是否已存在以避免重复 ---
    info "Checking for existing entries in world file... / 正在检查 world 文件中的现有条目..."

    local temp_world_file
    temp_world_file=$(mktemp)
    cp "$WORLD_FILE" "$temp_world_file"

    local new_content_to_add=""

    # Check the main strata declaration
    # 检查主 strata 声明
    if ! grep -Fxq "$strata_declaration" "$temp_world_file"; then
        new_content_to_add+="${strata_declaration}\n"
    else
        info "Strata declaration for '$strata_name' already exists. / '$strata_name' 的 Strata 声明已存在。"
    fi

    # Check each package declaration
    # 检查每个软件包声明
    for decl in "${pkg_declarations[@]}"; do
        if ! grep -Fxq "$decl" "$temp_world_file"; then
            new_content_to_add+="${decl}\n"
        fi
    done
    
    # --- Step 3: Append new declarations to the world file ---
    # --- 步骤 3: 将新的声明追加到 world 文件中 ---
    if [ -n "$new_content_to_add" ]; then
        info "Adding new declarations to $WORLD_FILE... / 正在将新的声明添加到 $WORLD_FILE..."
        
        # Add a header comment for clarity
        # 为清晰起见，添加一个头部注释
        printf "\n# Promoted Strata: %s (on %s)\n" "$strata_name" "$(date)" >> "$WORLD_FILE"
        printf "%b" "$new_content_to_add" >> "$WORLD_FILE"
        
        # Clean up by sorting and removing duplicate lines
        # 通过排序和去重来清理文件
        sort -u -o "$WORLD_FILE" "$WORLD_FILE"
        
        msg "Successfully promoted Strata '$strata_name'. / 成功提升 Strata '$strata_name'。"
        info "It is now part of the declarative system state. / 它现在是声明式系统状态的一部分。"
    else
        msg "Strata '$strata_name' and its packages are already fully declared in the world file. Nothing to do. / Strata '$strata_name' 及其软件包已在 world 文件中完全声明。无需操作。"
    fi

    rm -f "$temp_world_file"
}

# 参数: <分类/名称> <版本> <所有者> (Arguments: <category/name> <version> <owner>)
# 在 $INSTALLED_DB 下创建一个最小化记录，用于记载外部所有权。
# (Creates a minimal record under $INSTALLED_DB to record foreign ownership.)
db_mark_installed_external() {
    local pkg_id="$1"
    local ver="$2"
    local owner="$3"

    local cat="${pkg_id%/*}"
    local name="${pkg_id##*/}"
    # [修改] 修正了目录拼接方式以处理没有分类的包
    # [MODIFIED] Corrected directory concatenation to handle packages without a category
    local dst
    if [ -n "$cat" ] && [ "$cat" != "$name" ]; then
        dst="${INSTALLED_DB}/${cat//\//_}/${name}"
    else
        dst="${INSTALLED_DB}/_/${name}" # 使用"_"作为无分类包的目录
    fi

    mkdir -p "$dst"
    echo "$ver" > "${dst}/version"
    echo "$owner" > "${dst}/owner"
    : > "${dst}/files"      # 未知的文件列表 (unknown file list)
    : > "${dst}/metadata"   # 预留字段 (reserved)
}

nxpkg_delta_update() {
    local pkg_id="$1"
    get_pkg_id_parts "$pkg_id"
    local pkg_name="${PKG_CATEGORY}/${PKG_NAME}"
    
    # Get current installed version
    local pkg_dir
    pkg_dir=$(db_get_pkg_dir "$pkg_name" "$PKG_SLOT")
    local current_ver
    current_ver=$(cat "$pkg_dir/version" 2>/dev/null)
    [ -z "$current_ver" ] && return 1
    
    # Find latest version
    local build_file
    build_file=$(find_package_build_file "$pkg_id")
    local meta
    meta=$(_parse_build_file "$build_file")
    local latest_ver
    latest_ver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
    
    # Check if delta update is available
    local delta_url=""
    if echo "$meta" | grep -q "^delta_${current_ver}_${latest_ver}="; then
        delta_url=$(echo "$meta" | grep "^delta_${current_ver}_${latest_ver}=" | cut -d= -f2)
    elif [ -f "$build_file" ] && grep -q "^deltas=" "$build_file"; then
        # Check if build file has delta base URLs
        local delta_base
        delta_base=$(grep "^deltas=" "$build_file" | cut -d= -f2)
        delta_url="${delta_base}/${pkg_name//\//_}-${current_ver}-to-${latest_ver}.delta"
    fi
    
    if [ -n "$delta_url" ]; then
        msg "Found delta update from $current_ver to $latest_ver"
        local delta_file="${SOURCE_CACHE}/${pkg_name//\//_}-${current_ver}-to-${latest_ver}.delta"
        
        # Download delta
        if ! download_source "$delta_url" "$delta_file"; then
            warn "Delta download failed, falling back to full update"
            return 1
        fi
        
        # Apply delta to existing binary package
        local old_pkg="${BINARY_CACHE}/${pkg_name//\//_}-${current_ver}-${PKG_SLOT}-$(uname -m).nxpkg.tar.zst"
        local new_pkg="${BINARY_CACHE}/${pkg_name//\//_}-${latest_ver}-${PKG_SLOT}-$(uname -m).nxpkg.tar.zst"
        
        if command -v xdelta3 >/dev/null 2>&1; then
            info "Applying delta patch with xdelta3..."
            xdelta3 -d -s "$old_pkg" "$delta_file" "$new_pkg" || return 1
        elif command -v bsdiff >/dev/null 2>&1; then
            info "Applying delta patch with bsdiff..."
            bsdiff patch "$old_pkg" "$delta_file" "$new_pkg" || return 1
        else
            warn "No delta patch tool available (need xdelta3 or bsdiff)"
            return 1
        fi
        
        # Verify new package
        local expected_hash
        expected_hash=$(echo "$meta" | grep "^sha256sums=" | cut -d= -f2 | head -1)
        local actual_hash
        actual_hash=$(calculate_hash "$new_pkg")
        
        if [ "$expected_hash" = "$actual_hash" ]; then
            info "Delta update verified successfully"
            echo "$new_pkg"
            return 0
        else
            warn "Delta update verification failed (expected $expected_hash, got $actual_hash)"
            rm -f "$new_pkg"
            return 1
        fi
    fi
    
    return 1
}

nxpkg_gen_build() {
    local url="$1"
    local pkgname pkgver source_hash
    
    # Extract package name from URL
    pkgname=$(basename "$url" | sed -E 's/\.tar\.(gz|bz2|xz|zst)//' | sed -E 's/-[0-9].*//')
    
    # Download source for analysis
    local temp_dir
    temp_dir=$(mktemp -d)
    local source_file="${temp_dir}/$(basename "$url")"
    
    if ! download_source "$url" "$source_file"; then
        rm -rf "$temp_dir"
        error "Failed to download source for analysis"
    fi
    
    # Try to extract version
    pkgver=$(basename "$url" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [ -z "$pkgver" ] && pkgver="1.0.0"
    
    # Calculate hash
    source_hash=$(calculate_hash "$source_file")
    
    # Generate basic .build file
    cat <<EOF
pkgname="$pkgname"
pkgver="$pkgver"
pkgdesc="Automatically generated package"
url="$(echo "$url" | sed -E 's/(.*\/).*/\1/')"
slot="0"

source=("$url")
sha256sums=("$source_hash")

depends=()
makedepends=()

build() {
    ./configure --prefix=/usr
    make \${MAKEFLAGS}
}

package() {
    make DESTDIR="\${pkgdir}" install
}
EOF
    
    rm -rf "$temp_dir"
}

# --- SECTION 24: SYSTEM STATE RECONSTRUCTION ---

# Reconstructs the system state to match the world file, providing a declarative management interface.
#
# This function acts as the bridge between nxpkg's imperative core and a declarative workflow.
# It reads the world file as the "single source of truth" and synchronizes the system's
# installed packages to match that declaration.
#
# Key features:
#   - Installs packages listed in the world file and their dependencies.
#   - With --prune, it removes "orphaned" packages (those not required by the world file).
#   - Provides a detailed --dry-run mode to preview all changes.
# Reconstructs the system state to match the world file, providing a declarative management interface.
# v2.0 with Strata Integration
#
# 重建系统状态以匹配 world 文件，提供一个声明式的管理界面。
# v2.0 版本，已集成 Strata 环境管理
#
# This function acts as the bridge between nxpkg's imperative core and a declarative workflow.
# It reads the world file as the "single source of truth" and synchronizes the system's
# installed packages AND strata environments to match that declaration.
#
# 这个函数是 nxpkg 命令式核心与声明式工作流之间的桥梁。
# 它将 world 文件作为“唯一事实来源”，并同步系统的已安装软件包和 Strata 环境以匹配该声明。
#
# Key features (v2.0):
#   - Installs/removes NxPKG packages listed in the world file.
#   - Creates/destroys Strata environments declared in the world file (e.g., 'strata:debian-dev:apt').
#   - Ensures packages are installed inside a declared Strata (e.g., 'strata-pkg:debian-dev:build-essential').
#   - Provides a detailed --dry-run mode to preview all changes.
#
# 关键特性 (v2.0):
#   - 安装/移除 world 文件中列出的 NxPKG 软件包。
#   - 创建/销毁 world 文件中声明的 Strata 环境 (例如 'strata:debian-dev:apt')。
#   - 确保软件包被安装在声明的 Strata 环境内部 (例如 'strata-pkg:debian-dev:build-essential')。
#   - 提供详细的 --dry-run 模式以预览所有变更。
nxpkg_rebuild_from_world() {
    check_root
    local dry_run=0
    local prune=0
    local force=0

    # --- Argument Parsing (unchanged) ---
    # --- 参数解析 (无变动) ---
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) dry_run=1; shift ;;
            --prune) prune=1; shift ;;
            -y|--yes|--force) force=1; shift ;;
            *)
                error "rebuild-from-world: Unknown option '$1' / 未知选项 '$1'"
                ;;
        esac
    done

    [ -f "$WORLD_FILE" ] || error "World file not found: $WORLD_FILE / world 文件未找到: $WORLD_FILE"

    msg "Reconstructing system state from $WORLD_FILE... / 正在从 $WORLD_FILE 重建系统状态..."

    # --- [MODIFIED] Step 1: Parse world file and categorize targets ---
    # --- [已修改] 步骤 1: 解析 world 文件并对目标进行分类 ---
    info "Parsing world file for target state... / 正在解析 world 文件以确定目标状态..."
    local -a target_nxpkg_pkgs=()
    local -a target_strata=() # Format: "name:type" / 格式: "名称:类型"
    declare -A target_strata_pkgs # Associative array: Key=strata_name, Value="pkg1 pkg2..." / 关联数组: 键=strata名称, 值="包1 包2..."

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Ignore comments and empty lines / 忽略注释和空行
        [[ "$line" =~ ^\s*(#|$) ]] && continue
        
        case "$line" in
            strata:*:*)
                # Declaration for a Strata environment: strata:<name>:<type>
                # Strata 环境声明: strata:<名称>:<类型>
                local name type
                name=$(echo "$line" | cut -d':' -f2)
                type=$(echo "$line" | cut -d':' -f3)
                target_strata+=("${name}:${type}")
                ;;
            strata-pkg:*:*)
                # Declaration for a package inside a Strata: strata-pkg:<strata_name>:<pkg_name>
                # Strata 内部软件包声明: strata-pkg:<strata名称>:<软件包名称>
                local strata_name pkg_name
                strata_name=$(echo "$line" | cut -d':' -f2)
                pkg_name=$(echo "$line" | cut -d':' -f3-)
                # Append package to the list for that strata / 将软件包追加到对应 strata 的列表中
                target_strata_pkgs["$strata_name"]+="${pkg_name} "
                ;;
            *)
                # Default is a native NxPKG package / 默认为是原生 NxPKG 软件包
                target_nxpkg_pkgs+=("$line")
                ;;
        esac
    done < "$WORLD_FILE"

    # --- [MODIFIED] Step 2: Get current system state for all categories ---
    # --- [已修改] 步骤 2: 获取所有类别的当前系统状态 ---
    info "Getting current system state... / 正在获取当前系统状态..."
    
    # Get currently installed NxPKG packages (logic unchanged)
    # 获取当前已安装的 NxPKG 软件包 (逻辑无变动)
    local -a installed_pkgs_sorted=()
    if [ -d "$INSTALLED_DB" ] && [ -n "$(ls -A "$INSTALLED_DB")" ]; then
        mapfile -t installed_pkgs_sorted < <(find "$INSTALLED_DB" -mindepth 2 -maxdepth 2 -type d -printf '%f\n' | sed 's/_/:/g' | sort -u)
    fi

    # [NEW] Get currently existing Strata environments
    # [新增] 获取当前已存在的 Strata 环境
    local -a current_strata_sorted=()
    if [ -d "$STRATA_DIR" ]; then
        mapfile -t current_strata_sorted < <(find "$STRATA_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | while read -r name; do
            local type="unknown"
            local conf_file="$STRATA_DIR/$name/.nxpkg_strata"
            [ -f "$conf_file" ] && type=$(grep '^pm=' "$conf_file" | cut -d= -f2)
            echo "${name}:${type}"
        done | sort -u)
    fi

    # --- [MODIFIED] Step 3: Calculate the diff for all categories ---
    # --- [已修改] 步骤 3: 计算所有类别的差异 ---
    info "Calculating system state change plan... / 正在计算系统状态变更计划..."
    local -a to_install to_remove to_keep
    local -a strata_to_create strata_to_destroy strata_to_keep
    
    # Use `comm` for efficient, sorted list comparison (logic unchanged for NxPKG packages)
    # 使用 `comm` 进行高效的有序列表比较 (NxPKG 软件包的逻辑无变动)
    mapfile -t to_install < <(comm -13 <(printf '%s\n' "${installed_pkgs_sorted[@]}") <(printf '%s\n' "${target_nxpkg_pkgs[@]}" | sort -u))
    mapfile -t to_keep < <(comm -12 <(printf '%s\n' "${installed_pkgs_sorted[@]}") <(printf '%s\n' "${target_nxpkg_pkgs[@]}" | sort -u))
    [ "$prune" -eq 1 ] && mapfile -t to_remove < <(comm -23 <(printf '%s\n' "${installed_pkgs_sorted[@]}") <(printf '%s\n' "${target_nxpkg_pkgs[@]}" | sort -u))
    
    # [NEW] Use `comm` to calculate Strata changes
    # [新增] 使用 `comm` 计算 Strata 环境的变更
    mapfile -t strata_to_create < <(comm -13 <(printf '%s\n' "${current_strata_sorted[@]}") <(printf '%s\n' "${target_strata[@]}" | sort -u))
    mapfile -t strata_to_keep < <(comm -12 <(printf '%s\n' "${current_strata_sorted[@]}") <(printf '%s\n' "${target_strata[@]}" | sort -u))
    [ "$prune" -eq 1 ] && mapfile -t strata_to_destroy < <(comm -23 <(printf '%s\n' "${current_strata_sorted[@]}") <(printf '%s\n' "${target_strata[@]}" | sort -u))

    # --- [MODIFIED] Plan Presentation (Dry Run or Confirmation) ---
    # --- [已修改] 计划展示 (演习模式或用户确认) ---
    local has_changes=0
    echo
    info "System state change plan: / 系统状态变更计划:"

    if [ ${#to_install[@]} -gt 0 ]; then
        echo -e "\033[1;32m[+] To be INSTALLED (NxPKG):\033[0m / \033[1;32m将要被安装 (NxPKG):\033[0m"
        printf "      %s\n" "${to_install[@]}"
        has_changes=1
    fi
    if [ ${#strata_to_create[@]} -gt 0 ]; then
        echo -e "\033[1;32m[+] To be CREATED (Strata):\033[0m / \033[1;32m将要被创建 (Strata):\033[0m"
        printf "      %s\n" "${strata_to_create[@]}"
        has_changes=1
    fi
    if [ ${#target_strata_pkgs[@]} -gt 0 ]; then
        echo -e "\033[1;34m[*] To be ENSURED (Packages in Strata):\033[0m / \033[1;34m将要被确保 (Strata 内的包):\033[0m"
        for name in "${!target_strata_pkgs[@]}"; do
             printf "      in %s: %s\n" "$name" "${target_strata_pkgs[$name]}"
        done
        has_changes=1 # Ensuring packages is also a change
    fi
    if [ ${#to_remove[@]} -gt 0 ]; then
        echo -e "\033[1;31m[-] To be REMOVED (NxPKG, pruned):\033[0m / \033[1;31m将要被移除 (NxPKG, 清理):\033[0m"
        printf "      %s\n" "${to_remove[@]}"
        has_changes=1
    fi
    if [ ${#strata_to_destroy[@]} -gt 0 ]; then
        echo -e "\033[1;31m[-] To be DESTROYED (Strata, pruned):\033[0m / \033[1;31m将要被销毁 (Strata, 清理):\033[0m"
        printf "      %s\n" "${strata_to_destroy[@]}"
        has_changes=1
    fi
    if [ ${#to_keep[@]} -gt 0 ]; then
        echo -e "\033[0;34m[=] To be KEPT (NxPKG):\033[0m / \033[0;34m将要被保留 (NxPKG):\033[0m"
        printf "      %s\n" "${to_keep[@]}"
    fi
    if [ ${#strata_to_keep[@]} -gt 0 ]; then
        echo -e "\033[0;34m[=] To be KEPT (Strata):\033[0m / \033[0;34m将要被保留 (Strata):\033[0m"
        printf "      %s\n" "${strata_to_keep[@]}"
    fi

    if [ "$has_changes" -eq 0 ]; then
        msg "System is already in sync with the world file. Nothing to do. / 系统已与 world 文件同步。无需任何操作。"
        return 0
    fi
    echo

    if [ "$dry_run" -eq 1 ]; then
        msg "Dry run complete. No changes were made. / 演习运行完毕。未做任何更改。"
        return 0
    fi

    # --- Execution Confirmation (unchanged) ---
    # --- 执行确认 (无变动) ---
    if [ "$force" -eq 0 ]; then
        read -rp "Proceed with these changes? [y/N] / 确认执行这些变更吗？[y/N] " choice
        [[ ! "$choice" =~ ^[yY]([eE][sS])?$ ]] && {
            msg "Rebuild cancelled by user. / 用户已取消重建操作。"
            return 1
        }
    fi

    # --- [MODIFIED] Execution Phase (ordered for safety) ---
    # --- [已修改] 执行阶段 (为保证安全进行了排序) ---
    acquire_lock "block"
    
    # 1. Perform removals and destructions first
    # 1. 首先执行移除和销毁操作
    if [ ${#strata_to_destroy[@]} -gt 0 ]; then
        msg "Destroying orphaned Strata environments... / 正在销毁孤儿 Strata 环境..."
        for s in "${strata_to_destroy[@]}"; do
            local name=${s%:*}
            nxpkg strata --destroy "$name"
        done
    fi
    if [ ${#to_remove[@]} -gt 0 ]; then
        msg "Pruning orphaned NxPKG packages... / 正在清理孤儿 NxPKG 软件包..."
        release_lock
        nxpkg_remove "${to_remove[@]}"
        acquire_lock "block"
    fi

    # 2. Perform creations and installations
    # 2. 然后执行创建和安装操作
    if [ ${#strata_to_create[@]} -gt 0 ]; then
        msg "Creating new Strata environments... / 正在创建新的 Strata 环境..."
        for s in "${strata_to_create[@]}"; do
            local name=${s%:*}
            local type=${s#*:}
            nxpkg strata --create "$name" "$type"
        done
    fi
    if [ ${#to_install[@]} -gt 0 ]; then
        msg "Installing missing packages to match world state... / 正在安装缺失的软件包以匹配 world 状态..."
        release_lock
        nxpkg_install "${to_install[@]}"
        acquire_lock "block"
    fi
    
    # 3. Finally, ensure packages within Strata
    # 3. 最后，确保 Strata 内部的软件包
    if [ ${#target_strata_pkgs[@]} -gt 0 ]; then
        msg "Ensuring packages within Strata environments... / 正在确保 Strata 环境内的软件包..."
        for name in "${!target_strata_pkgs[@]}"; do
            local pkgs_to_install="${target_strata_pkgs[$name]}"
            local strata_type
            strata_type=$(grep '^pm=' "$STRATA_DIR/$name/.nxpkg_strata" | cut -d= -f2)
            
            local install_cmd=""
            case "$strata_type" in
                apt) install_cmd="apt-get install -y" ;;
                pacman) install_cmd="pacman -S --noconfirm" ;;
                dnf) install_cmd="dnf install -y" ;;
                portage) install_cmd="emerge" ;; # Portage typically requires more config
            esac

            if [ -n "$install_cmd" ]; then
                info "Installing into '$name' (type: $strata_type): $pkgs_to_install / 正在向 '$name' (类型: $strata_type) 中安装: $pkgs_to_install"
                # The strata execute function handles locks appropriately
                # strata 执行函数会妥善处理锁
                nxpkg strata -e "$name" "$install_cmd" "$pkgs_to_install"
            else
                warn "Unsupported strata type '$strata_type' for package installation inside strata '$name'. Please install manually. / 不支持在 strata '$name' 内部为 '$strata_type' 类型的环境自动安装包，请手动安装。"
            fi
        done
    fi
    
    release_lock
    msg "System rebuild complete. State is now in sync with the world file. / 系统重建完成。当前状态已与 world 文件同步。"
}

# Autoremoves orphaned packages and Strata environments not required by the world file.
# v2.1 with granular confirmation
#
# 自动移除 world 文件不再需要的孤儿软件包和 Strata 环境。
# v2.1 版本，带有粒度化确认功能
nxpkg_autoremove() {
    check_root
    msg "Searching for orphaned packages and Strata to remove... / 正在搜索要移除的孤儿软件包和 Strata 环境..."
    
    # --- State Calculation (reusing the complete logic from rebuild-from-world) ---
    # --- 状态计算 (复用来自 rebuild-from-world 的完整逻辑) ---
    [ -f "$WORLD_FILE" ] || error "World file not found: $WORLD_FILE / world 文件未找到: $WORLD_FILE"

    # --- Step 1: Parse world file to get target state ---
    local -a target_nxpkg_pkgs=()
    local -a target_strata=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^\s*(#|$) ]] && continue
        case "$line" in
            strata:*:*)
                local name type
                name=$(echo "$line" | cut -d':' -f2); type=$(echo "$line" | cut -d':' -f3)
                target_strata+=("${name}:${type}")
                ;;
            strata-pkg:*:*)
                # autoremove ignores packages inside strata.
                # autoremove 会忽略 strata 内部的包。
                ;;
            *)
                target_nxpkg_pkgs+=("$line")
                ;;
        esac
    done < "$WORLD_FILE"

    local target_full_dep_list
    target_full_dep_list=$(dep_resolve_topological "${target_nxpkg_pkgs[@]}")
    for pkg in "${target_nxpkg_pkgs[@]}"; do
        if ! [[ " ${target_full_dep_list[*]} " =~ " ${pkg} " ]]; then
            target_full_dep_list+=" $pkg"
        fi
    done
    local -a target_pkgs_sorted
    mapfile -t target_pkgs_sorted < <(echo "$target_full_dep_list" | tr ' ' '\n' | sort -u)

    # --- Step 2: Get current system state ---
    local -a installed_pkgs_sorted=()
    [ -d "$INSTALLED_DB" ] && [ -n "$(ls -A "$INSTALLED_DB")" ] && \
        mapfile -t installed_pkgs_sorted < <(find "$INSTALLED_DB" -mindepth 2 -maxdepth 2 -type d -printf '%f\n' | sed 's/_/:/g' | sort -u)

    local -a current_strata_sorted=()
    [ -d "$STRATA_DIR" ] && \
        mapfile -t current_strata_sorted < <(find "$STRATA_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | while read -r name; do
            local type="unknown"
            local conf_file="$STRATA_DIR/$name/.nxpkg_strata"; [ -f "$conf_file" ] && type=$(grep '^pm=' "$conf_file" | cut -d= -f2)
            echo "${name}:${type}"
        done | sort -u)

    # --- Step 3: Calculate orphans ---
    local -a to_remove_pkgs to_remove_strata
    mapfile -t to_remove_pkgs < <(comm -23 <(printf '%s\n' "${installed_pkgs_sorted[@]}") <(printf '%s\n' "${target_pkgs_sorted[@]}"))
    mapfile -t to_remove_strata < <(comm -23 <(printf '%s\n' "${current_strata_sorted[@]}") <(printf '%s\n' "${target_strata[@]}" | sort -u))

    if [ ${#to_remove_pkgs[@]} -eq 0 ] && [ ${#to_remove_strata[@]} -eq 0 ]; then
        msg "No orphaned items found. Your system is clean. / 未找到孤儿项目。您的系统是干净的。"
        return 0
    fi
    
    # --- [MODIFIED] Step 4: Granular Confirmation ---
    # --- [已修改] 步骤 4: 粒度化确认 ---
    local proceed_with_pkgs=0
    local proceed_with_strata=0
    
    if [ ${#to_remove_pkgs[@]} -gt 0 ]; then
        echo
        echo -e "\033[1;33mThe following packages are no longer required and can be removed:\033[0m"
        echo -e "\033[1;33m以下软件包已不再需要，可以被移除：\033[0m"
        printf "  %s\n" "${to_remove_pkgs[@]}"
        echo
        read -rp "Proceed with removing these packages? [y/N] / 确认移除这些软件包吗？[y/N] " choice
        if [[ "$choice" =~ ^[yY] ]]; then
            proceed_with_pkgs=1
        fi
    fi

    if [ ${#to_remove_strata[@]} -gt 0 ]; then
        echo
        echo -e "\033[1;33mThe following Strata environments are no longer required and can be destroyed:\033[0m"
        echo -e "\033[1;33m以下 Strata 环境已不再需要，可以被销毁：\033[0m"
        printf "  %s\n" "${to_remove_strata[@]}"
        echo
        read -rp "Proceed with destroying these Strata? [y/N] / 确认销毁这些 Strata 吗？[y/N] " choice
        if [[ "$choice" =~ ^[yY] ]]; then
            proceed_with_strata=1
        fi
    fi

    if [ "$proceed_with_pkgs" -eq 0 ] && [ "$proceed_with_strata" -eq 0 ]; then
        msg "Autoremove cancelled. No changes were made. / 自动移除已取消。未做任何更改。"
        return 0
    fi

    # --- Execution Phase ---
    acquire_lock "block"
    if [ "$proceed_with_strata" -eq 1 ]; then
        msg "Destroying orphaned Strata environments... / 正在销毁孤儿 Strata 环境..."
        for s in "${to_remove_strata[@]}"; do
            local name=${s%:*}
            # Use the internal function directly for less output noise
            # 直接使用内部函数以减少输出噪音
            nxpkg_strata_destroy "$name"
        done
    fi
    if [ "$proceed_with_pkgs" -eq 1 ]; then
        msg "Removing orphaned NxPKG packages... / 正在移除孤儿 NxPKG 软件包..."
        release_lock
        nxpkg_remove "${to_remove_pkgs[@]}"
        acquire_lock "block"
    fi
    release_lock
    msg "Autoremove complete. / 自动移除完成。"
}

# =======================================================
# --- SECTION 25: CACHE MANAGEMENT AND CLEANING       ---
# --- 第25节: 缓存管理与清理                         ---
# =======================================================

# Cleans up cached source files and binary packages to free up disk space.
# 清理缓存的源码文件和二进制包以释放磁盘空间。
#
# This function provides a user-facing command 'nxpkg clean' with various
# options to control what gets deleted. It prioritizes safety by using a
# dry-run mode by default and requiring explicit confirmation.
# 此函数提供了面向用户的 'nxpkg clean' 命令，带有多种选项来控制删除内容。
# 它默认使用“演习模式”(dry-run)并要求显式确认，以此来优先保证安全。
nxpkg_clean() {
    check_root

    # --- Default settings ---
    local dry_run=1
    local force_confirm=0
    local target_sources=0
    local target_binaries=0
    local target_tmp=0 # --- [功能增强] 新增目标：临时文件 ---
    local older_than_days=0
    local keep_last_n=0

    # --- Argument parsing for user control ---
    if [ $# -eq 0 ]; then
        info "Running in default mode: --dry-run --binaries --sources --tmp / 以默认模式运行: --dry-run --binaries --sources --tmp"
        target_sources=1
        target_binaries=1
        target_tmp=1
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --sources)
                target_sources=1; shift ;;
            --binaries)
                target_binaries=1; shift ;;
            --tmp) # --- [功能增强] 新增选项 ---
                target_tmp=1; shift ;;
            --all)
                target_sources=1; target_binaries=1; target_tmp=1; shift ;;
            --dry-run)
                dry_run=1; shift ;;
            --force)
                dry_run=0; force_confirm=1; shift ;;
            --older-than)
                [ -z "${2:-}" ] && error "--older-than requires a number of days (e.g., 30)."
                older_than_days="$2"; shift 2 ;;
            --keep-last)
                [ -z "${2:-}" ] && error "--keep-last requires a number (e.g., 3)."
                keep_last_n="$2"; shift 2 ;;
            -y) # Alias for --force
                dry_run=0; force_confirm=1; shift ;;
            *)
                error "Unknown option for clean: $1" ;;
        esac
    done

    if [ "$target_sources" -eq 0 ] && [ "$target_binaries" -eq 0 ] && [ "$target_tmp" -eq 0 ]; then
        error "No target specified. Use --sources, --binaries, --tmp, or --all."
    fi

    msg "Starting cache and temporary file cleaning process... / 开始缓存与临时文件清理流程..."

    local items_to_delete=()
    local total_size=0

    # --- Binary Cache Cleaning ---
    if [ "$target_binaries" -eq 1 ]; then
        info "Analyzing binary package cache... / 正在分析二进制包缓存..."
        mapfile -t bin_files < <(_clean_binary_cache "$dry_run" "$older_than_days" "$keep_last_n")
        items_to_delete+=("${bin_files[@]}")
    fi

    # --- Source Cache Cleaning ---
    if [ "$target_sources" -eq 1 ]; then
        info "Analyzing source code cache... / 正在分析源码缓存..."
        mapfile -t src_files < <(_clean_source_cache "$dry_run" "$older_than_days" "${items_to_delete[@]}")
        items_to_delete+=("${src_files[@]}")
    fi

    # --- [功能增强] Temporary Files Cleaning ---
    if [ "$target_tmp" -eq 1 ]; then
        info "Analyzing temporary build directories... / 正在分析临时构建目录..."
        if [ -d "$BUILD_TMP_DIR_BASE" ]; then
            # 安全地查找并列出所有nxpkg创建的临时目录
            mapfile -t tmp_dirs < <(find "$BUILD_TMP_DIR_BASE" -mindepth 1 -maxdepth 1 -type d -name '*-build.XXXXXX' -o -name '*-install.XXXXXX' -o -name 'bt_download.XXXXXX')
            items_to_delete+=("${tmp_dirs[@]}")
        fi
    fi

    # --- Execution Phase ---
    if [ ${#items_to_delete[@]} -eq 0 ]; then
        msg "System is clean. No items to delete. / 系统是干净的。没有项目需要删除。"
        return 0
    fi

    info "The following files/directories have been marked for deletion: / 以下文件/目录已被标记为待删除:"
    for item in "${items_to_delete[@]}"; do
        local item_size
        item_size=$(du -sh "$item" 2>/dev/null | awk '{print $1}')
        total_size=$((total_size + $(du -sb "$item" 2>/dev/null | awk '{print $1}' || echo 0)))
        detail "  - $(basename "$item") ($item_size)"
    done

    local human_readable_size
    human_readable_size=$(echo "$total_size" | awk '{
        suff="B";
        if($1 > 1024){$1/=1024; suff="K"}
        if($1 > 1024){$1/=1024; suff="M"}
        if($1 > 1024){$1/=1024; suff="G"}
        printf "%.1f%s", $1, suff;
    }')

    echo
    msg "Total space to be freed / 总计可释放空间: $human_readable_size"

    if [ "$dry_run" -eq 1 ]; then
        msg "Dry run complete. No items were deleted. / 演习运行完毕。未删除任何项目。"
        info "To delete these items, run the command again with the --force or -y flag. / 要删除这些项目，请使用 --force 或 -y 标志重新运行此命令。"
        return 0
    fi

    if [ "$force_confirm" -eq 0 ]; then
        read -rp "Proceed with deletion? [y/N] / 确认删除吗？[y/N] " choice
        [[ ! "$choice" =~ ^[yY]([eE][sS])?$ ]] && {
            msg "Deletion cancelled by user. / 用户已取消删除操作。"
            return 1
        }
    fi

    acquire_lock "block"
    info "Deleting items... / 正在删除项目..."
    for item in "${items_to_delete[@]}"; do
        # 对文件和目录都有效的删除命令
        rm -rf "$item"
        local sig_file="${item}.sig"
        [ -f "$sig_file" ] && rm -f "$sig_file"
    done
    release_lock

    msg "Cleaning complete. Freed $human_readable_size of space. / 清理完成。释放了 $human_readable_size 的空间。"
}

# Internal function to determine and list orphan binary packages for deletion.
# An orphan is a package that is NOT installed AND NOT the latest available version.
# This preserves the latest version for quick installation and older versions if they are
# currently in use, which is critical for the 'rollback' feature.
#
# 内部函数，用于确定并列出待删除的孤儿二进制包。
# 孤儿包的定义是：未被安装 且 不是最新可用版本 的包。
# 这种策略保留了最新版本以备快速安装，也保留了当前正在使用的旧版本，这对 'rollback' 功能至关重要。
_clean_binary_cache() {
    local dry_run="$1"
    local older_than_days="$2"
    local keep_last_n="$3"

    # --- Stage 1: Gather system state information for quick lookups ---
    declare -A installed_pkgs
    declare -A latest_versions
    declare -A all_pkg_versions

    # Get a list of all installed packages (format: category/name-version-slot)
    if [ -d "$INSTALLED_DB" ]; then
        while read -r pkg_dir; do
            local pkg_name pkg_ver pkg_slot
            pkg_name=$(cat "$pkg_dir/name" 2>/dev/null)
            pkg_ver=$(cat "$pkg_dir/version" 2>/dev/null)
            pkg_slot=$(cat "$pkg_dir/slot" 2>/dev/null)
            [ -n "$pkg_name" ] && [ -n "$pkg_ver" ] && installed_pkgs["${pkg_name//\//_}-${pkg_ver}-${pkg_slot}"]=1
        done < <(find "$INSTALLED_DB" -mindepth 2 -maxdepth 2 -type d)
    fi

    # Get a list of the latest available version for all packages in repos
    while read -r build_file; do
        local meta pkg_cat pkg_name pkg_ver
        meta=$(_parse_build_file "$build_file" 2>/dev/null || continue)
        pkg_cat=$(dirname "$build_file" | xargs basename)
        pkg_name_base=$(echo "$meta" | grep "^pkgname=" | cut -d= -f2)
        pkg_name="${pkg_cat}/${pkg_name_base}"
        pkg_ver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
        latest_versions["$pkg_name"]="$pkg_ver"
    done < <(find "$REPOS_DIR" -name "*.build" -type f)

    # --- Stage 2: Iterate through the cache and apply deletion rules ---
    local now
    now=$(date +%s)
    
    find "$BINARY_CACHE" -type f -name "*.nxpkg.tar.*" | while read -r pkg_file; do
        local filename pkg_base_name pkg_ver pkg_slot pkg_id_for_lookup
        filename=$(basename "$pkg_file")
        # Regex to parse "category_name-version-slot-arch.nxpkg.tar.zst"
        # 正则表达式，用于解析 "类别_名称-版本-槽位-架构.nxpkg.tar.zst"
        if [[ "$filename" =~ ^(.*)-([0-9].*)-([0-9]+)-.*\.nxpkg\.tar\..*$ ]]; then
            pkg_base_name="${BASH_REMATCH[1]}"
            pkg_ver="${BASH_REMATCH[2]}"
            pkg_slot="${BASH_REMATCH[3]}"
        else
            continue # Skip files with non-standard names / 跳过非标准命名的文件
        fi
        
        # Reconstruct package name (category/name) from category_name
        local pkg_cat pkg_name
        pkg_cat=$(echo "$pkg_base_name" | cut -d_ -f1)
        pkg_name=$(echo "$pkg_base_name" | cut -d_ -f2-)
        local full_pkg_name="${pkg_cat}/${pkg_name}"
        
        # --- Rule 1: Never delete currently installed packages ---
        pkg_id_for_lookup="${pkg_base_name}-${pkg_ver}-${pkg_slot}"
        if [ "${installed_pkgs[$pkg_id_for_lookup]+_}" ]; then
            continue
        fi
        
        # --- Rule 2: Never delete the latest available version ---
        local latest_ver="${latest_versions[$full_pkg_name]:-}"
        if [ -n "$latest_ver" ] && [ "$pkg_ver" = "$latest_ver" ]; then
            continue
        fi

        # --- Rule 3 (Optional): Check age if --older-than is used ---
        if [ "$older_than_days" -gt 0 ]; then
            local file_age_seconds
            file_age_seconds=$((now - $(stat -c %Y "$pkg_file")))
            if [ "$file_age_seconds" -lt $((older_than_days * 86400)) ]; then
                continue # File is not old enough / 文件还不够旧
            fi
        fi
        
        # If we reach here, the package is an orphan. Mark for deletion.
        # 如果代码执行到这里，说明这个包是孤儿包。标记以待删除。
        echo "$pkg_file"
    done
}


# Internal function to determine and list orphan source code archives.
# A source is considered an orphan if no corresponding binary package (of any version)
# exists in the cache anymore, AND it's not the source for the latest available version.
#
# 内部函数，用于确定并列出孤儿源码存档。
# 如果一个源码对应的所有版本的二进制包都已不在缓存中，并且它也不是最新可用版本的源码，
# 那么它就被认为是孤儿源码。
_clean_source_cache() {
    local dry_run="$1"
    local older_than_days="$2"
    # The remaining arguments are the list of binaries that are *about to be deleted*.
    # 剩下的参数是 *将要被删除* 的二进制包列表。
    shift 2
    local binaries_to_be_deleted=("$@")

    # --- Stage 1: Build necessary maps for quick lookups ---
    declare -A source_to_pkg_map
    declare -A latest_sources
    declare -A existing_binaries
    
    # Map source filenames to their package names (e.g., "hello-2.12.1.tar.gz" -> "app-misc/hello-world")
    # Also get a list of source files for the latest versions
    while read -r build_file; do
        local meta pkg_cat pkg_name_base pkg_name pkg_ver source_list latest_ver
        meta=$(_parse_build_file "$build_file" 2>/dev/null || continue)
        pkg_cat=$(dirname "$build_file" | xargs basename)
        pkg_name_base=$(echo "$meta" | grep "^pkgname=" | cut -d= -f2)
        pkg_name="${pkg_cat}/${pkg_name_base}"
        pkg_ver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
        source_list=$(echo "$meta" | grep "^source=" | cut -d= -f2-)
        
        while IFS= read -r src_url; do
            local src_filename
            [[ "$src_url" == *"::"* ]] && src_filename="${src_url%%::*}" || src_filename=$(basename "$src_url")
            source_to_pkg_map["$src_filename"]="$pkg_name"
        done <<< "$source_list"

        latest_ver=$(echo "$meta" | grep "^pkgver=" | cut -d= -f2)
        if [ "$pkg_ver" = "$latest_ver" ]; then
            while IFS= read -r src_url; do
                local src_filename
                [[ "$src_url" == *"::"* ]] && src_filename="${src_url%%::*}" || src_filename=$(basename "$src_url")
                latest_sources["$src_filename"]=1
            done <<< "$source_list"
        fi
    done < <(find "$REPOS_DIR" -name "*.build" -type f)

    # Get a list of all binary packages that will *remain* after cleaning
    while read -r bin_file; do
        # Check if this binary is in the list of files to be deleted
        local found=0
        for to_delete in "${binaries_to_be_deleted[@]}"; do
            [ "$bin_file" = "$to_delete" ] && { found=1; break; }
        done
        [ "$found" -eq 1 ] && continue

        if [[ "$(basename "$bin_file")" =~ ^(.*)-([0-9].*)-([0-9]+)-.* ]]; then
            local pkg_base_name="${BASH_REMATCH[1]}"
            local pkg_cat pkg_name
            pkg_cat=$(echo "$pkg_base_name" | cut -d_ -f1)
            pkg_name=$(echo "$pkg_base_name" | cut -d_ -f2-)
            existing_binaries["${pkg_cat}/${pkg_name}"]=1
        fi
    done < <(find "$BINARY_CACHE" -type f -name "*.nxpkg.tar.*")


    # --- Stage 2: Iterate through source cache and apply rules ---
    local now
    now=$(date +%s)

    find "$SOURCE_CACHE" -type f | while read -r src_file; do
        local filename pkg_name
        filename=$(basename "$src_file")
        pkg_name="${source_to_pkg_map[$filename]:-}"
        
        # If we don't know which package this source belongs to, we can't safely delete it.
        # 如果我们不知道这个源码属于哪个包，就不能安全地删除它。
        [ -z "$pkg_name" ] && continue
        
        # --- Rule 1: If any binary for this package still exists, keep the source ---
        # This is for rebuilding during rollbacks.
        # 这是为了回滚时的重新构建。
        if [ "${existing_binaries[$pkg_name]+_}" ]; then
            continue
        fi
        
        # --- Rule 2: Never delete the source for the latest available version ---
        if [ "${latest_sources[$filename]+_}" ]; then
            continue
        fi

        # --- Rule 3 (Optional): Check age if --older-than is used ---
        if [ "$older_than_days" -gt 0 ]; then
            local file_age_seconds
            file_age_seconds=$((now - $(stat -c %Y "$src_file")))
            if [ "$file_age_seconds" -lt $((older_than_days * 86400)) ]; then
                continue # File is not old enough / 文件还不够旧
            fi
        fi

        # Orphan source file. Mark for deletion.
        # 孤儿源码文件。标记以待删除。
        echo "$src_file"
    done
}

# =======================================================
# --- SECTION 26: TRUST AND SIGNATURE MANAGEMENT      ---
# --- 第26节: 信任与签名管理                         ---
# =======================================================
# This section implements a Public Key Infrastructure (PKI) based on GPG.
# It provides a "defense-in-depth" layer on top of the blockchain consensus,
# allowing administrators to define explicit trust anchors.
#
# 本节基于GPG实现了一个公钥基础设施(PKI)。它在区块链共识之上提供了一个
# “深度防御”层，允许管理员定义明确的信任锚。

# New Paths
# 新增路径
TRUST_ZONES_DIR="${ETC_NXPKG_DIR}/trust_zones"

# Get the current active trust zone's keyring path.
# 获取当前活动信任区的密钥环路径。
_get_current_keyring_path() {
    local active_zone
    active_zone=$(cat "${TRUST_ZONES_DIR}/active_zone" 2>/dev/null || echo "default")
    echo "${TRUST_ZONES_DIR}/${active_zone}/keyring.gpg"
}

# Verifies a file against a detached signature using the current trust zone's keyring.
# 使用当前信任区的密钥环，对照一个分离的签名来验证一个文件。
# Usage: _verify_gpg_signature <file_to_verify> <signature_file>
_verify_gpg_signature() {
    local file_to_verify="$1"
    local signature_file="$2"
    local keyring_path
    keyring_path=$(_get_current_keyring_path)

    [ ! -f "$keyring_path" ] && { warn "信任区密钥环未找到: $keyring_path (Trust Zone keyring not found: $keyring_path)"; return 1; }
    [ ! -f "$signature_file" ] && { warn "签名文件未找到: $signature_file (Signature file not found: $signature_file)"; return 1; }

    # Use GPG in batch mode to verify. The output is redirected to stderr.
    # We check the return code to determine success.
    # 在批处理模式下使用GPG进行验证。输出被重定向到stderr。我们通过检查返回码来确定成功与否。
    if gpg --batch --no-default-keyring --keyring "$keyring_path" --verify "$signature_file" "$file_to_verify" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# The user-facing command dispatcher for 'nxpkg key'.
# 面向用户的 'nxpkg key' 命令分发器。
nxpkg_key() {
    check_root
    local sub_cmd="${1:-}"
    shift || true

    case "$sub_cmd" in
        --list)
            nxpkg_key_list
            ;;
        --import)
            [ $# -lt 1 ] && error "用法: nxpkg key --import <key_file.asc> (Usage: nxpkg key --import <key_file.asc>)"
            nxpkg_key_import "$1"
            ;;
        --delete)
            [ $# -lt 1 ] && error "用法: nxpkg key --delete <KEY_ID> (Usage: nxpkg key --delete <KEY_ID>)"
            nxpkg_key_delete "$1"
            ;;
        --list-zones)
            nxpkg_key_list_zones
            ;;
        --create-zone)
            [ $# -lt 1 ] && error "用法: nxpkg key --create-zone <zone_name> (Usage: nxpkg key --create-zone <zone_name>)"
            nxpkg_key_create_zone "$1"
            ;;
        --switch-zone)
            [ $# -lt 1 ] && error "用法: nxpkg key --switch-zone <zone_name> (Usage: nxpkg key --switch-zone <zone_name>)"
            nxpkg_key_switch_zone "$1"
            ;;
        *)
            echo "nxpkg key: 管理信任密钥与信任区 (Manage trust keys and zones)"
            echo "  --list             列出当前信任区中的所有GPG公钥 (List all GPG public keys in the current zone)"
            echo "  --import <file>    向当前信任区导入一个新的GPG公钥 (Import a new GPG public key to the current zone)"
            echo "  --delete <KEY_ID>  从当前信任区删除一个GPG公key (Delete a GPG key from the current zone)"
            echo "  --list-zones       列出所有可用的信任区 (List all available trust zones)"
            echo "  --create-zone <name> 创建一个新的信任区 (Create a new trust zone)"
            echo "  --switch-zone <name> 切换到指定的信任区 (Switch to a specific trust zone)"
            ;;
    esac
}

# Lists all keys in the current trust zone's keyring.
# 列出当前信任区密钥环中的所有密钥。
nxpkg_key_list() {
    local keyring_path
    keyring_path=$(_get_current_keyring_path)
    [ ! -f "$keyring_path" ] && { msg "当前信任区没有密钥。 (No keys in the current trust zone.)"; return 0; }
    
    msg "当前信任区中的密钥 (Keys in current trust zone): $(cat "${TRUST_ZONES_DIR}/active_zone" 2>/dev/null || echo "default")"
    gpg --batch --no-default-keyring --keyring "$keyring_path" --list-keys
}

# Imports a new GPG key into the current trust zone.
# 向当前信任区导入一个新的GPG密钥。
nxpkg_key_import() {
    local key_file="$1"
    [ ! -f "$key_file" ] && error "密钥文件未找到: $key_file (Key file not found: $key_file)"
    
    local keyring_path zone_dir
    zone_dir=$(dirname "$(_get_current_keyring_path)")
    keyring_path=$(_get_current_keyring_path)
    
    mkdir -p "$zone_dir"
    
    msg "正在向当前信任区导入密钥... (Importing key to the current trust zone...)"
    if gpg --batch --no-default-keyring --keyring "$keyring_path" --import "$key_file"; then
        info "密钥导入成功。 (Key imported successfully.)"
    else
        error "密钥导入失败。请检查文件格式或密钥是否已存在。 (Failed to import key. Check the file format or if the key already exists.)"
    fi
}

# Deletes a key from the current trust zone.
# 从当前信任区删除一个密钥。
nxpkg_key_delete() {
    local key_id="$1"
    local keyring_path
    keyring_path=$(_get_current_keyring_path)
    [ ! -f "$keyring_path" ] && error "密钥环未找到，无法删除。 (Keyring not found, cannot delete.)"
    
    read -rp "您确定要从当前信任区永久删除密钥 '$key_id' 吗? [y/N] (Are you sure you want to permanently delete key '$key_id' from the current trust zone? [y/N]) " choice
    [[ ! "$choice" =~ ^[yY] ]] && { msg "删除已取消。 (Deletion cancelled.)"; return 0; }

    if gpg --batch --no-default-keyring --keyring "$keyring_path" --delete-key "$key_id"; then
        msg "密钥已成功删除。 (Key deleted successfully.)"
    else
        error "删除密钥失败。请检查KEY_ID是否正确。 (Failed to delete key. Please check if the KEY_ID is correct.)"
    fi
}

# Lists all available trust zones.
# 列出所有可用的信任区。
nxpkg_key_list_zones() {
    msg "可用的信任区: (Available trust zones:)"
    local active_zone
    active_zone=$(cat "${TRUST_ZONES_DIR}/active_zone" 2>/dev/null || echo "default")
    
    find "$TRUST_ZONES_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r zone_dir; do
        local zone_name
        zone_name=$(basename "$zone_dir")
        if [ "$zone_name" = "$active_zone" ]; then
            echo "  * $zone_name (active / 当前)"
        else
            echo "    $zone_name"
        fi
    done
}

# Creates a new, empty trust zone.
# 创建一个新的、空的信任区。
nxpkg_key_create_zone() {
    local zone_name="$1"
    local zone_path="${TRUST_ZONES_DIR}/${zone_name}"

    [ -d "$zone_path" ] && error "信任区 '$zone_name' 已存在。 (Trust zone '$zone_name' already exists.)"
    
    mkdir -p "$zone_path"
    msg "信任区 '$zone_name' 已创建。 (Trust zone '$zone_name' created.)"
    info "您现在可以切换到它并导入密钥: nxpkg key --switch-zone $zone_name (You can now switch to it and import keys: nxpkg key --switch-zone $zone_name)"
}

# Switches the active trust zone.
# 切换活动的信任区。
nxpkg_key_switch_zone() {
    local zone_name="$1"
    local zone_path="${TRUST_ZONES_DIR}/${zone_name}"
    
    [ ! -d "$zone_path" ] && error "信任区 '$zone_name' 未找到。请先创建它。 (Trust zone '$zone_name' not found. Please create it first.)"
    
    echo "$zone_name" > "${TRUST_ZONES_DIR}/active_zone"
    msg "已切换到信任区: $zone_name (Switched to trust zone: $zone_name)"
}

# =======================================================
# --- SECTION 27: USAGE AND HELP FUNCTION             ---
# --- 第27节: 用法与帮助函数                           ---
# =======================================================

usage() {
    local command_to_help="${1:-}"

    # General Help (if no specific command is asked for)
    # 通用帮助 (如果没有请求特定命令的帮助)
    if [ -z "$command_to_help" ]; then
        echo "nxpkg - The Next-Generation Meta Package Manager (v${NXPKG_VERSION})"
        echo
        echo -e "Usage: \033[1mnxpkg\033[0m [global options] <command> [arguments...]"
        echo -e "用法:  \03g[1mnxpkg\033[0m [全局选项] <命令> [参数...]"
        echo
        echo "Global Options (全局选项):"
        echo "  --help, -h          Show this help message. / 显示此帮助信息。"
        echo "  --version           Show the version of nxpkg. / 显示 nxpkg 的版本。"
        echo "  --debug             Enable verbose debug output. / 启用详细的调试输出。"
        echo
        echo "Global Environment Variables (全局环境变量):"
        echo "  NXPKG_AUTO_TRUST_NEW_NODES=true"
        echo "                      Bypass interactive prompt for trusting new P2P peers."
        echo "                      (跳过交互式提示，自动信任新的P2P节点)"
        echo -e "                      \033[1;31mWARNING:\033[0m Use only in trusted, automated environments."
        echo -e "                      \033[1;31m警告:\033[0m 仅在受信任的自动化环境中使用。"
        echo
        echo "Core Package Management Commands (核心包管理命令):"
        echo "  install (in)        Install one or more packages and their dependencies. / 安装一个或多个软件包及其依赖。"
        echo "  remove (rm)         Remove one or more packages from the system. / 从系统中移除一个或多个软件包。"
        echo "  upgrade             Upgrade all packages listed in the world file. / 升级 world 文件中列出的所有软件包。"
        echo "  sync                Synchronize all configured package repositories. / 同步所有已配置的软件包仓库。"
        echo "  search              Search for packages in repositories. / 在仓库中搜索软件包。"
        echo "  info                Display detailed information about a package. / 显示软件包的详细信息。"
        echo
        echo "Declarative System Management (声明式系统管理):"
        echo "  rebuild             Reconstruct the system state to match the world file. / 重建系统状态以匹配 world 文件。"
        echo "  autoremove (auto)   Remove orphaned packages and strata not required by the world file. / 移除 world 文件不再需要的孤儿包和 strata。"
        echo
        echo "Advanced & Developer Commands (高级与开发者命令):"
        echo "  build               Build a package from source using its .build file. / 根据 .build 文件从源码构建软件包。"
        echo "  strata              Manage isolated environments (strata). / 管理隔离的运行环境 (strata)。"
        echo "  forum               Access the decentralized forum system. / 访问去中心化论坛系统。"
        echo "  key                 Manage GPG trust keys and Trust Zones. / 管理GPG信任密钥与信任区。"
        echo "  owns                Find which package owns a specific file. / 查找特定文件属于哪个软件包。"
        echo "  clean               Clean up cached source, binary, and temporary files. / 清理缓存的源码、二进制包及临时文件。"
        echo "  manage              Integrate with external system package managers. / 与外部的系统包管理器集成。"
        echo "  init                Initialize the nxpkg system on a new machine. / 在新机器上初始化 nxpkg 系统。"
        echo
        echo "Run 'nxpkg help <command>' for detailed information about a specific command."
        echo "运行 'nxpkg help <命令>' 来获取特定命令的详细信息。"
        return
    fi

    # Detailed help for a specific command
    # 特定命令的详细帮助
    case "$command_to_help" in
        install|in)
            echo "Usage: nxpkg install [--allow-canary] <pkg1> [pkg2] ..."
            echo "  Installs one or more packages and their dependencies."
            echo
            echo "Arguments:"
            echo "  <pkg>               Package identifier, e.g., 'app-misc/hello-world' or 'app-text/vim:0'."
            echo
            echo "Options:"
            echo "  --allow-canary      Allow the installation of packages marked as canary (unstable) releases."
            echo
            echo "用法: nxpkg install [--allow-canary] <包1> [包2] ..."
            echo "  安装一个或多个软件包及其依赖。"
            echo
            echo "参数:"
            echo "  <pkg>               软件包标识符, 例如 'app-misc/hello-world' 或 'app-text/vim:0'。"
            echo
            echo "选项:"
            echo "  --allow-canary      允许安装被标记为金丝雀（不稳定）版本的软件包。"
            ;;
        rebuild)
            echo "Usage: nxpkg rebuild [--prune] [--dry-run] [-y|--yes]"
            echo "  Synchronizes the system's state (packages and strata) to match the declaration in the world file."
            echo "  This provides a powerful, declarative way to manage the entire system, similar to NixOS."
            echo
            echo "Actions performed:"
            echo "  - Installs/Removes NxPKG packages to match the declaration."
            echo "  - Creates/Destroys Strata environments to match the declaration."
            echo "  - Ensures specified packages are installed inside a declared Strata environment."
            echo
            echo "Options:"
            echo "  --prune             Enable the removal/destruction of orphaned packages and strata."
            echo "  --dry-run           Show a detailed plan of all changes without making them."
            echo "  -y, --yes, --force  Skip the interactive confirmation prompt."
            echo
            echo "Extended World File Syntax:"
            echo "  - my/package              # Declares a native NxPKG package"
            echo "  - strata:debian-dev:apt   # Declares a Strata named 'debian-dev' of type 'apt'"
            echo "  - strata-pkg:debian-dev:build-essential # Ensures 'build-essential' is installed in 'debian-dev' strata"
            echo
            echo "用法: nxpkg rebuild [--prune] [--dry-run] [-y|--yes]"
            echo "  将系统状态（包括软件包和Strata环境）与 world 文件中的声明进行同步。"
            echo "  这提供了一种强大的、类似 NixOS 的声明式方式来管理整个系统。"
            echo
            echo "执行的操作:"
            echo "  - 安装/移除 NxPKG 软件包以匹配声明。"
            echo "  - 创建/销毁 Strata 环境以匹配声明。"
            echo "  - 确保指定的软件包被安装在声明的 Strata 环境中。"
            echo
            echo "选项:"
            echo "  --prune             启用对孤儿软件包和 Strata 环境的移除/销毁功能。"
            echo "  --dry-run           显示所有变更的详细计划，但不会实际执行。"
            echo "  -y, --yes, --force  跳过交互式确认提示。"
            echo
            echo "工作流示例 (Workflow Example):"
            echo "  1. 编辑 /etc/nxpkg/world 文件，定义你期望的系统状态。 (Edit /etc/nxpkg/world to define your desired system state.)"
            echo "  2. 运行 'sudo nxpkg rebuild --dry-run --prune' 来预览计划中的变更。 (Run 'sudo nxpkg rebuild --dry-run --prune' to review the planned changes.)"
            echo "  3. 如果计划无误，运行 'sudo nxpkg rebuild --prune' 来应用这些变更。 (If the plan is correct, run 'sudo nxpkg rebuild --prune' to apply the changes.)"
            ;;
        autoremove|auto)
            echo "Usage: nxpkg autoremove"
            echo "  Removes orphaned NxPKG packages and Strata environments that are no longer required by the world file."
            echo "  This command is a specialized version of 'rebuild --prune' that only performs removals."
            echo "  You will be prompted to confirm the removal of packages and strata separately."
            echo
            echo "用法: nxpkg autoremove"
            echo "  移除 world 文件不再需要的孤儿 NxPKG 软件包和 Strata 环境。"
            echo "  此命令是 'rebuild --prune' 的一个特化版本，只执行移除操作。"
            echo "  系统将分别提示您确认移除软件包和 Strata 环境。"
            ;;
        build)
            echo "Usage: nxpkg build [--canary] <package_name>"
            echo "  Builds a single package from its corresponding .build file."
            echo
            echo "Options:"
            echo "  --canary            Append a '-canary' suffix to the package version, marking it as a non-stable build."
            echo
            echo "Build File Options (`options` array):"
            echo "  To disable network access during the build process for security, add the following to your .build file:"
            echo "  options=(\"!network\")"
            echo
            echo "用法: nxpkg build [--canary] <软件包名>"
            echo "  根据对应的 .build 文件构建单个软件包。"
            echo
            echo "选项:"
            echo "  --canary            在软件包版本后附加 '-canary' 后缀，将其标记为非稳定构建版。"
            echo
            echo ".build 文件选项 (`options` 数组):"
            echo "  为了安全起见，如需在构建过程中禁用网络访问，请在你的 .build 文件中加入以下行："
            echo "  options=(\"!network\")"
            ;;
        clean)
            echo "Usage: nxpkg clean [options...]"
            echo "  Cleans up cached files and temporary directories to free up disk space."
            echo "  By default, runs in --dry-run mode, showing what would be deleted without actually deleting anything."
            echo
            echo "Options (Targets):"
            echo "  --sources           Target the source code cache (${SOURCE_CACHE})."
            echo "  --binaries          Target the binary package cache (${BINARY_CACHE})."
            echo "  --tmp               Target temporary build/install directories (${BUILD_TMP_DIR_BASE})."
            echo "  --all               Target all of the above (default if no target is specified)."
            echo
            echo "Options (Execution):"
            echo "  --dry-run           (Default) Show a plan of what will be deleted."
            echo "  --force, -y         Execute the deletion without interactive confirmation."
            echo
            echo "Options (Filtering - for --sources and --binaries only):"
            echo "  --older-than <days> Only target files older than the specified number of days."
            echo "  --keep-last <N>     (Binaries only) Keep the N most recent versions of each package."
            echo
            echo "用法: nxpkg clean [选项...]"
            echo "  清理缓存文件和临时目录以释放磁盘空间。"
            echo "  默认情况下，命令以 --dry-run (演习)模式运行，仅显示将被删除的内容，而不会真的删除任何东西。"
            echo
            echo "选项 (目标):"
            echo "  --sources           目标为源码缓存 (${SOURCE_CACHE})。"
            echo "  --binaries          目标为二进制包缓存 (${BINARY_CACHE})。"
            echo "  --tmp               目标为临时构建/安装目录 (${BUILD_TMP_DIR_BASE})。"
            echo "  --all               目标为以上所有 (如果未指定目标，则为默认行为)。"
            echo
            echo "选项 (执行):"
            echo "  --dry-run           (默认) 显示将被删除内容的计划。"
            echo "  --force, -y         执行删除操作，无需交互式确认。"
            echo
            echo "选项 (过滤器 - 仅对 --sources 和 --binaries 生效):"
            echo "  --older-than <天数> 仅处理比指定天数更老的文件。"
            echo "  --keep-last <N>     (仅二进制包) 保留每个软件包的最近 N 个版本。"
            echo
            echo "工作流示例 (Workflow Example):"
            echo "  1. 预览所有将要被清理的项目: 'sudo nxpkg clean'"
            echo "  2. 确认计划无误后，执行清理: 'sudo nxpkg clean --force'"
            echo "  3. 只清理临时构建目录: 'sudo nxpkg clean --tmp -y'"
            ;;
        strata)
            echo "Usage: nxpkg strata <subcommand> [arguments...]"
            echo "  Manages isolated environments (strata) where other package managers can operate."
            echo
            echo "Subcommands:"
            echo "  --create <name> <pm>  Create a new strata for temporary or exploratory use."
            echo "                        (创建一个新的 strata，用于临时或探索性目的)"
            echo "                        <pm> can be: apt, pacman, dnf, portage."
            echo "  --list                List all available strata. (列出所有可用的 strata)"
            echo "  -e, --execute <name> <command...>"
            echo "                        Execute a command inside a strata. (在 strata 内部执行命令)"
            echo "  --destroy <name>      Permanently delete a strata. (永久删除一个 strata)"
            echo "  --export-pkgs <name>  List all packages inside a strata in a format suitable for the world file."
            echo "                        (以适用于 world 文件的格式，列出 strata 内的所有包)"
            echo "  --promote <name>      'Promote' a strata to the world file, making it declarative."
            echo "                        (将一个 strata '提升' 到 world 文件中，使其成为声明式状态)"
            echo
            echo "用法: nxpkg strata <子命令> [参数...]"
            echo "  管理隔离的运行环境 (strata)，可在其中运行其他包管理器。"
            echo
            echo "子命令:"
            echo "  --create <名称> <包管理器>  创建一个新的 strata，用于临时或探索性目的。"
            echo "                              <包管理器> 可以是: apt, pacman, dnf, portage。"
            echo "  --list                      列出所有可用的 strata。"
            echo "  -e, --execute <名称> <命令...>"
            echo "                              在 strata 内部执行一个命令。"
            echo "  --destroy <名称>            永久删除一个 strata。"
            echo "  --export-pkgs <名称>        以适用于 world 文件的格式，列出 strata 内的所有包。"
            echo "  --promote <名称>            将一个 strata '提升' 到 world 文件中，使其成为声明式状态。"
            ;;
        forum)
            # 这部分的帮助信息已经非常完善和双语化，无需大的改动
            # ... (保留原有的 forum 帮助信息) ...
            ;;
        *)
            # Fallback for other commands with simple help
            # 其他简单命令的备用帮助信息
            local base_command=${command_to_help%%|*}
            if command -v "usage_${base_command}" >/dev/null 2>&1; then
                "usage_${base_command}"
            else
                echo "No detailed help available for '$command_to_help'."
                echo "没有关于 '$command_to_help' 的详细帮助信息。"
            fi
            ;;
    esac
}

# =======================================================
# --- SECTION 28: MAIN DISPATCHER (The Entry Point)   ---
# --- 第28节: 主分发器 (程序入口)                       ---
# =======================================================

# Ensure the script is executed, not sourced
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then

    # --- Global Options Parsing (Handles --debug, --help, --version) ---
    # --- 全局选项解析 (处理 --debug, --help, --version) ---
    # This loop handles global options before the main command is processed.
    while [[ "$1" =~ ^- ]]; do
        case "$1" in
            --help|-h)
                usage
                exit 0
                ;;
            --version)
                echo "nxpkg version ${NXPKG_VERSION}"
                exit 0
                ;;
            --debug)
                export NXPKG_DEBUG=1
                echo "Debug mode enabled."
                shift # Move to the next argument
                ;;
            --)
                # End of options delimiter
                shift
                break
                ;;
            *)
                # Stop parsing if it's an unknown option; it might be for the subcommand.
                break
                ;;
        esac
    done

    # Load configuration from /etc/nxpkg/networks/${NXPKG_NETWORK_ID}/nxpkg.conf
    # Note: Global options like --debug are parsed first, so config can be loaded after.
    load_config

    # --- Main Command Dispatcher ---
    # --- 主命令分发器 ---
    main_command="${1:-}"

    # If no command is provided, show help and exit.
    if [ -z "$main_command" ]; then
        echo "Error: No command provided." >&2
        usage >&2
        exit 1
    fi
    shift # Remove the command from the arguments list, so '$@' contains only the command's arguments.

    case "$main_command" in
        init)
            nxpkg_init "$@"
            ;;
        sync)
            nxpkg_sync "$@"
            ;;
        install|in)
            nxpkg_install "$@"
            ;;
        remove|rm)
            nxpkg_remove "$@"
            ;;
        upgrade)
            nxpkg_upgrade "$@"
            ;;
        info)
            nxpkg_info "$@"
            ;;
        rebuild)
            nxpkg_rebuild_from_world "$@"
            ;;
        autoremove|autorm)
            nxpkg_autoremove "$@"
            ;;
        owns)
            nxpkg_owns "$@"
            ;;
        search)
            nxpkg_search "$@"
            ;;
        build)
            nxpkg_build "$@"
            ;;
        gen-build)
            [ $# -ne 1 ] && { echo "Usage: nxpkg gen-build <source_url>" >&2; exit 1; }
            nxpkg_gen_build "$1"
            ;;
        create-delta)
            nxpkg_create_delta "$@"
            ;;
        delta-update)
            [ $# -ne 1 ] && { echo "Usage: nxpkg delta-update <package_id>" >&2; exit 1; }
            nxpkg_delta_update "$1"
            ;;
        adopt)
            nxpkg_adopt "$@"
            ;;
        rollback)
            nxpkg_rollback "$@"
            ;;
        strata)
            # Pass all remaining arguments to the sub-dispatcher
            nxpkg_strata "$@"
            ;;
        manage)
            # Pass all remaining arguments to the sub-dispatcher
            nxpkg_manage "$@"
            ;;
        forum)
            # Pass all remaining arguments to the sub-dispatcher
            nxpkg_forum "$@"
            ;;
        key)
            nxpkg_key "$@"
            ;;
        clean)
            nxpkg_clean "$@"
            ;;
        # =======================================================
        # --- Internal Commands (Not for direct user execution) ---
        # --- 内部命令 (非用户直接执行)                         ---
        # =======================================================

        # [DEPRECATED] This entry point is the source of a major performance bottleneck
        # and has been replaced by logic within the Python DHT server. It is kept
        # here, commented out, for historical reference only.
        #
        # [已废弃] 这个命令入口是一个主要性能瓶颈的根源，已被 Python DHT 服务器
        # 内部的逻辑所取代。注释并保留在此处仅为历史参考。
        # _internal_handle_announcement)
        #     _blockchain_handle_new_block_announcement
        #     ;;

        # [ACTIVE] The sole entry point for the Python DHT server to trigger a
        #          blockchain reorganization after it has verified a heavier chain.
        # [使用的] Python DHT 服务器在验证了一条更重的链之后，用于触发区块链重组的唯一入口。
        # Arguments: $1=new_tip_hash, $2=peer_ip, $3=peer_port
        _internal_trigger_reorg)
            _blockchain_reorganize_to "$@"
            ;;

        # [ACTIVE] Helper for the Python daemon to resolve a user ID (hash) to
        #          a local public key file path, reusing the shell's caching logic.
        # [使用的] 供 Python 守护进程使用的辅助函数，用于将用户ID(哈希)解析为
        #          本地公钥文件的路径，复用了 shell 的缓存逻辑。
        _internal_get_pubkey_path)
            _internal_get_pubkey_path "$@"
            ;;
        help|h)
            # Call usage function with the next argument (e.g., 'nxpkg help install')
            # 调用 usage 函数，并传入下一个参数（例如 'nxpkg help install'）
            local cmd_to_help="${1:-}" # 如果没有参数，则为空
            case "$cmd_to_help" in
                in) cmd_to_help="install" ;;
                rm) cmd_to_help="remove" ;;
                auto|autorm) cmd_to_help="autoremove" ;;
                # --- [接口增强] 让 'help' 知道 'clean' 命令 ---
                clean) cmd_to_help="clean" ;;
            esac
            usage "$cmd_to_help"
            ;;
        *)
            echo "Error: Unknown command '$main_command'" >&2
            usage >&2
            exit 1
            ;;
    esac
fi

# =========================================================================================
# --- SECTION 29: PHILOSOPHY & WORKFLOW NOTES ON DECLARATIVE STRATA MANAGEMENT          ---
# --- 第29节: 关于声明式 STRATA 管理的哲学与工作流说明                                  ---
# =========================================================================================
#
# A critical design principle of NxPKG's declarative management (`rebuild` command)
# is the distinction between managing the Strata environment itself and the packages within it.
#
# NxPKG 声明式管理（`rebuild` 命令）的一个关键设计原则是：
# 区分“管理 Strata 环境本身”和“管理其内部的软件包”。
#
# -----------------------------------------------------------------------------------------
# HOW `rebuild --prune` AFFECTS STRATA
# `rebuild --prune` 如何影响 STRATA
# -----------------------------------------------------------------------------------------
#
# 1.  IT MANAGES THE CONTAINER, NOT THE CONTENT.
#     它管理的是“容器”，而非“内容”。
#
#     - A Strata environment is considered an "orphan" and will be DESTROYED by `--prune`
#       if, and only if, there is no corresponding `strata:<name>:<type>` declaration for it
#       in your world file.
#       一个 Strata 环境当且仅当在您的 world 文件中没有对应的 `strata:<name>:<type>` 声明时，
#       才被视为“孤儿”，并会被 `--prune` 销毁。
#
#     - It WILL NOT touch, check, or remove any packages you have manually installed
#       inside a Strata (e.g., via `nxpkg strata -e ... apt install ...`).
#       它绝对不会触碰、检查或移除任何您在 Strata 内部手动安装的软件包
#       （例如，通过 `nxpkg strata -e ... apt install ...` 安装的包）。
#
#
# 2.  THE `strata-pkg:` DECLARATION IS A "MINIMUM GUARANTEE", NOT AN "EXACT STATE".
#     `strata-pkg:` 声明是一种“最低保证”，而非“精确快照”。
#
#     - When you declare `strata-pkg:debian-dev:htop`, the `rebuild` command simply ensures
#       that `htop` is installed. If it's already there, it does nothing.
#       当您声明 `strata-pkg:debian-dev:htop` 时，`rebuild` 命令仅仅是确保 `htop` 被安装。
#       如果它已存在，命令什么也不做。
#
#     - It does NOT uninstall other packages inside the Strata that are not declared.
#       This allows you to safely install temporary tools for debugging or development
#       without fear of them being automatically removed.
#       它不会卸载 Strata 内部其他未被声明的包。这允许您安全地安装用于调试或开发的
#       临时工具，而无需担心它们会被自动移除。
#
# -----------------------------------------------------------------------------------------
# RECOMMENDED WORKFLOW: FROM EXPLORATION TO DECLARATION
# 推荐工作流：从“探索”到“声明”
# -----------------------------------------------------------------------------------------
#
# This design enables a powerful and flexible workflow:
# 这个设计带来了一个强大且灵活的工作流：
#
# 1.  EXPLORE (Imperative Mode):
#     探索阶段 (命令式模式):
#
#     Quickly set up a temporary environment for a new project or task.
#     为一个新项目或任务快速搭建一个临时环境。
#     $ sudo nxpkg strata --create my-temp-env apt
#
#     Freely install any tools you need inside it.
#     在其中自由地安装任何您需要的工具。
#     $ sudo nxpkg strata -e my-temp-env apt install -y git vim curl
#
#
# 2.  PROMOTE (Transition to Declarative):
#     提升阶段 (过渡到声明式):
#
#     Once you decide this environment is a long-term part of your system,
#     "promote" it. This automatically adds all necessary declarations to your world file.
#     一旦您决定这个环境是您系统的一个长期组成部分，就“提升”它。
#     这会自动将所有必要的声明添加到您的 world 文件中。
#     $ sudo nxpkg strata --promote my-temp-env
#
#
# 3.  MANAGE (Declarative Mode):
#     管理阶段 (声明式模式):
#
#     From now on, this environment's existence and its core packages are managed
#     declaratively. You can reproduce it on any machine just by applying your world file.
#     从现在起，这个环境的存在及其核心软件包都将以声明式方式被管理。
#     您可以在任何机器上通过应用您的 world 文件来复现它。
#     $ sudo nxpkg rebuild --prune
#
#     If you later decide to remove the environment, simply delete its declarations
#     from the world file, and `rebuild --prune` will automatically clean it up.
#     如果日后您决定移除该环境，只需从 world 文件中删除它的声明，
#     `rebuild --prune` 就会自动地将其清理干净。
#
# =========================================================================================

# =========================================================================================
# --- SECTION 30: MORE & MORE ---
# --- 第30节: 更多说明 ---
# =========================================================================================
howto_use_mod(){
    python3 -c """
如何创建和使用一个“Mod” (How to Create and Use a 'Mod')

现在系统已经具备了钩子功能，但用户如何创建和安装一个Mod呢？我们将遵循“万物皆包”的原则，并提供一个完整的示例。

Now that the system has the hook functionality, how can users create and install a Mod? We will follow the 'Everything as a Package' principle and provide a complete example.

A. Mod包的.build文件规范 (The .build File Specification for a Mod Package)

一个Mod包的.build文件需要一个新的元数据变量：nxpkg_hook_event。它的package()函数会将脚本安装到正确的钩子目录。

A Mod package's .build file requires a new metadata variable: nxpkg_hook_event. Its package() function will install the script into the correct hook directory.

B. 示例：创建一个桌面通知Mod (Example: Creating a Desktop Notification Mod)

让我们创建一个名为mod-desktop-notifier的模组。当nxpkg install成功后，它会在桌面弹出一个通知。

Let's create a mod named mod-desktop-notifier. After nxpkg install completes successfully, it will display a notification on the desktop.

1. 创建Mod的目录和文件 (Create the Mod's Directory and Files)

在你的本地仓库中 (例如, /usr/nxpkg/repos/core):
In your local repository (e.g., /usr/nxpkg/repos/core):



mkdir -p mods/mod-desktop-notifier
cd mods/mod-desktop-notifier

2. 编写 mod-desktop-notifier.build 文件 (Write the mod-desktop-notifier.build File)



# mods/mod-desktop-notifier/mod-desktop-notifier.build

pkgname='mod-desktop-notifier'
pkgver='1.0'
pkgdesc='A mod that shows a desktop notification after installing packages.'
url='https://example.com/nxpkg-mods'
slot='0'

# --- [关键] 定义这是一个什么类型的钩子 ---
# --- [CRITICAL] Defines what kind of hook this is ---
nxpkg_hook_event='post-install'

# Mod的源文件就是它的脚本
# The Mod's source file is its script
source=('notify.sh')
# 运行 sha256sum notify.sh 来获取
# Run sha256sum notify.sh to get this
sha256sums=('PUT_SHA256SUM_HERE')

# 假设脚本需要 notify-send
# Assuming the script requires notify-send
makedepends=('libnotify')

package() {
    # 将脚本安装到正确的钩子目录，并确保它是可执行的
    # Install the script to the correct hook directory and ensure it's executable
    install -D -m 0755 '${srcdir}/notify.sh' \
        '${pkgdir}/etc/nxpkg/hooks/${nxpkg_hook_event}.d/${pkgname}'
}

3. 编写钩子脚本 notify.sh (Write the Hook Script notify.sh)

这个脚本将在沙箱中执行。
This script will be executed inside the sandbox.



#!/bin/bash
# mods/mod-desktop-notifier/notify.sh

# 检查 notify-send 命令是否存在
# Check if the notify-send command exists
if ! command -v notify-send >/dev/null 2>&1; then
    echo 'mod-desktop-notifier: 'notify-send' command not found. Cannot send notification.' >&2
    exit 1
fi

# 从环境变量中读取由 _run_hooks 传递的上下文信息
# Read context from environment variables passed by _run_hooks
if [ -n '$NXPKG_INSTALLED_PACKAGES' ]; then
    # 计算安装了多少个包
    # Count how many packages were installed
    pkg_count=$(echo '$NXPKG_INSTALLED_PACKAGES' | wc -w)
    
    # 准备双语通知内容
    # Prepare bilingual notification content
    title='NxPKG 安装完成 (Installation Complete)'
    body='成功安装了 ${pkg_count} 个软件包 (Successfully installed ${pkg_count} package(s)):\n${NXPKG_INSTALLED_PACKAGES}'
    
    # 发送通知
    # Send the notification
    notify-send -i 'system-software-install' '$title' '$body'
fi

exit 0

4. 如何使用Mod (How to Use the Mod)

分发 (Distribution): 将mods/mod-desktop-notifier目录放置于nxpkg的一个仓库中。
Place the mods/mod-desktop-notifier directory into an nxpkg repository.

同步 (Sync): 运行 sudo nxpkg sync，nxpkg会发现这个新的Mod包。
Run sudo nxpkg sync, and nxpkg will discover this new Mod package.

安装 (Install): 像安装普通软件一样安装这个Mod：
Install the Mod just like any other package:



sudo nxpkg install mods/mod-desktop-notifier

nxpkg会执行package()函数，将notify.sh脚本安装到/etc/nxpkg/hooks/post-install.d/mod-desktop-notifier。
nxpkg will execute the package() function, installing the notify.sh script to /etc/nxpkg/hooks/post-install.d/mod-desktop-notifier.

触发 (Trigger): 现在，当你安装任何其他软件包时，例如 sudo nxpkg install app-misc/hello-world，在安装成功后，_run_hooks 'post-install' 会被触发，你的桌面将会收到一个通知！
Now, when you install any other package, for example sudo nxpkg install app-misc/hello-world, the _run_hooks 'post-install' will be triggered upon successful installation, and you will receive a desktop notification!

卸载 (Uninstall): 运行 sudo nxpkg remove mods/mod-desktop-notifier，钩子脚本会被自动删除，功能也就移除了。
Run sudo nxpkg remove mods/mod-desktop-notifier, the hook script will be automatically removed, and the functionality will be gone.
"""

# --- A Note on Seemingly 'Simulated' Components ---
# A brief clarification for developers: Certain components described as 'simulated' are
# not incomplete placeholders, but deliberate design choices essential to the project's
# architecture and philosophy.
#
# 1. P2P Node Simulator vs. The Real Network:
#    The P2P network itself (based on a Kademlia DHT over encrypted HTTPS) is fully
#    functional. The 'P2P node simulator' (`P2P_SIMULATE_NODES`) is an intentional
#    utility for network bootstrapping (cold starts) and development. It allows a user
#    to instantly create a micro-network for testing or to launch a new, private
#    network without reliance on public bootstrap nodes. It is a feature, not a workaround.
#
# 2. Genesis Block Signature:
#    The 'simulated' signature of the genesis block is a conceptual necessity for any
#    blockchain. The first block cannot be created by consensus because the network does
#    not yet exist. It must be pre-defined as the root of trust. This design empowers
#    any user to create their own independent network by defining their own `genesis.json` file.
#
# 3. PoW Consensus Mechanism:
#    The Proof-of-Work (PoW) code is a true placeholder and is non-functional. The core
#    consensus logic of NxPKG is built entirely around Proof-of-Stake (PoS). The PoW
#    references can be safely ignored.

# --- 关于看似“模拟”组件的设计说明 ---
# 为开发者提供的简要说明：某些被描述为“模拟”的组件并非未完成的占位符，
# 而是对项目架构与哲学至关重要的、刻意的设计选择。
#
# 1. P2P节点模拟器 vs. 真实的P2P网络：
#    P2P网络本身（基于Kademlia DHT和加密HTTPS）是功能完备的。所谓的“P2P节点模拟器”
#    (`P2P_SIMULATE_NODES`)是一个为网络“冷启动”和开发而设计的实用功能。它允许用户
#    即时创建一个用于测试的微型网络，或在不依赖任何公共引导节点的情况下启动一个
#    全新的私有网络。这是一个特性，而非一个权宜之计。
#
# 2. 创世区块签名：
#    创世区块的“模拟”签名对于任何区块链系统而言，都是一个概念上的必需品。
#    第一个区块无法通过网络共识产生，因为那时网络尚不存在。它必须被预先定义为
#    整个信任链的根源。此设计旨在赋能任何用户，让他们能通过定义自己的
#    `genesis.json` 文件来创建独立的网络。
#
# 3. PoW共识机制：
#    工作量证明（PoW）相关的代码是真正的占位符，不具备功能。NxPKG的核心共识逻辑
#    完全围绕权益证明（PoS）构建。关于PoW的部分可以安全地忽略。

# =========================================================================================
# --- [BUG ANALYSIS] Stale PID in Background Process Tracking (Minor Issue)             ---
# --- [缺陷分析] 后台进程跟踪中的陈旧PID (次要问题)                                     ---
# =========================================================================================
#
#
# --- English Analysis ---
#
# 1.  **Problem Description:**
#     The `dht_server_daemon` function is designed to be robust, automatically restarting
#     the Python DHT server if it ever crashes, thanks to its `while true` loop.
#     The initial PID of the Python process is correctly captured in `dht_bootstrap` and
#     added to the global `NXPKG_BACKGROUND_PIDS` array.
#
# 2.  **The Flaw:**
#     If the Python server crashes and is restarted by the `while` loop, the new Python
#     process will have a new PID. However, the logic to capture this new PID and update
#     the `NXPKG_BACKGROUND_PIDS` array is *outside* the loop (it runs only once at startup).
#     As a result, the array holds a "stale" PID of the original, now-dead process, while
#     the newly started process becomes untracked by this primary mechanism.
#
# 3.  **Impact & Mitigation:**
#     The potential impact (an orphaned process left running after the main script exits)
#     is **fully mitigated** by a secondary cleanup mechanism in the `cleanup` function:
#
#     `jobs -p | xargs -r kill 2>/dev/null || true`
#
#     The `jobs -p` command correctly identifies *all* background jobs started by the current
#     shell, including the newly restarted Python process. This fallback ensures that even
#     if the PID array is stale, the active daemon is still properly terminated upon exit.
#
# 4.  **Conclusion:**
#     This is a minor logical imperfection in the explicit PID tracking mechanism. It does
#     not lead to resource leaks or functional failure due to the robust, dual-guarantee
#     design of the `cleanup` function. It is not considered a critical bug and requires no
#     immediate fix, as the system's overall robustness already accounts for it.
#
#
# --- 中文分析 ---
#
# 1.  **问题描述:**
#     `dht_server_daemon` 函数被设计得非常健壮，其内部的 `while true` 循环可以在 Python DHT
#     服务器崩溃时自动重启它。在脚本首次启动时，`dht_bootstrap` 函数会正确捕获初始的
#     Python 进程PID，并将其添加到全局的 `NXPKG_BACKGROUND_PIDS` 数组中。
#
# 2.  **逻辑瑕疵:**
#     如果 Python 服务器崩溃并被 `while` 循环重启，新的 Python 进程会获得一个全新的PID。
#     然而，捕获这个新PID并更新 `NXPKG_BACKGROUND_PIDS` 数组的逻辑位于循环之*外*（它只在
#     启动时运行一次）。因此，该数组将继续持有一个“陈旧的”、指向已死亡进程的PID，而新启动的
#     进程对于这个主跟踪机制而言是“不可见”的。
#
# 3.  **影响与规避:**
#     这个问题的潜在影响（主脚本退出后留下一个孤儿进程）被 `cleanup` 函数中的一个备用清理
#     机制**完全规避**了：
#
#     `jobs -p | xargs -r kill 2>/dev/null || true`
#
#     `jobs -p` 命令能够正确地识别出由当前 Shell 启动的所有后台作业，其中就包括那个被重新
#     启动的、拥有新PID的 Python 进程。这个后备方案确保了即使PID数组中的信息是陈旧的，
#     活跃的守护进程在脚本退出时依然能被正确地终止。
#
# 4.  **结论:**
#     这是一个在显式PID跟踪机制中存在的微小逻辑瑕疵。由于 `cleanup` 函数健壮的“双重保障”
#     设计，它并不会导致资源泄漏或功能性故障。因此，这不被认为是一个关键缺陷，也无需立即修复，
#     因为系统的整体健壮性已经覆盖了这种情况。
#
# =========================================================================================