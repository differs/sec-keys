# EVM Key Manager

生成、加密、管理 Ethereum 私钥的命令行工具。**加密后的私钥文件可以安全地提交到 GitHub。**

## 功能

| 命令 | 说明 |
|------|------|
| `generate N` | 生成 N 个私钥，加密保存到 `YYYYMMDD_XXXX.csv.enc` |
| `list` | 解密并显示所有私钥‑地址对 |
| `export` | 导出为明文 CSV 或重新加密 |

## 安装

需要 Python 3.10+：

```bash
pip install cryptography pycryptodome
```

## 使用

### 生成私钥

```bash
# 生成 5 个私钥
python3 evm_key_manager.py generate 5

# 指定数量（默认 1 个）
python3 evm_key_manager.py generate 10

# 指定文件名（不指定则自动命名 20260623_a1f2.csv.enc）
python3 evm_key_manager.py generate 3 -f my_wallet.csv.enc
```

首次运行会要求设置密码，后续操作都需要此密码。

**输出示例：**

```
✔ Generated 3 new key(s).  Total in store: 3
   Store: 20260623_a1f2.csv.enc

  Newly generated keys

    #  PRIVATE KEY                                                           ADDRESS
  ────────────────────────────────────────────────────────────────────────────────────────────
    1  0xe7be88776b7cc86195906a3b89b3938296b58c23a9e2835262c7fbfde5c054bf    0x8de47ada6483b0badf2137a83c22aaf1b173fd01
    2  0x9f0825f714911fab0ccbfc3f625ffcf72e2d2049a1625338dbb4cdea5ce3e6e8    0x63288dec98c6bcdd967240ba1877b1583dba29b5
    3  0x16d4a8c8a060f82495268875bb5d05a68130d1e393a0a080625ee8776e045391    0x0c0837133dda565bc159838e011a552b6d007309
  ────────────────────────────────────────────────────────────────────────────────────────────
```

### 追加生成（已有文件）

```bash
python3 evm_key_manager.py generate 2 -f 20260623_a1f2.csv.enc
```

会先解密旧文件，追加新密钥，再重新加密保存。

### 查看私钥

```bash
python3 evm_key_manager.py list
python3 evm_key_manager.py list -f 20260623_a1f2.csv.enc
```

省略 `-f` 时自动选择目录中唯一的 `.csv.enc` 文件。

### 导出

```bash
# 导出为明文 CSV（⚠️ 包含原始私钥，小心处理）
python3 evm_key_manager.py export -f 20260623_a1f2.csv.enc --decrypt -o backup.csv

# 导出为重新加密的文件（换密码）
python3 evm_key_manager.py export -f 20260623_a1f2.csv.enc -o backup_encrypted.csv.enc
```

## 加密方案

```
密码 → Argon2id(64 MiB, 3轮, 1并行) → 256位密钥 → AES-256-GCM 加密
```

| 项目 | 参数 |
|------|------|
| **KDF** | Argon2id（memory‑hard，抗 GPU/ASIC） |
| **KDF 参数** | 64 MiB 内存，3 轮迭代，1 路并行 |
| **对称加密** | AES-256-GCM（认证加密，防篡改） |
| **随机数** | 128-bit salt + 96-bit nonce，每次加密不同 |
| **文件权限** | 创建后自动设为 `600`（仅 owner 读写） |

每次加密使用独立随机 salt 和 nonce，相同密码每次产生不同密文。

## 备份到 GitHub

### 安全原理

加密文件 `*.csv.enc` 的内容是一个 JSON 容器，只包含：

```json
{
  "version": 2,
  "kdf": {
    "type": "argon2id",
    "salt": "DQo3i+TzAH57rp39QJ0gIQ==",
    "iterations": 3,
    "lanes": 1,
    "memory_cost_kib": 65536
  },
  "nonce": "qVF9IJnxw74YExtr",
  "data": "b1fxHm3u1IscJhZFP3vBQFk6ep83..."
}
```

- `salt` — 随机值，无信息泄露
- `nonce` — 随机值，无信息泄露
- `data` — AES-256-GCM 密文，无密码无法解密

**可以安全地提交到任意公开/私有仓库。**

### 安全规则

| ✅ 可以做 | ❌ 绝不能做 |
|----------|------------|
| `git add *.csv.enc` | `git add exported_keys.csv`（明文导出） |
| 密码存在密码管理器 | 密码写在源码、README、或 issue 里 |
| `git push` 加密文件 | 把明文 `.csv` 传上网 |

### 工作流示例

```bash
# 生成密钥
python3 evm_key_manager.py generate 5

# 提交到 GitHub
git add 20260623_a1f2.csv.enc
git commit -m "add key store 2026-06-23"
git push

# 异地恢复
git clone git@github.com:your/repo.git
python3 evm_key_manager.py list -f 20260623_a1f2.csv.enc
# 输入密码 → 即可看到所有私钥
```

### 密码丢失

**密码丢失 = 私钥永久丢失。** 本工具没有密码找回机制，这是有意设计的安全特性。

建议：
1. 使用 16 位以上强密码（大小写 + 数字 + 符号）
2. 存到密码管理器（1Password / Bitwarden / KeePass 等）
3. 不要依赖"自己肯定记得住"

## .gitignore 说明

```gitignore
exported_keys.csv
```

只屏蔽了默认的明文导出文件名。`*.csv.enc` 不受限制，可以正常提交。

## 安全审计

本工具的设计原则：
- **绝不在磁盘上写入明文私钥**（除非用户显式执行 `export --decrypt`）
- **密码通过 `getpass` 交互输入**，不会出现在 shell history 中
- **加密文件权限自动设为 600**，防止同机其他用户读取
- **无临时文件**，所有加解密操作在内存中完成

## 依赖

- `cryptography` — Argon2id 密钥派生 + AES-256-GCM 加解密
- `pycryptodome` — keccak256 哈希（Ethereum 地址推导）
