# rustfuzz

**rustfuzz** is a high-performance, advanced web fuzzer written in Rust. It’s designed for security professionals and developers to discover hidden files, directories, and vulnerabilities on web servers. Inspired by tools like `ffuf`, rustfuzz emphasizes speed, flexibility, and modern security research workflows.

---

## 🚀 Features

- 🌐 **URL and Directory Fuzzing**: Quickly identify hidden endpoints, files, and directories.
- ⚡ **High Performance**: Async/multithreaded engine for maximum speed.
- 🧰 **Flexible & Customizable**:
  - Specify target URLs (`-u`, `--url`)
  - Custom wordlists (`-w`, `--wordlist`)
  - Status code matching (`-m`, `--matcher`)
  - Custom headers, cookies, and authentication tokens
  - Timeout and rate limiting
  - **Config file support** (`--config`) for reusable setups
  - Proxy support (HTTP/SOCKS5/Burp Suite)
  - Export results (`--export`) in JSON or CSV
  - Payload injection (`--payloads`)
  - Mutation-based fuzzing (`--mutate`)
  - Smart crawling (`--crawl`) to discover more endpoints
  - OpenAPI/Swagger parsing (`--openapi`)
  - Results analysis (`--analyze`)
- 🔒 **Modern Security Workflows**:
  - Designed for both bug bounty hunters and blue teams
  - Diagnostic output and robust error handling

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/martian58/rustfuzz.git
   cd rustfuzz
   ```

2. Build the project using Cargo:
   ```bash
   cargo build --release
   ```

3. The binary will be available at:
   ```bash
   ./target/release/rustfuzz
   ```

---

## 📖 Usage

Run `rustfuzz` with your desired options:

```bash
./rustfuzz -u <URL> -w <wordlist> -t <threads>
```

### Example (CLI only):

```bash
./rustfuzz -u https://example.com/FUZZ -w /path/to/wordlist.txt -t 20
```

### Using a Configuration File

You can store your options in a TOML config file and load them with the `--config` flag:

```bash
./rustfuzz --config rustfuzz.toml
```

**Example `rustfuzz.toml`:**
```toml
url = "https://example.com"
wordlist = "wordlists/common.txt"
threads = 20
timeout = 10
matcher = "200,301,302"
proxy = "http://127.0.0.1:8080"
export = "results/output.json"
# Add other options as needed
```

- Any command-line argument will override the value in the config file.
- The config file supports all options available via CLI.

### More Examples

With a proxy (e.g., Burp Suite):
```bash
./rustfuzz --config config.toml --proxy http://127.0.0.1:8080
```

Exporting results:
```bash
./rustfuzz -u https://example.com -w words.txt --export results.json
```

Advanced fuzzing with payloads:
```bash
./rustfuzz -u https://example.com --payloads payloads/xss.txt
```

Smart crawling:
```bash
./rustfuzz -u https://example.com --crawl
```

Analyze exported results:
```bash
./rustfuzz --analyze results.json
```

For the full list of options and help:
```bash
./rustfuzz --help
```

---

## 🛠️ Development

To contribute or make changes:
1. Ensure you have Rust installed: [Rust Installation Guide](https://www.rust-lang.org/tools/install)
2. Clone the repository and create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Build and test your changes:
   ```bash
   cargo build
   cargo test
   ```
4. Push your branch and create a pull request.

---

## ⚡ Proxy Support

- HTTP, HTTPS, and SOCKS5 proxies are supported.
- For Burp Suite integration, use `http://127.0.0.1:8080` as your proxy.

---

## 📜 License

This project is licensed under the GNU General Public License. See the [LICENSE](LICENSE) file for details.

---

## 💡 Feedback

We'd love to hear your feedback!  
Open an issue or pull request to help improve rustfuzz.

Happy fuzzing! 🕵️‍♂️