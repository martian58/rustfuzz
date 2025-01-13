# rustfuzz

**rustfuzz** is a high-performance web fuzzer written in Rust, designed to help security professionals and developers discover hidden files and directories on web servers. Inspired by tools like `ffuf`, rustfuzz focuses on speed, simplicity, and reliability.

---

## 🚀 Features

- 🌐 **URL Fuzzing**: Quickly identify hidden endpoints and directories.
- ⚡ **High Performance**: Multithreaded for maximum efficiency.
- 🧰 **Customizable Options**:
  - Specify the target URL (`-u`).
  - Use custom wordlists (`-w`).
  - Give a list of http status codes (`-m`).
  - Set a timeout (`-T`).
---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone git@github.com:<your-username>/rustfuzz.git
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

Run `rustfuzz` with the following options:

```bash
./rustfuzz -u <URL> -w <wordlist> -t <threads>
```

### Example:
```bash
./rustfuzz -u http://example.com/FUZZ -w /path/to/wordlist.txt -t 10
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

## 📜 License

This project is licensed under the GNU GENERAL PUBLIC License. See the [LICENSE](LICENSE) file for details.

---

## 💡 Feedback

We'd love to hear your feedback! Feel free to open an issue or submit a pull request to help improve rustfuzz.

Happy fuzzing! 🕵️‍♂️
