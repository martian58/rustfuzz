use clap::{Arg, ArgAction, Command};
use futures::{stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::{collections::{HashSet, VecDeque}, fs, time::Duration};
use std::sync::Arc;
use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt, BufReader},
    sync::Semaphore,
    time::sleep,
};
use url::Url;
use serde_json;
use csv;

#[derive(Debug, Deserialize)]
struct Config {
    url: Option<String>,
    wordlist: Option<String>,
    threads: Option<usize>,
    timeout: Option<u64>,
    matcher: Option<String>,
    headers: Option<Vec<(String, String)>>,
    cookies: Option<Vec<(String, String)>>,
    auth_token: Option<String>,
    proxy: Option<String>,
    rate_limit: Option<u64>,
    export: Option<String>,
    crawl: Option<bool>,
    mutate: Option<bool>,
    payloads: Option<String>,
    openapi: Option<String>,
    analyze: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FuzzResult {
    url: String,
    word: String,
    status: u16,
    reflected: bool,
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    println!(
        r#"
         _____           _    __               
        |  __ \         | |  / _|              
        | |__) |   _ ___| |_| |_ _   _ ________
        |  _  / | | / __| __|  _| | | |_  /_  /
        | | \ \ |_| \__ \ |_| | | |_| |/ / / / 
        |_|  \_\__,_|___/\__|_|  \__,_/___/___|
                                       
        rustfuzz - v3.2.0
        "#
    );

    let matches = Command::new("rustfuzz")
        .version("3.2.0")
        .author("Martian58")
        .about("Website fuzzer written in Rust - advanced edition")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to TOML config file")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .value_name("URL")
                .help("Target URL to fuzz (overrides config)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("FILE")
                .help("Path to the wordlist (overrides config)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("NUMBER")
                .help("Number of concurrent threads")
                .default_value("40")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("timeout")
                .short('T')
                .long("timeout")
                .value_name("SECONDS")
                .help("Request timeout in seconds")
                .default_value("10")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("matcher")
                .short('m')
                .long("matcher")
                .value_name("CODES")
                .help("Comma-separated list of status codes to match (e.g., 200,301,302)")
                .default_value("200,301,302,401,403,405,500")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("headers")
                .long("header")
                .value_name("HEADER")
                .help("Custom header(s) (key:value, can be used multiple times)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("cookie")
                .long("cookie")
                .value_name("COOKIE")
                .help("Custom cookie(s) (key:value, can be used multiple times)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("auth")
                .long("auth-token")
                .value_name("TOKEN")
                .help("Bearer or other auth token")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .value_name("PROXY")
                .help("Proxy URL (http/https/socks5)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("rate_limit")
                .long("rate-limit")
                .value_name("MS")
                .help("Rate limit in milliseconds between requests")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("export")
                .long("export")
                .value_name("FILE")
                .help("Export results to file (json/csv)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("mutate")
                .long("mutate")
                .help("Use mutation-based fuzzing")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("payloads")
                .long("payloads")
                .value_name("FILE")
                .help("Additional payloads file for injection/fuzzing")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("crawl")
                .long("crawl")
                .help("Enable smart crawler to find more endpoints")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("openapi")
                .long("openapi")
                .value_name("URL")
                .help("Parse OpenAPI/Swagger spec for endpoints")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("analyze")
                .long("analyze")
                .value_name("FILE")
                .help("Analyze and beautifully print results from an export file")
                .action(ArgAction::Set),
        )
        .get_matches();

    // Require at least one of --analyze, --wordlist, or --crawl, or --config
    let has_analyze = matches.get_one::<String>("analyze").is_some();
    let has_config = matches.get_one::<String>("config").is_some();
    let has_wordlist = matches.get_one::<String>("wordlist").is_some();
    let has_crawl = matches.get_flag("crawl");

    if !(has_analyze || has_wordlist || has_crawl || has_config) {
        eprintln!(
            "Error: You must provide at least one of --analyze <file>, --config <file>, --wordlist <file>, or --crawl\n\
            Example: rustfuzz --wordlist words.txt --url https://example.com\n\
            Or:      rustfuzz --config config.toml\n\
            Or:      rustfuzz --crawl --url https://example.com\n\
            Or:      rustfuzz --analyze results.json"
        );
        std::process::exit(1);
    }

    // Parse config
    let mut config = if let Some(cfg_path) = matches.get_one::<String>("config") {
        let cfg_str = std::fs::read_to_string(cfg_path).expect("Failed to read config");
        toml::from_str::<Config>(&cfg_str).expect("Failed to parse TOML config")
    } else {
        Config {
            url: matches.get_one::<String>("url").cloned(),
            wordlist: matches.get_one::<String>("wordlist").cloned(),
            threads: matches.get_one::<String>("threads").and_then(|s| s.parse().ok()),
            timeout: matches.get_one::<String>("timeout").and_then(|s| s.parse().ok()),
            matcher: matches.get_one::<String>("matcher").cloned(),
            headers: matches.get_many::<String>("headers").map(|vals| vals.map(|kv| split_kv(kv)).collect()),
            cookies: matches.get_many::<String>("cookie").map(|vals| vals.map(|kv| split_kv(kv)).collect()),
            auth_token: matches.get_one::<String>("auth").cloned(),
            proxy: matches.get_one::<String>("proxy").cloned(),
            rate_limit: matches.get_one::<String>("rate_limit").and_then(|s| s.parse().ok()),
            export: matches.get_one::<String>("export").cloned(),
            crawl: matches.get_flag("crawl").then_some(true),
            mutate: matches.get_flag("mutate").then_some(true),
            payloads: matches.get_one::<String>("payloads").cloned(),
            openapi: matches.get_one::<String>("openapi").cloned(),
            analyze: matches.get_one::<String>("analyze").cloned(),
        }
    };

    // Command-line always overrides config if set
    if let Some(url) = matches.get_one::<String>("url") {
        config.url = Some(url.clone());
    }
    if let Some(wordlist) = matches.get_one::<String>("wordlist") {
        config.wordlist = Some(wordlist.clone());
    }
    if matches.get_flag("crawl") {
        config.crawl = Some(true);
    }
    if matches.get_flag("mutate") {
        config.mutate = Some(true);
    }
    if let Some(payloads) = matches.get_one::<String>("payloads") {
        config.payloads = Some(payloads.clone());
    }
    if let Some(analyze) = matches.get_one::<String>("analyze") {
        config.analyze = Some(analyze.clone());
    }
    if let Some(openapi) = matches.get_one::<String>("openapi") {
        config.openapi = Some(openapi.clone());
    }

    // Unified feature switches
    let crawl_enabled = config.crawl.unwrap_or(false);
    let mutate_enabled = config.mutate.unwrap_or(false);
    let analyze_path = config.analyze.clone();
    let payloads_path = config.payloads.clone();

    let url = config.url.as_deref().unwrap_or("");
    let wordlist = config.wordlist.as_deref().unwrap_or("");
    let threads = config.threads.unwrap_or(40);
    let timeout = config.timeout.unwrap_or(10);
    let status_codes: Vec<u16> = config
        .matcher
        .as_deref()
        .unwrap_or("200,301,302,401,403,405,500")
        .split(',')
        .filter_map(|code| code.parse::<u16>().ok())
        .collect();
    let rate_limit = config.rate_limit.unwrap_or(0);

    println!(":: Method           : GET");
    println!(":: URL              : {}", url);
    println!(":: Wordlist         : {}", wordlist);
    println!(":: Threads          : {}", threads);
    println!(":: Timeout          : {} seconds", timeout);
    println!(":: Matcher          : {:?}", status_codes);
    if let Some(proxy) = &config.proxy {
        println!(":: Proxy            : {}", proxy);
    }
    if let Some(export) = &config.export {
        println!(":: Export           : {}", export);
    }
    println!();

    // Load wordlist
    let mut words = Vec::new();
    if !wordlist.is_empty() {
        words = load_wordlist(wordlist).await.expect("Failed to load wordlist");
    }

    // Mutation-based fuzzing
    if mutate_enabled {
        let extra_mutations = mutate_wordlist(&words);
        words.extend(extra_mutations);
    }

    // Add payloads
    if let Some(payload_file) = payloads_path {
        let mut payloads = load_wordlist(&payload_file).await.expect("Failed to load payloads file");
        words.append(&mut payloads);
    }

    // Crawl mode: find additional endpoints (now smart)
    let mut discovered = HashSet::new();
    if crawl_enabled {
        let found = crawl(
            url,
            4,        // depth
            1000,     // max pages
            config.cookies.as_ref().unwrap_or(&vec![]),
            config.headers.as_ref().unwrap_or(&vec![]),
        ).await;
        for endpoint in &found {
            println!(":: Discovered endpoint: {}", endpoint);
        }
        discovered.extend(found);
    }

    // OpenAPI parsing (stub)
    let openapi_path = config.openapi.clone();
    if let Some(openapi_url) = openapi_path {
        let api_endpoints = parse_openapi(&openapi_url).await;
        for ep in &api_endpoints {
            println!(":: OpenAPI endpoint: {}", ep);
        }
        discovered.extend(api_endpoints);
    }

    // Combine discovered endpoints with words
    let mut targets: Vec<String> = words
        .iter()
        .filter(|w| !w.trim().is_empty())
        .map(|w| format!("{}/{}", url.trim_end_matches('/'), w))
        .collect();
    for ep in discovered {
        targets.push(ep);
    }

    let progress_bar = ProgressBar::new(targets.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut client_builder = Client::builder().timeout(Duration::from_secs(timeout));
    if let Some(proxy) = &config.proxy {
        client_builder = client_builder.proxy(Proxy::all(proxy).expect("Invalid proxy"));
    }
    let client = client_builder.build().unwrap();

    let headers = config.headers.clone().unwrap_or_default();
    let cookies = config.cookies.clone().unwrap_or_default();
    let auth_token = config.auth_token.clone();

    let results = tokio::sync::Mutex::new(Vec::new());
    let semaphore = Arc::new(Semaphore::new(threads));

    // The main fuzzing loop
    stream::iter(targets)
        .for_each_concurrent(threads, |target| {
            let client = client.clone();
            let status_codes = status_codes.clone();
            let progress_bar = progress_bar.clone();
            let headers = headers.clone();
            let cookies = cookies.clone();
            let auth_token = auth_token.clone();
            let results = &results;
            let semaphore = semaphore.clone();

            async move {
                let _permit = semaphore.acquire().await.unwrap();
                if rate_limit > 0 {
                    sleep(Duration::from_millis(rate_limit)).await;
                }
                let word = target.split('/').last().unwrap_or("");
                let res = fuzz_url_adv(
                    &client,
                    &target,
                    word,
                    &headers,
                    &cookies,
                    auth_token.as_deref(),
                )
                .await;
                match &res {
                    Ok((status, body)) => {
                        let reflected = body.contains(word);
                        let has_error = detect_error(body);

                        // Only print/export if status in --matcher
                        if status_codes.contains(status) {
                            println!(
                                "{status} - {target}{}{}",
                                if reflected { " [REFLECTED]" } else { "" },
                                if has_error { " [ERROR]" } else { "" }
                            );
                            let r = FuzzResult {
                                url: target.clone(),
                                word: word.to_string(),
                                status: *status,
                                reflected,
                                error: if has_error { Some("Possible error detected".into()) } else { None },
                            };
                            results.lock().await.push(r);
                        }
                    }
                    Err(_e) => {
                        // Always show and export network errors
                        // println!("ERR  - {target} [error: {e}]");
                        // let r = FuzzResult {
                        //     url: target.clone(),
                        //     word: word.to_string(),
                        //     status: 0,
                        //     reflected: false,
                        //     error: Some(e.to_string()),
                        // };
                        // results.lock().await.push(r);
                    }
                }
                progress_bar.inc(1);
            }
        })
        .await;

    progress_bar.finish_with_message("Fuzzing complete!");

    // Export results
    if let Some(export) = &config.export {
        let results = results.lock().await;
        if export.ends_with(".json") {
            std::fs::write(export, serde_json::to_string_pretty(&*results).unwrap()).unwrap();
            println!(":: Results exported to {export}");
        } else if export.ends_with(".csv") {
            let mut wtr = csv::Writer::from_path(export).unwrap();
            for r in &*results {
                wtr.serialize(r).unwrap();
            }
            wtr.flush().unwrap();
            println!(":: Results exported to {export}");
        } else {
            println!(":: Unknown export format. Supported: .json, .csv");
        }
    }

    // Analyze results if requested
    if let Some(analyze_file) = analyze_path {
        analyze_results(&analyze_file).await;
    }
}

async fn load_wordlist(path: &str) -> io::Result<Vec<String>> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut line_stream = reader.lines();
    while let Some(line) = line_stream.next_line().await? {
        lines.push(line);
    }
    Ok(lines)
}

fn mutate_wordlist(words: &[String]) -> Vec<String> {
    let mut rng = thread_rng();
    let specials = ["'", "\"", "<", ">", ";", "|", "&"];
    let mut mutations = Vec::new();
    for word in words {
        mutations.push(word.to_uppercase());
        mutations.push(word.chars().rev().collect());
        mutations.push(format!("{}{}", word, specials.choose(&mut rng).unwrap()));
        mutations.push(format!("%{}%", word));
        mutations.push(format!("{}1", word));
    }
    mutations
}

fn split_kv(s: &str) -> (String, String) {
    let mut sp = s.splitn(2, ':');
    (
        sp.next().unwrap_or("").trim().to_string(),
        sp.next().unwrap_or("").trim().to_string(),
    )
}

async fn fuzz_url_adv(
    client: &Client,
    url: &str,
    _word: &str,
    headers: &Vec<(String, String)>,
    cookies: &Vec<(String, String)>,
    auth_token: Option<&str>,
) -> Result<(u16, String), reqwest::Error> {
    let mut req = client.get(url);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if !cookies.is_empty() {
        let cookie_str = cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        req = req.header("Cookie", cookie_str);
    }
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body))
}

fn detect_error(body: &str) -> bool {
    let error_patterns = [
        "internal server error",
        "exception",
        "traceback",
        "fatal",
        "stack trace",
        "syntax error",
        "sql error",
        "not allowed",
        "access denied",
        "unhandled",
    ];
    let re = Regex::new(&error_patterns.join("|")).unwrap();
    re.is_match(&body.to_lowercase())
}

/// Smart Crawler: BFS, supports cookies, headers, domain limit, ignores non-HTML, deduplicates, detects API/REST endpoints.
pub async fn crawl(
    base_url: &str,
    max_depth: usize,
    max_pages: usize,
    cookies: &Vec<(String, String)>,
    headers: &Vec<(String, String)>,
) -> HashSet<String> {
    let mut found = HashSet::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    let client = Client::new();
    let base_url = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return found,
    };
    let base_domain = base_url.domain().map(|d| d.to_string());

    queue.push_back((base_url.clone(), 0));
    visited.insert(base_url.as_str().to_string());

    let href_re = Regex::new(r#"href\s*=\s*["']([^"'>]+)["']"#).unwrap();
    let api_re = Regex::new(r#"(api|rest|openapi|swagger|v\d+)"#).unwrap();

    // Prepare cookie/header string if needed
    let cookie_str = if !cookies.is_empty() {
        Some(
            cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ")
        )
    } else {
        None
    };

    while let Some((url, depth)) = queue.pop_front() {
        if depth > max_depth || found.len() >= max_pages {
            break;
        }

        let mut req = client.get(url.as_str());
        if let Some(ref c) = cookie_str {
            req = req.header("Cookie", c);
        }
        for (k, v) in headers {
            req = req.header(k, v);
        }

        let body = match req.send().await {
            Ok(resp) => {
                // Ignore non-HTML responses (e.g., images, PDFs)
                let content_type = resp.headers().get("content-type")
                    .and_then(|val| val.to_str().ok())
                    .unwrap_or("");
                if !content_type.starts_with("text/html") {
                    continue;
                }
                match resp.text().await {
                    Ok(txt) => txt,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };

        for cap in href_re.captures_iter(&body) {
            let href = cap.get(1).unwrap().as_str();

            // Ignore fragments, mailto, javascript, tel, data URIs, etc.
            if href.starts_with('#')
                || href.starts_with("mailto:")
                || href.starts_with("javascript:")
                || href.starts_with("tel:")
                || href.starts_with("data:")
            {
                continue;
            }

            // Resolve relative/absolute
            let Ok(joined) = url.join(href) else { continue; };

            // Stay within the same domain (and scheme)
            if let Some(domain) = joined.domain() {
                if let Some(base) = &base_domain {
                    if domain != base {
                        continue;
                    }
                }
            }
            if joined.scheme() != base_url.scheme() {
                continue;
            }

            let joined_str = joined.as_str().to_string();
            // Skip duplicates
            if !visited.insert(joined_str.clone()) {
                continue;
            }

            // Ignore static assets (optional: expand this list)
            if joined_str.ends_with(".jpg") || joined_str.ends_with(".jpeg")
                || joined_str.ends_with(".png") || joined_str.ends_with(".gif")
                || joined_str.ends_with(".svg") || joined_str.ends_with(".ico")
                || joined_str.ends_with(".css") || joined_str.ends_with(".js")
                || joined_str.ends_with(".woff") || joined_str.ends_with(".woff2")
                || joined_str.ends_with(".ttf") || joined_str.ends_with(".eot")
                || joined_str.ends_with(".pdf") || joined_str.ends_with(".zip")
            {
                continue;
            }

            // Mark interesting API endpoints as priority
            if api_re.is_match(&joined_str) {
                // Optionally: print or log "API endpoint detected"
            }

            found.insert(joined_str.clone());
            queue.push_back((joined, depth + 1));
        }
    }

    found
}

async fn parse_openapi(_url: &str) -> HashSet<String> {
    let mut s = HashSet::new();
    s.insert("https://example.com/api/v1/users".to_string());
    s.insert("https://example.com/api/v1/login".to_string());
    s
}

/// Analyze and beautifully print the results from JSON or CSV export file
async fn analyze_results(path: &str) {
    println!(":: Analyzing results from {path}");
    let mut results: Vec<FuzzResult> = Vec::new();

    if path.ends_with(".json") {
        let file_content = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read file: {e}");
                return;
            }
        };
        results = match serde_json::from_str(&file_content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse JSON: {e}");
                return;
            }
        };
    } else if path.ends_with(".csv") {
        let mut rdr = match csv::Reader::from_path(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to open CSV: {e}");
                return;
            }
        };
        for result in rdr.deserialize() {
            match result {
                Ok(r) => results.push(r),
                Err(e) => {
                    eprintln!("Failed to deserialize row: {e}");
                }
            }
        }
    } else {
        eprintln!("Unsupported file type for analysis: {path}");
        return;
    }

    if results.is_empty() {
        println!("No results to analyze.");
        return;
    }

    // Beautiful summary and table
    let total = results.len();
    let success = results.iter().filter(|r| r.status >= 200 && r.status < 300).count();
    let redirects = results.iter().filter(|r| r.status >= 300 && r.status < 400).count();
    let client_err = results.iter().filter(|r| r.status >= 400 && r.status < 500).count();
    let server_err = results.iter().filter(|r| r.status >= 500 && r.status < 600).count();
    let reflected = results.iter().filter(|r| r.reflected).count();
    let errors = results.iter().filter(|r| r.error.is_some()).count();

    println!("\n===== Analysis Summary =====");
    println!("Total Results : {}", total);
    println!("2xx Success   : {}", success);
    println!("3xx Redirects : {}", redirects);
    println!("4xx ClientErr : {}", client_err);
    println!("5xx ServerErr : {}", server_err);
    println!("Reflected     : {}", reflected);
    println!("Errors        : {}", errors);
    println!("===========================\n");

    // Pretty table (first 20 results)
    println!("{:<5} {:<45} {:<8} {:<10} {:<10}", "Code", "URL", "Word", "Reflected", "Error");
    println!("{}", "-".repeat(90));
    for r in results.iter().take(20) {
        println!(
            "{:<5} {:<45} {:<8} {:<10} {:<10}",
            r.status,
            truncate(&r.url, 45),
            truncate(&r.word, 8),
            if r.reflected { "yes" } else { "" },
            r.error.as_ref().map(|e| truncate(e, 10)).unwrap_or("".to_string())
        );
    }
    if results.len() > 20 {
        println!("... ({} more rows)", results.len() - 20);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max-1]) }
}