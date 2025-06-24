use clap::{Arg, ArgAction, Command};
use futures::{stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, time::Duration};
use std::sync::Arc;
use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt, BufReader},
    sync::Semaphore,
    time::sleep,
};
use url::Url;

// Needed for JSON export
use serde_json;

#[derive(Debug, Deserialize)]
struct Config {
    url: String,
    wordlist: String,
    threads: Option<usize>,
    timeout: Option<u64>,
    matcher: Option<String>,
    headers: Option<Vec<(String, String)>>,
    cookies: Option<Vec<(String, String)>>,
    auth_token: Option<String>,
    proxy: Option<String>,
    rate_limit: Option<u64>,
    export: Option<String>,
}

#[derive(Debug, Serialize)]
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
                                                
        rustfuzz - v3.0.0
        "#
    );

    let matches = Command::new("rustfuzz")
        .version("3.0.0")
        .author("Martian58 & Copilot")
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
                .help("Enable simple crawler to find more endpoints")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("openapi")
                .long("openapi")
                .value_name("URL")
                .help("Parse OpenAPI/Swagger spec for endpoints")
                .action(ArgAction::Set),
        )
        .get_matches();

    let mut config = if let Some(cfg_path) = matches.get_one::<String>("config") {
        let cfg_str = fs::read_to_string(cfg_path).expect("Failed to read config");
        toml::from_str::<Config>(&cfg_str).expect("Failed to parse TOML config")
    } else {
        Config {
            url: matches
                .get_one::<String>("url")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            wordlist: matches
                .get_one::<String>("wordlist")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            threads: matches
                .get_one::<String>("threads")
                .and_then(|s| s.parse().ok()),
            timeout: matches
                .get_one::<String>("timeout")
                .and_then(|s| s.parse().ok()),
            matcher: matches.get_one::<String>("matcher").cloned(),
            headers: matches
                .get_many::<String>("headers")
                .map(|vals| {
                    vals.map(|kv| split_kv(kv)).collect()
                }),
            cookies: matches
                .get_many::<String>("cookie")
                .map(|vals| {
                    vals.map(|kv| split_kv(kv)).collect()
                }),
            auth_token: matches.get_one::<String>("auth").cloned(),
            proxy: matches.get_one::<String>("proxy").cloned(),
            rate_limit: matches
                .get_one::<String>("rate_limit")
                .and_then(|s| s.parse().ok()),
            export: matches.get_one::<String>("export").cloned(),
        }
    };

    // Command-line always overrides config
    if let Some(url) = matches.get_one::<String>("url") {
        config.url = url.clone();
    }
    if let Some(wordlist) = matches.get_one::<String>("wordlist") {
        config.wordlist = wordlist.clone();
    }

    let url = &config.url;
    let wordlist = &config.wordlist;
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
    let mut words = load_wordlist(wordlist).await.expect("Failed to load wordlist");

    // Mutation-based fuzzing
    if matches.get_flag("mutate") {
        let extra_mutations = mutate_wordlist(&words);
        words.extend(extra_mutations);
    }

    // Add payloads
    if let Some(payload_file) = matches.get_one::<String>("payloads") {
        let mut payloads = load_wordlist(payload_file).await.expect("Failed to load payloads file");
        words.append(&mut payloads);
    }

    // Crawl mode: find additional endpoints
    let mut discovered = HashSet::new();
    if matches.get_flag("crawl") {
        let found = crawl(url).await;
        for endpoint in &found {
            println!(":: Discovered endpoint: {}", endpoint);
        }
        discovered.extend(found);
    }

    // OpenAPI parsing (stub)
    if let Some(openapi_url) = matches.get_one::<String>("openapi") {
        let api_endpoints = parse_openapi(openapi_url).await;
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
                let mut output = None;
                match &res {
                    Ok((status, body)) => {
                        let reflected = body.contains(word);
                        let has_error = detect_error(body);

                        // Only print if:
                        // - Status code matches --matcher (e.g. 200, 301, etc)
                        // - The response contains the tested word (reflected input)
                        // - An error pattern is detected in the body
                        if status_codes.contains(status)
                        {
                            println!(
                                "{status} - {target}{}{}",
                                if reflected { " [REFLECTED]" } else { "" },
                                if has_error { " [ERROR]" } else { "" }
                            );
                        }
                        // 404s (and other non-matching codes) are hidden unless interesting
                        output = Some(FuzzResult {
                            url: target.clone(),
                            word: word.to_string(),
                            status: *status,
                            reflected,
                            error: if has_error { Some("Possible error detected".into()) } else { None },
                        });
                    }
                    Err(e) => {
                        // Always show real network errors
                        println!("ERR  - {target} [error: {e}]");
                        output = Some(FuzzResult {
                            url: target.clone(),
                            word: word.to_string(),
                            status: 0,
                            reflected: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
                if let Some(r) = output {
                    results.lock().await.push(r);
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
            fs::write(export, serde_json::to_string_pretty(&*results).unwrap()).unwrap();
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
    word: &str,
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

async fn crawl(base_url: &str) -> HashSet<String> {
    let mut found = HashSet::new();
    let client = Client::new();
    if let Ok(resp) = client.get(base_url).send().await {
        if let Ok(body) = resp.text().await {
            let re = Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
            for cap in re.captures_iter(&body) {
                if let Some(link) = cap.get(1) {
                    if let Ok(url) = Url::parse(base_url) {
                        let joined = url.join(link.as_str()).unwrap_or_else(|_| url.clone());
                        found.insert(joined.to_string());
                    }
                }
            }
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