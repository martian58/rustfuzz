use clap::{Arg, Command};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, BufReader};

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
                                                
        rustfuzz - v1.0.0
        "#
    );

    let matches = Command::new("rustfuzz")
        .version("1.0.0")
        .author("Martian58")
        .about("Website fuzzer written in Rust")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .value_name("URL")
                .help("Target URL to fuzz")
                .required(true)
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("FILE")
                .help("Path to the wordlist")
                .required(true)
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("NUMBER")
                .help("Number of concurrent threads")
                .default_value("40")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("timeout")
                .short('T')
                .long("timeout")
                .value_name("SECONDS")
                .help("Request timeout in seconds")
                .default_value("10")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("status_codes")
                .short('m')
                .long("matcher")
                .value_name("CODES")
                .help("Comma-separated list of status codes to match (e.g., 200,301,302)")
                .default_value("200,301,302,401,403,405,500")
                .action(clap::ArgAction::Set),
        )
        .get_matches();

    let url = matches.get_one::<String>("url").unwrap();
    let wordlist = matches.get_one::<String>("wordlist").unwrap();
    let threads: usize = matches.get_one::<String>("threads").unwrap().parse().unwrap();
    let timeout: u64 = matches.get_one::<String>("timeout").unwrap().parse().unwrap();
    let status_codes: Vec<u16> = matches
        .get_one::<String>("status_codes")
        .unwrap()
        .split(',')
        .filter_map(|code| code.parse().ok())
        .collect();

    println!(":: Method           : GET");
    println!(":: URL              : {}", url);
    println!(":: Wordlist         : {}", wordlist);
    println!(":: Threads          : {}", threads);
    println!(":: Timeout          : {} seconds", timeout);
    println!(":: Matcher          : {:?}", status_codes);
    println!();

    // Load the wordlist
    let words = load_wordlist(wordlist).await.expect("Failed to load wordlist");

    // Initialize progress bar
    let progress_bar = ProgressBar::new(words.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    // Fuzz the target URL
    stream::iter(words)
        .map(|word| {
            let client = client.clone();
            let url = url.to_string();
            let status_codes = status_codes.clone();
            let progress_bar = progress_bar.clone();
            tokio::spawn(async move {
                if let Ok(status) = fuzz_url(&client, &url, &word).await {
                    if status_codes.contains(&status) {
                        println!("{} - {}/{}", status, url, word);
                    }
                }
                progress_bar.inc(1);
            })
        })
        .buffer_unordered(threads)
        .for_each(|_| async {})
        .await;

    progress_bar.finish_with_message("Fuzzing complete!");
}

// Load the wordlist from a file
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

// Fuzz a single URL with a word
async fn fuzz_url(client: &Client, base_url: &str, word: &str) -> Result<u16, reqwest::Error> {
    let url = format!("{}/{}", base_url, word);
    let response = client.get(&url).send().await?;
    Ok(response.status().as_u16())
}
