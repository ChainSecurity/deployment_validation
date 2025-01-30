use actix_web::{web, web::get, web::post, App, HttpRequest, HttpServer, Responder};
use alloy::primitives::keccak256;
use clap::{value_parser, Arg, Command};
use reqwest::header::HeaderValue;
use reqwest::{header::HeaderMap, header::HeaderName, Url};
use serde_json::Value;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;

struct AppState {
    url: String,
    cachedir: String,
    verbose: u8,
}

async fn generic_function(
    data: web::Bytes,
    req: HttpRequest,
    state: web::Data<Mutex<AppState>>,
) -> impl Responder {
    let (url, cachedir, verbose) = {
        let state = state.lock().unwrap();
        (state.url.clone(), state.cachedir.clone(), state.verbose)
    };
    let method = req.method().clone();

    if verbose > 1 {
        println!(
            "Request: {:?}, Data {:?}, Query: {:?}",
            req,
            data,
            req.query_string()
        );
    }

    // Capture headers from the incoming request
    let mut headers = HeaderMap::new();
    for (key, value) in req.headers().iter() {
        if key.as_str().contains("api-key") || key.as_str().contains("content") {
            headers.insert(
                HeaderName::from_bytes(key.as_str().as_bytes()).unwrap(),
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
    }

    let fname = get_fname(&data, req.query_string().as_bytes(), &cachedir);
    if Path::new(&fname).exists() {
        if verbose > 0 {
            println!("Served {:?} from cache: {}", data, fname);
        }
        let mut file = File::open(fname).unwrap();
        let mut saved = Vec::new();
        file.read_to_end(&mut saved).unwrap();
        let response: Value = serde_json::from_slice(&saved).unwrap();
        return web::Json(response);
    }

    // If we are running in test mode, answer no non-cached queries
    if url.len() < 2 {
        return web::Json("".into());
    }

    // Generate Query Pairs out of query string
    let mut dummyurl = Url::parse("https://example.com/api").unwrap();
    dummyurl.set_query(Some(req.query_string()));

    // Convert query pairs into a vector of tuples
    let query_pairs: Vec<(String, String)> = dummyurl.query_pairs().into_owned().collect();

    let client = reqwest::Client::new();
    let response = match method.as_str() {
        "GET" => client
            .get(&url)
            .headers(headers)
            .query(&query_pairs)
            .body(data.to_vec())
            .send()
            .await
            .unwrap(),
        "POST" => client
            .post(&url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .unwrap(),
        _ => panic!("Unsupported HTTP method"),
    };

    let response_text = response.text().await.unwrap();
    if verbose > 1 {
        println!("Response: {:?}", response_text);
    }
    let response_json: Value = serde_json::from_str(&response_text).unwrap();

    // Cache the response
    let mut file = File::create(&fname).unwrap();
    file.write_all(response_text.as_bytes()).unwrap();

    if data.len() > 100 {
        println!("Saved long data for {:?} in cache", data);
    } else {
        println!("Saved {:?} for {:?} in cache", response_json, data);
    }

    web::Json(response_json)
}

// TODO: Dedup these functions
async fn generic_path_function<T: AsRef<str> + std::fmt::Display>(
    path: web::Path<T>,
    data: web::Bytes,
    req: HttpRequest,
    state: web::Data<Mutex<AppState>>,
) -> impl Responder {
    let (url, cachedir, verbose) = {
        let state = state.lock().unwrap();
        (state.url.clone(), state.cachedir.clone(), state.verbose)
    };
    let method = req.method().clone();

    let path_str = format!("{}", path.as_ref());
    let url = if path_str.len() > 1 {
        format!("{url}/{path_str}")
    } else {
        url
    };

    if verbose > 1 {
        println!(
            "Request: {:?}, Data {:?}, Query: {:?}",
            req,
            data,
            req.query_string()
        );
    }

    // Capture headers from the incoming request
    let mut headers = HeaderMap::new();
    for (key, value) in req.headers().iter() {
        if key.as_str().contains("api-key") || key.as_str().contains("content") {
            headers.insert(
                HeaderName::from_bytes(key.as_str().as_bytes()).unwrap(),
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
    }

    // TODO: Use the path here
    let fname = get_fname(&data, req.query_string().as_bytes(), &cachedir);
    if Path::new(&fname).exists() {
        if verbose > 0 {
            println!("Served {:?} from cache: {}", data, fname);
        }
        let mut file = File::open(fname).unwrap();
        let mut saved = Vec::new();
        file.read_to_end(&mut saved).unwrap();
        let response: Value = serde_json::from_slice(&saved).unwrap();
        return web::Json(response);
    }

    // If we are running in test mode, answer no non-cached queries
    if url.len() < 2 {
        return web::Json("".into());
    }

    // Generate Query Pairs out of query string
    let mut dummyurl = Url::parse("https://example.com/api").unwrap();
    dummyurl.set_query(Some(req.query_string()));

    // Convert query pairs into a vector of tuples
    let query_pairs: Vec<(String, String)> = dummyurl.query_pairs().into_owned().collect();

    let client = reqwest::Client::new();
    let response = match method.as_str() {
        "GET" => client
            .get(&url)
            .headers(headers)
            .query(&query_pairs)
            .body(data.to_vec())
            .send()
            .await
            .unwrap(),
        "POST" => client
            .post(&url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .unwrap(),
        _ => panic!("Unsupported HTTP method"),
    };

    let response_text = response.text().await.unwrap();
    if verbose > 1 {
        println!("Response: {:?}", response_text);
    }
    let response_json: Value = serde_json::from_str(&response_text).unwrap();

    // Cache the response
    let mut file = File::create(&fname).unwrap();
    file.write_all(response_text.as_bytes()).unwrap();

    if data.len() > 100 {
        println!("Saved long data for {:?} in cache", data);
    } else {
        println!("Saved {:?} for {:?} in cache", response_json, data);
    }

    web::Json(response_json)
}

fn get_fname(data: &[u8], query: &[u8], cachedir: &str) -> String {
    let mut vec3: Vec<u8> = data.to_vec();
    vec3.extend(query);
    let res = keccak256(vec3);
    format!("{}/{}", cachedir, hex::encode(res))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let matches = Command::new("rpcproxy")
        .about("Cache RPC results")
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(clap::ArgAction::Count),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .default_value("5000")
                .value_parser(value_parser!(u16)),
        )
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .value_name("URL")
                .default_value(""),
        )
        .arg(
            Arg::new("cachedir")
                .short('d')
                .long("cachedir")
                .value_name("CACHEDIR")
                .required(true),
        )
        .get_matches();

    let port: u16 = *matches.get_one::<u16>("port").unwrap();
    let url = matches.get_one::<String>("url").unwrap().to_string();
    let cachedir = matches.get_one::<String>("cachedir").unwrap().to_string();

    create_dir_all(&cachedir)?;

    println!("Port: {}", port);
    println!("URL: {}", url);
    println!("Cache Directory: {}", cachedir);

    let state = web::Data::new(Mutex::new(AppState {
        url,
        cachedir,
        verbose: matches.get_count("verbose"),
    }));

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(
                web::resource("/{generic_path}")
                    .route(get().to(generic_path_function::<String>))
                    .route(post().to(generic_path_function::<String>)),
            )
            .service(
                web::resource("/")
                    .route(get().to(generic_function))
                    .route(post().to(generic_function)),
            )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
