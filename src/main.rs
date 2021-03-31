use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::join;
use structopt::StructOpt;
use tokio;
use warp::Filter;

mod crypto;
mod errors;
mod handlers;
mod models;
mod onion_requests;
mod options;
mod routes;
mod rpc;
mod storage;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() {
    // Parse arguments
    let opt = options::Opt::from_args();
    let addr = SocketAddr::new(IpAddr::V4(opt.host), opt.port);
    let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
    *crypto::PRIVATE_KEY_PATH.lock().unwrap() = opt.x25519_private_key;
    *crypto::PUBLIC_KEY_PATH.lock().unwrap() = opt.x25519_public_key;
    // Print the server public key
    let hex_public_key = hex::encode(crypto::PUBLIC_KEY.as_bytes());
    println!("The public key of this server is: {}", hex_public_key);
    // Create the main database
    storage::create_main_database_if_needed();
    // Create required folders
    fs::create_dir_all("./rooms").unwrap();
    fs::create_dir_all("./files").unwrap();
    // Create default rooms
    create_default_rooms().await;
    // Set up pruning jobs
    let prune_pending_tokens_future = storage::prune_pending_tokens_periodically();
    let prune_tokens_future = storage::prune_tokens_periodically();
    let prune_files_future = storage::prune_files_periodically();
    // Serve routes
    let public_routes = routes::root().or(routes::lsrpc());
    let private_routes =
        routes::create_room().or(routes::delete_room()).or(routes::add_moderator());
    if opt.tls {
        println!("Running on {} with TLS.", addr);
        let serve_public_routes_future = warp::serve(public_routes)
            .tls()
            .cert_path(opt.tls_certificate)
            .key_path(opt.tls_private_key)
            .run(addr);
        let serve_private_routes_future = warp::serve(private_routes).run(localhost);
        // Keep futures alive
        join!(
            prune_pending_tokens_future,
            prune_tokens_future,
            prune_files_future,
            serve_public_routes_future,
            serve_private_routes_future
        );
    } else {
        println!("Running on {}.", addr);
        let serve_public_routes_future = warp::serve(public_routes).run(addr);
        let serve_private_routes_future = warp::serve(private_routes).run(localhost);
        // Keep futures alive
        join!(
            prune_pending_tokens_future,
            prune_tokens_future,
            prune_files_future,
            serve_public_routes_future,
            serve_private_routes_future
        );
    }
}

async fn create_default_rooms() {
    let info: Vec<(&str, &str)> = vec![("main", "Main")];
    for info in info {
        let id = info.0.to_string();
        let name = info.1.to_string();
        let room = models::Room { id, name, image_id: None };
        handlers::create_room(room).await.unwrap();
    }
}
