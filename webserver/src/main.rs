use mio::tcp::{TcpListener, TcpStream};
use mio::{Event, Events, Poll, PollOpt, Ready, Token};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::{env, process, str};
#[macro_use]
extern crate log;

const SERVER: Token = Token(0);
const WEBROOT: &str = "/webroot";

struct WebServer {
    listening_socket: TcpListener,
    connections: HashMap<usize, TcpStream>,
    next_connection_id: usize,
}

impl WebServer {
    fn new(addr: &str) -> Result<Self, failure::Error> {
        let address = addr.parse()?;
        let listening_socket = TcpListener::bind(&address)?;
        Ok(WebServer {
            listening_socket,
            connections: HashMap::new(),
            next_connection_id: 1,
        })
    }

    fn run(&mut self) -> Result<(), failure::Error> {
        let poll = Poll::new()?;
        poll.register(
            // 監視対象のソケット
            &self.listening_socket,
            //
            SERVER,
            // 監視する命令 (今回は読み込み)
            Ready::readable(),
            // エッジトリガー or レベルトリガー
            // 今回は読み込み準備完了条件を満たしている間はpoll:Poll()の呼び出しごとにイベントを発生させるのでレベルトリガー
            PollOpt::level(),
        )?;
        // イベントキュー
        let mut events = Events::with_capacity(1024);
        // レスポンス用のバッファ
        let mut response: Vec<u8> = Vec::new();
        loop {
            // イベントをポーリング
            match poll.poll(&mut events, None) {
                Ok(_) => {}
                Err(e) => {
                    error!("{}", e);
                    continue;
                }
            }

            for event in &events {
                match event.token() {
                    SERVER => {
                        let (stream, remote) = match self.listening_socket.accept() {
                            Ok(t) => t,
                            Err(e) => {
                                error!("{}", e);
                                continue;
                            }
                        };
                        debug!("Connection from {}", &remote);
                        self.register_connection(&poll, stream)
                            .unwrap_or_else(|e| error!("{}", e))
                    }
                    Token(conn_id) => {
                        self.http_handler(conn_id, event, &poll, &mut response)
                            .unwrap_or_else(|e| error!("{}", e));
                    }
                }
            }
        }
    }

    /**
     * 接続済みソケットを監視対象に登録する
     */
    fn register_connection(
        &mut self,
        poll: &Poll,
        stream: TcpStream,
    ) -> Result<(), failure::Error> {
        let token = Token(self.next_connection_id);
        // コネクション確立済みソケットに対する監視はエッジトリガーで行う
        // エッジトリガーを使うのは、一度リクエスト/レスポンスを行うとコネクションを破棄するため、
        // トークンと監視対象操作(今回は読み込み)が一致するイベントが連続して発生しないから
        poll.register(&stream, token, Ready::readable(), PollOpt::edge())?;

        if self
            .connections
            .insert(self.next_connection_id, stream)
            .is_some()
        {
            error!("Connection ID is already exists");
        }
        self.next_connection_id += 1;

        Ok(())
    }

    /**
     * 接続済ソケットで発生したイベントのハンドラ
     */
    fn http_handler(
        &mut self,
        conn_id: usize,
        event: Event,
        poll: &Poll,
        response: &mut Vec<u8>,
    ) -> Result<(), failure::Error> {
        let stream = self
            .connections
            .get_mut(&conn_id)
            .ok_or_else(|| failure::err_msg("Failed to get connection"))?;
        // 接続済ソケットから読み込み可能
        if event.readiness().is_readable() {
            debug!("readable conn_id: {}", conn_id);
            let mut buffer = [0u8; 1024];
            let nbytes = stream.read(&mut buffer)?;
            if nbytes != 0 {
                *response = make_response(&buffer[..nbytes])?;
                poll.reregister(stream, Token(conn_id), Ready::writable(), PollOpt::edge())?;
            } else {
                self.connections.remove(&conn_id);
            }
            Ok(())
        // 接続済ソケットに書き込み可能状態
        } else if event.readiness().is_writable() {
            debug!("writable conn_id: {}", conn_id);
            stream.write_all(response)?;
            self.connections.remove(&conn_id);
            Ok(())
        } else {
            Err(failure::err_msg("Undefined event."))
        }
    }
}

fn make_response(buffer: &[u8]) -> Result<Vec<u8>, failure::Error> {
    let http_pattern = Regex::new(r"(.*) (.*) HTTP/1.([0-1])\r\n.*")?;
    let captures = match http_pattern.captures(str::from_utf8(buffer)?) {
        Some(cap) => cap,
        None => {
            return create_message_from_code(400, None);
        }
    };

    let method = captures[1].to_string();
    let path = format!(
        "{}{}{}",
        env::current_dir()?.display(),
        WEBROOT,
        &captures[2]
    );
    let _version = captures[3].to_string();

    if method == "GET" {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(_) => {
                return create_message_from_code(404, None);
            }
        };
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        create_message_from_code(200, Some(buf))
    } else {
        create_message_from_code(501, None)
    }
}

fn create_message_from_code(
    status_code: u16,
    msg: Option<Vec<u8>>,
) -> Result<Vec<u8>, failure::Error> {
    match status_code {
        200 => {
            let mut header = "HTTP/1.0, 200 OK \r\nServer: mio webserver\r\n\r\n"
                .to_string()
                .into_bytes();
            if let Some(mut msg) = msg {
                header.append(&mut msg);
            }
            Ok(header)
        }
        400 => Ok(
            "HTTP/1.0, 400 Bad Request \r\nServer: mio webserver\r\n\r\n"
                .to_string()
                .into_bytes(),
        ),
        404 => Ok("HTTP/1.0, 404 Not Found \r\nServer: mio webserver\r\n\r\n"
            .to_string()
            .into_bytes()),
        501 => Ok(
            "HTTP/1.0, 501 Not Implemented \r\nServer: mio webserver\r\n\r\n"
                .to_string()
                .into_bytes(),
        ),
        _ => Err(failure::err_msg("Undefined status code")),
    }
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("wrong number of arguments");
        process::exit(1);
    }
    let mut server = WebServer::new(&args[1]).unwrap_or_else(|e| {
        error!("{}", e);
        panic!();
    });
    server.run().unwrap_or_else(|e| {
        error!("{}", e);
        panic!();
    });
}
