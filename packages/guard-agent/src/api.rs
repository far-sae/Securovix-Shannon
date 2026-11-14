//! HTTPS client for the Guard server (/api/endpoint-agent/v1). TLS via rustls; the server
//! certificate is verified against the bundled Mozilla roots.
use crate::config::Policy;
use crate::event::Event;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Deserialize, Debug, Clone)]
pub struct Command {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub params: Value,
    #[serde(rename = "undoData", default)]
    pub undo_data: Value,
}

#[derive(Deserialize, Debug, Default)]
pub struct HashUpdate {
    pub version: u64,
    pub list: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct CheckIn {
    #[serde(default)]
    pub commands: Vec<Command>,
    #[serde(default)]
    pub policy: Option<Policy>,
    #[serde(default)]
    pub hashes: Option<HashUpdate>,
}

#[derive(Deserialize, Debug)]
pub struct Enrolled {
    #[serde(rename = "agentId")]
    pub agent_id: String,
    pub token: String,
    pub policy: Policy,
}

pub struct Client {
    base: String,
    token: String,
    http: ureq::Agent,
}

fn describe(err: ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            let reason = serde_json::from_str::<Value>(&body).ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from));
            format!("server answered {code}: {}", reason.unwrap_or(body))
        }
        other => other.to_string(),
    }
}

impl Client {
    pub fn new(server: &str, token: &str) -> Client {
        let http = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout(Duration::from_secs(60)).user_agent(concat!("securovix-guard/", env!("CARGO_PKG_VERSION"))).build();
        Client { base: format!("{}/api/endpoint-agent/v1", server.trim_end_matches('/')), token: token.to_string(), http }
    }

    fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let mut req = self.http.post(&format!("{}{}", self.base, path));
        if !self.token.is_empty() {
            req = req.set("authorization", &format!("Bearer {}", self.token));
        }
        req.send_json(body).map_err(describe)?.into_json::<Value>().map_err(|e| e.to_string())
    }

    pub fn enroll(&self, enroll_token: &str, hostname: &str, machine_id: &str) -> Result<Enrolled, String> {
        let body = json!({
            "token": enroll_token,
            "hostname": hostname,
            "os": std::env::consts::OS,
            "osVersion": sysinfo::System::long_os_version().unwrap_or_default(),
            "arch": std::env::consts::ARCH,
            "version": env!("CARGO_PKG_VERSION"),
            "machineId": machine_id,
        });
        serde_json::from_value(self.post("/enroll", body)?).map_err(|e| e.to_string())
    }

    pub fn check_in(&self, body: Value) -> Result<CheckIn, String> {
        serde_json::from_value(self.post("/checkin", body)?).map_err(|e| e.to_string())
    }

    pub fn send_events(&self, events: &[Event]) -> Result<Value, String> {
        self.post("/events", json!({ "events": events }))
    }

    pub fn send_result(&self, command_id: &str, ok: bool, detail: &str, data: Value) -> Result<(), String> {
        self.post("/results", json!({ "commandId": command_id, "ok": ok, "detail": detail, "data": data })).map(|_| ())
    }

    pub fn upload_sample(&self, bytes: &[u8], file_name: &str, sha256: &str, command_id: Option<&str>) -> Result<Value, String> {
        let encoded: String = file_name.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
        let mut req = self
            .http
            .post(&format!("{}/samples", self.base))
            .set("authorization", &format!("Bearer {}", self.token))
            .set("content-type", "application/octet-stream")
            .set("x-sha256", sha256)
            .set("x-file-name", &encoded);
        if let Some(id) = command_id {
            req = req.set("x-command-id", id);
        }
        req.send_bytes(bytes).map_err(describe)?.into_json::<Value>().map_err(|e| e.to_string())
    }
}
