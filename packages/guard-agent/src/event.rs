//! Events the agent sends, matching what the Guard server accepts (endpoint.mjs sanitizeEvents).
use serde::Serialize;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Clone, Debug, Default)]
pub struct Parent {
    pub name: String,
    pub pid: u32,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<Parent>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Persistence {
    pub kind: String,
    pub name: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Logon {
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub user: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistence: Option<Persistence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon: Option<Logon>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl Event {
    pub fn new(kind: &str) -> Self {
        let at = crate::util::now_ms();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        Event { id: format!("{at:x}-{seq:x}"), kind: kind.to_string(), at, ..Default::default() }
    }
}

/// Bounded outgoing queue. When the server is unreachable for a long time the oldest events are
/// dropped first, so memory stays inside the agent's budget.
pub struct Queue {
    items: Mutex<Vec<Event>>,
    cap: usize,
    dropped: AtomicU64,
}

impl Queue {
    pub fn new(cap: usize) -> Self {
        Queue { items: Mutex::new(Vec::new()), cap, dropped: AtomicU64::new(0) }
    }
    pub fn push(&self, event: Event) {
        let mut items = self.items.lock().unwrap();
        if items.len() >= self.cap {
            items.remove(0);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        items.push(event);
    }
    pub fn take(&self, max: usize) -> Vec<Event> {
        let mut items = self.items.lock().unwrap();
        let n = items.len().min(max);
        items.drain(..n).collect()
    }
    /// Puts a batch back at the front after a failed upload.
    pub fn restore(&self, mut batch: Vec<Event>) {
        let mut items = self.items.lock().unwrap();
        batch.append(&mut items);
        let overflow = batch.len().saturating_sub(self.cap);
        *items = batch.split_off(overflow);
    }
    pub fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_is_bounded_and_restores_in_order() {
        let q = Queue::new(3);
        for i in 0..5 {
            let mut e = Event::new("process.start");
            e.id = i.to_string();
            q.push(e);
        }
        let batch = q.take(10);
        assert_eq!(batch.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["2", "3", "4"]);
        q.restore(batch);
        assert_eq!(q.len(), 3);
        let json = serde_json::to_string(&q.take(1)[0]).unwrap();
        assert!(json.contains("\"type\":\"process.start\""));
        assert!(!json.contains("process\":"), "empty sections are omitted");
    }

    #[test]
    fn file_info_uses_server_field_names() {
        let mut e = Event::new("file.rename");
        e.file = Some(FileInfo { path: "a.locked".into(), old_path: Some("a.docx".into()), ..Default::default() });
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"oldPath\":\"a.docx\""));
    }
}
