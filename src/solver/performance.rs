use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceResourceEntry {
    #[serde(rename = "t")]
    pub r#type: String, // r
    #[serde(rename = "dlt")]
    pub time_taken: f64,
    #[serde(rename = "i")]
    pub initiator_type: String,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "nh")]
    pub next_hop_protocol: String,
    #[serde(rename = "ts")]
    pub transfer_size: usize,
    #[serde(rename = "bs")]
    pub encoded_body_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceNavigationEntry {
    #[serde(rename = "t")]
    pub r#type: String, // n
    #[serde(rename = "i")]
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceVisibilityStateEntry {
    #[serde(rename = "t")]
    pub r#type: String, // v
    #[serde(rename = "s")]
    pub start_time: i32,
    #[serde(rename = "d")]
    pub duration: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformancePaintEntry {
    #[serde(rename = "t")]
    pub r#type: String, // p
    #[serde(rename = "i")]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceLongFrameEntry {
    #[serde(rename = "t")]
    pub r#type: String, // lf
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRenderEntry {
    #[serde(rename = "t")]
    pub r#type: String, // o
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceFirstInputEntry {
    #[serde(rename = "t")]
    pub r#type: String, // f
    #[serde(rename = "s")]
    pub entry_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMarkEntry {
    #[serde(rename = "t")]
    pub r#type: String, // m
    #[serde(rename = "n")]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub enum PerformanceEntry {
    Resource(PerformanceResourceEntry),
    VisibilityState(PerformanceVisibilityStateEntry),
    Paint(PerformancePaintEntry),
    LongFrame(PerformanceLongFrameEntry),
    Mark(PerformanceMarkEntry),
}

impl Serialize for PerformanceEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PerformanceEntry::Resource(entry) => entry.serialize(serializer),
            PerformanceEntry::VisibilityState(entry) => entry.serialize(serializer),
            PerformanceEntry::Paint(entry) => entry.serialize(serializer),
            PerformanceEntry::LongFrame(entry) => entry.serialize(serializer),
            PerformanceEntry::Mark(entry) => entry.serialize(serializer),
        }
    }
}

#[derive(Default)]
pub struct Performance {
    pub entries: Vec<PerformanceEntry>,
}

impl Performance {
    pub fn serialize(&self) -> serde_json::Value {
        serde_json::to_value(&self.entries).unwrap()
    }

    pub fn add_entry(&mut self, entry: PerformanceEntry) {
        self.entries.push(entry);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn add_long_frame(&mut self) {
        self.entries.push(PerformanceEntry::LongFrame(PerformanceLongFrameEntry {
            r#type: "lf".to_string(),
        }));
    }
}