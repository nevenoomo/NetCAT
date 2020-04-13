use crate::online_tracker::{Time, SavedLats};

/// Extracts timestamps from the data from Online Tracker
pub fn extract(data: SavedLats) -> Vec<Time> {
    data.into_iter().map(|(_, _, t)| t).collect()
}