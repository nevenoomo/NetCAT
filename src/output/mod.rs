//! # Output module
//!
//! Provides functionality for saving measurements, gathered by `OnlineTracker`

use std::io::Result;

/// Provides interface for recording a result in the underlying storage
pub trait Record<T> {
    /// Saves data to the underlying storage
    fn record(&mut self, data: T) -> Result<()>;
}

pub mod file {
    //! Functionality for saving results into a file

    use super::Record;
    use serde::ser::Serialize;
    use serde_json::to_writer;
    use std::io::{Error, ErrorKind, Result, Write};

    /// Writes json-serialized data
    impl<T: Serialize, W: Write> Record<T> for W {
        fn record(&mut self, data: T) -> Result<()> {
            to_writer(self, &data).map_err(|e| Error::new(ErrorKind::InvalidData, e))
        }
    }
}

pub mod vec {
    use super::Record;

    /// Just pushes the data to a vector
    impl<T> Record<T> for Vec<T> {
        fn record(&mut self, data: T) -> Result<()> {
            self.push(data);
            Ok(())
        }
    }
}
