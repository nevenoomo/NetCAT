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

    /// Outputs data in JSON format to the underlying writer
    pub struct JsonRecorder<W: Write>(W);

    impl<W: Write> JsonRecorder<W> {
        /// Wraps provided value in `JsonRecorder`
        pub fn new(w: W) -> JsonRecorder<W> {
            JsonRecorder(w)
        }

        /// Unwraps this `JsonRecorder<W>`, returns the underlying writer.
        pub fn into_inner(self) -> Result<W> {
            Ok(self.0)
        }
    }

    impl<W: Write> Write for JsonRecorder<W> {
        // IDEA maybe add json validation
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.write(buf) 
        }

        fn flush(&mut self) -> Result<()> {
            self.0.flush()
        }
    }

    /// Writes json-serialized data
    impl<T: Serialize, W: Write> Record<T> for JsonRecorder<W> {
        fn record(&mut self, data: T) -> Result<()> {
            to_writer(self, &data).map_err(|e| Error::new(ErrorKind::InvalidData, e))
        }
    }
}

pub mod vec {
    use super::Record;
    use std::io::Result;

    /// Just pushes the data to a vector
    impl<T> Record<T> for Vec<T> {
        fn record(&mut self, data: T) -> Result<()> {
            self.push(data);
            Ok(())
        }
    }
}
