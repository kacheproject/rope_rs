use std::sync::Once;
use simple_logger::SimpleLogger;

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| {
        SimpleLogger::new().with_level(log::LevelFilter::Trace).init().unwrap();
    });
}
