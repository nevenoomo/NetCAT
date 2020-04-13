use clap::{crate_authors, crate_version, App, Arg};
use std::net::IpAddr;
use std::str::FromStr;

fn main() {
    let matches = App::new("NetCAT PoC")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Implementation of the Network Cache Attack (CVE-2019-11184)")
        .arg(
            Arg::with_name("connection")
                .long("conn")
                .short("c")
                .value_name("CONNECTION_TYPE")
                .possible_values(&["rdma", "local"])
                .help("Sets the connection type")
        )
        .arg(
            Arg::with_name("adress")
                .help("Victim server adress")
                .long("addr")
                .short("a")
                .takes_value(true)
                .required_if("conneciton", "rdma")
                .value_name("IP_ADDR")
                .validator(|x| match IpAddr::from_str(x.as_str()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Faulty IP adress")),
                })
        )
        .arg(Arg::from_usage(
            "[interactive] -i --interactive 'Sets the program into interactive mode'",
        ))
        .arg(Arg::with_name("output").help("A file to dump gathered data to"))
        .get_matches();

    if matches.is_present("interactive") {
        interactive::run_session(matches);
    } else {
        uninteractive::run_session(matches);
    }
}

mod interactive {
    use clap::ArgMatches;

    pub fn run_session(args: ArgMatches) {
        println!("I am interactive");
    }
}

mod uninteractive {
    use clap::ArgMatches;

    pub fn run_session(args: ArgMatches) {
        println!("I am uninteractive");
    }
}
