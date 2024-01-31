mod nmap;
use nmap::Nmap;

fn main() {
    let mut scanner = Nmap::new();

    let scanner = scanner.set_targets(vec!["sk-nic.sk".to_string(), "muni.cz".to_string()]);

    let result = scanner.run_scan();

    println!("{:#?}", result);
}
