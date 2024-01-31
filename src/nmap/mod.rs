pub enum DiscoveryTechnique {
    Pn,
    PS(u16),
    PA(u16),
    PU(u16),
    PE,
    PP,
    PM,
    PO(u8),
    PR,
}

pub struct Nmap {
    discovery_techniques: Vec<DiscoveryTechnique>,
    resolve: bool,
    targets: Vec<String>,
}

#[derive(Debug)]
pub struct NmapResult {
    hosts: Vec<NmapResultHost>,
}

#[derive(Debug)]
pub struct NmapResultHost {
    ports: Vec<NmapResultPort>,
}

#[derive(Debug)]
pub struct NmapResultPort {
    port: u16,
    state: NmapResultPortState,
}

#[derive(Debug)]
pub enum NmapResultPortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl Nmap {
    pub fn new() -> Self {
        Self {
            discovery_techniques: vec![
                DiscoveryTechnique::PE,
                DiscoveryTechnique::PS(443),
                DiscoveryTechnique::PA(80),
                DiscoveryTechnique::PP,
            ],
            resolve: true,
            targets: vec![],
        }
    }

    pub fn set_resolve(&mut self, new_resolve: bool) -> &mut Nmap {
        self.resolve = new_resolve;
        self
    }

    pub fn set_discovery_techniques(
        &mut self,
        new_discovery_techniques: Vec<DiscoveryTechnique>,
    ) -> &mut Nmap {
        self.discovery_techniques = new_discovery_techniques;
        self
    }

    pub fn set_targets(&mut self, new_targets: Vec<String>) -> &mut Nmap {
        self.targets = new_targets;
        self
    }

    pub fn run_scan(&mut self) -> NmapResult {
        let mut command = "nmap ".to_string();

        if !self.resolve {
            command.push_str("-n ");
        }

        for dt in &self.discovery_techniques {
            let technique = match dt {
                DiscoveryTechnique::Pn => "-Pn".to_string(),
                DiscoveryTechnique::PS(port) => format!("-PS {}", port),
                DiscoveryTechnique::PA(port) => format!("-PA {}", port),
                DiscoveryTechnique::PU(port) => format!("-PU {}", port),
                DiscoveryTechnique::PE => "-PE".to_string(),
                DiscoveryTechnique::PP => "-PP".to_string(),
                DiscoveryTechnique::PM => "-PM".to_string(),
                DiscoveryTechnique::PO(protocol) => format!("-PO {}", protocol),
                DiscoveryTechnique::PR => "-PR".to_string(),
            };
            command.push_str(&format!("{} ", technique));
        }

        for t in &self.targets {
            command.push_str(&format!("{} ", t));
        }

        println!("Simulating command: '{}'", command);

        // magic
        NmapResult {
            hosts: vec![NmapResultHost {
                ports: vec![
                    NmapResultPort {
                        port: 22,
                        state: NmapResultPortState::Open,
                    },
                    NmapResultPort {
                        port: 443,
                        state: NmapResultPortState::Open,
                    },
                ],
            }],
        }
    }
}
