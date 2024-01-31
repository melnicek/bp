## Example

```
user@bp:~/bp$ cargo run
Simulating command: 'nmap -PE -PS 443 -PA 80 -PP sk-nic.sk muni.cz '
NmapResult {
    hosts: [
        NmapResultHost {
            ports: [
                NmapResultPort {
                    port: 22,
                    state: Open,
                },
                NmapResultPort {
                    port: 443,
                    state: Open,
                },
            ],
        },
    ],
}
```