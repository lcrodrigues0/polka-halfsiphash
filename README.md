# PolKA - Polynomial Key-based Architecture for Source Routing

## Developing 

Use [nix](https://nixos.org/) with [flakes enabled](https://nixos.wiki/wiki/Flakes) to build your devShell.

```bash
nix develop
```

- Use `python3 build_polka.py` to build the PolKA files.
- Use `sudo python3 run_linear_topology.py` to run the network scripts and tests. Sudo is needed for the network scripts, so enter sudo before running the script.
