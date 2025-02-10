# PolKA - Polynomial Key-based Architecture for Source Routing

## Developing 

Use [nix](https://nixos.org/) with [flakes enabled](https://nixos.wiki/wiki/Flakes) to build your devShell.

```bash
nix develop
```

- Use `uv run build_polka.py` to build the PolKA files.
- Use `uv run run_net.py` to run the network scripts and tests. Sudo is needed for the network scripts, so enter sudo before running the script.
