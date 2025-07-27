# How to use

These scripts automate nmap scanning across multiple hosts, and organising the results. Each script's purpose can be inferred from its name. To get the usage instructions, run them without any arguments.

# Example

```
./nmap-multi-host-discovery-only.sh 192.168.47.1/24
```

# Note

These scripts are meant to be run in `bash`, not `zsh`. Certain things break on `zsh`. If you use `zsh`, run the scripts with `bash` like:

```
bash -c "./nmap-multi-host-discovery-only.sh 192.168.47.1/24"
```


