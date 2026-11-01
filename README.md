# net-rdns-sweep
Performs a reverse DNS lookup on a range of IP addresses and reports back hostname mappings. Useful for identifying potential service names. Requires 'dnspython' - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowStrikeHQ/net-rdns-sweep`

## Usage
`./net-rdns-sweep [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided
- `-o`: No description provided
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ

## Notes
- The sweep feeds the network address iterator straight into the lookup loop, with only a small window of lookups in flight at a time, so lookups start at once and memory stays flat even for a large range.
