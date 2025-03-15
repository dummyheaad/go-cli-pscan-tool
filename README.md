# Port Scanner Tool CLI App
A simple CLI App that can be used to perform TCP port scanning on a specified host

## How to Install
### Clone the repository

    git clone https://github.com/dummyheaad/go-cli-pscan-tool

### Build the executable

    go build .

## Functionalities
### Adding a host for port scanning (output will be saved in .pScan.hosts file)

    ./pScan.exe hosts add HOSTNAME

### Perform port scanning from a file (default file will be .pScan.hosts file)

    ./pScan.exe scan --ports PORTS

Note:
- the default PORTS used for scanning are 22, 80, and 443
- PORTS can be speficied as comma separated value (e.g 80,443)
- PORTS can also be speficied in format a-b (e.g 1-20)

### Explore ./docs for more usage

## Examples
    ./pScan.exe hosts add localhost
    ./pScan.exe scan --ports 22,443,8080
    Output:
    localhost:
        22: closed
        80: closed
        443: closed