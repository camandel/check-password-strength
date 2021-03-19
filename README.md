# check-password-strength

[![CI](https://github.com/camandel/check-password-strength/actions/workflows/ci.yml/badge.svg)](https://github.com/camandel/check-password-strength/actions/workflows/ci.yml) [![Build Release](https://github.com/camandel/check-password-strength/actions/workflows/release.yml/badge.svg)](https://github.com/camandel/check-password-strength/actions/workflows/release.yml)

check-password-strength is an open-source tool that could help you to check how your passwords are good. It reads a CSV file and assigns a score to each password within a range from 0 (worst) to 4 (best):

```bash
$ ./check-password-strength password.csv
```
![img](assets/img/screenshot.jpg?raw=true)

It supports CSV files from exported from the most popular Password Managers and Browsers and runs on Linux, Windows and MacOS.

It's based on the awesome [zxcvbn](https://github.com/dropbox/zxcvbn) library and its Go porting [zxcvbn-go](github.com/nbutton23/zxcvbn-go).

The passwords will be checked on:
- english words and names
- italian words and names
- common used passwords
- common keyboards sequences
- l33t substitutions
- username as part of the password

## Suppoted CSV file formats

- [x] LastPass
- [x] Bitwarden
- [x] Keepass
- [x] Firefox
- [x] Chrome
- [x] Custom (*)

(*) the custom CSV files must have a header with at least the following three fields: `url,username,password`

## Getting started

### Install

Installation of check-password-strength is simple, just download [the release for your system](https://github.com/camandel/check-password-strength/releases) and run the binary passing a CSV file:
```bash
$ chmod +x ./check-password-strength
$ ./check-password-strength password.csv
```
or run it in a Docker container:
```
$ docker run --rm --net none -v $PWD:/data:ro camandel/check-password-strength /data/password.csv
```

### Building from source

```shell linux
$ git clone https://github.com/camandel/check-password-strength

$ cd check-password-strength

$ # it compiles for current OS and ARCH
$ make
```
#### For Linux

```shell linux
$ make linux-64
```
#### For MacOS

```shell linux
$ make macos-64
```
#### For Windows

```shell
$ make windows-32
```
or 
```shell
$ make windows-64
```
#### For Docker image

````shell linux
$ make docker
````
It will create a local image called `check-password-strength:latest`

### Run

You can use command line or the Docker image:

```
$ ./check-password-strength --help
NAME:
   check-password-strength - Check the passwords strength from csv file

USAGE:
   check-password-strength [--debug] CSVFILE

VERSION:
   v0.0.1

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d    show debug logs (default: false)
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

## How to add custom dictionaries
If you need to add your custom dictionaries create one ore more json file in `assets/data/' with the following format:

```json
{
    "list": [
        "foo",
        "bar",
    ]
}
```
and recompile.
