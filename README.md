# check-password-strength

[![CI](https://github.com/camandel/check-password-strength/actions/workflows/ci.yml/badge.svg)](https://github.com/camandel/check-password-strength/actions/workflows/ci.yml) [![Build Release](https://github.com/camandel/check-password-strength/actions/workflows/release.yml/badge.svg)](https://github.com/camandel/check-password-strength/actions/workflows/release.yml)

check-password-strength is a tool that runs on Linux, Windows and MacOS that could help you to check how your passwords are good. It reads data from a CSV file, user input or stdin and assigns a score to each password within a range from 0 (worst) to 4 (best):

```
$ check-password-strength -f password.csv
```
![img](assets/img/screenshot.jpg?raw=true)

It's based on the awesome [zxcvbn](https://github.com/dropbox/zxcvbn) library and its Go porting [zxcvbn-go](https://github.com/nbutton23/zxcvbn-go).

The passwords will be checked on:
- english words and names
- italian words and names
- common used passwords
- common keyboards sequences
- l33t substitutions
- username as part of the password
- duplicated passwords
- a custom dictionary can be loaded at runtime

It supports `CSV files` exported from the most popular Password Managers and Browsers:

- [x] LastPass
- [x] Bitwarden
- [x] Keepass
- [x] Firefox
- [x] Chrome
- [x] Custom (*)

(*) the custom CSV files must have a header with at least the following three fields: `url,username,password`

To check only one password at a time it can be used in `interactive` mode (password will not be displayed as you type):
```
$ check-password-strength -i
Enter Username: username
Enter Password: 
  URL | USERNAME | PASSWORD |   SCORE (0-4)    | ESTIMATED TIME TO CRACK | ALREADY USED   
------+----------+----------+------------------+-------------------------+---------------
      | username | p******d |  0 - Really bad  | instant                 |
```
or reading from `stdin`:
```
$ echo $PASSWORD | check-password-strength
  URL | USERNAME | PASSWORD |   SCORE (0-4)    | ESTIMATED TIME TO CRACK | ALREADY USED  
------+----------+----------+------------------+-------------------------+---------------
      |          | p******j |  4 - Strong      | centuries               |
```
If you need to use it in a script you can use `-q` flag. It will display nothing on stdout and the `exit code` will contain the password score (it works only with single password):
```
$ echo $PASSWORD | ./check-password-strength -q
$ echo $?
4
```
You can also display overall statistics about your passwords:
```
$ check-password-strength -f password.csv --stats
```
![img](assets/img/stats-screenshot.jpg?raw=true)

## Getting started

### Install

Installation of check-password-strength is simple, just download [the release for your system](https://github.com/camandel/check-password-strength/releases) and run the binary:
```
$ chmod +x check-password-strength
$ ./check-password-strength -f password.csv
```
or run it in a Docker container:
```
$ docker run --rm --net none -v $PWD:/data:ro camandel/check-password-strength -f /data/password.csv
```

### Building from source

```
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
$ check-password-strength -h
NAME:
   check-password-strength - Check the passwords strength from csv file, console or stdin

USAGE:
   check-password-strength [options]

VERSION:
   v0.0.6

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --filename CSVFILE, -f CSVFILE      Check passwords from CSVFILE
   --customdict JSONFILE, -c JSONFILE  Load custom dictionary from JSONFILE
   --interactive, -i                   enable interactive mode asking data from console (default: false)
   --stats, -s                         display only statistics (default: false)
   --quiet, -q                         return score as exit code (valid only with single password) (default: false)
   --limit value, -l value             Limit output based on score [0-4] (valid only with csv file) (default: 4)
   --debug, -d                         show debug logs (default: false)
   --help, -h                          show help (default: false)
   --version, -v                       print the version (default: false)
```

## How to add custom dictionary
If you need to add your custom dictionary to the integrated ones, create one json file in the following format:

```json
{
    "words": [
        "foo",
        "bar",
        "baz",
    ]
}
```
and load it at runtime with the `-c` flag:
```
$ check-password-strength -c customdict.json -f password.csv
```
Or add it directly into the binary copying the json file in `assets/data` and recompile.
