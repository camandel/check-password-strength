package cmd

import (
	"errors"
	"os"

	"github.com/urfave/cli/v2"
)

var log = New(Level).Sugar()

// Execute main function
func Execute() {

	var interactive, stats, quiet, debug bool
	var username, filename, customDict string
	var limit int

	app := &cli.App{
		Name:      "check-password-strength",
		Usage:     "Check the passwords strength from csv file, console or stdin",
		UsageText: "check-password-strength [options]",
		Version:   Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "filename",
				Aliases:     []string{"f"},
				Usage:       "Check passwords from `CSVFILE`",
				Destination: &filename,
			},
			&cli.StringFlag{
				Name:        "customdict",
				Aliases:     []string{"c"},
				Usage:       "Load custom dictionary from `FILE` (json, txt or lst)",
				Destination: &customDict,
			},
			&cli.BoolFlag{
				Name:        "interactive",
				Aliases:     []string{"i"},
				Destination: &interactive,
				Value:       false,
				Usage:       "enable interactive mode asking data from console",
			},
			&cli.BoolFlag{
				Name:        "stats",
				Aliases:     []string{"s"},
				Destination: &stats,
				Value:       false,
				Usage:       "display only statistics",
			},
			&cli.BoolFlag{
				Name:        "quiet",
				Aliases:     []string{"q"},
				Destination: &quiet,
				Value:       false,
				Usage:       "return score as exit code (valid only with single password)",
			},
			&cli.IntFlag{
				Name:        "limit",
				Aliases:     []string{"l"},
				Usage:       "Limit output based on score [0-4] (valid only with csv file)",
				Value:       4,
				Destination: &limit,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Aliases:     []string{"d"},
				Destination: &debug,
				Value:       false,
				Usage:       "show debug logs",
			},
		},
		HideHelpCommand: false,
		Action: func(c *cli.Context) error {

			if debug {
				Level.SetLevel(DebugLevel)
			}

			password, err := getPwdStdin()
			if err != nil && !interactive && filename == "" {
				cli.ShowAppHelpAndExit(c, -1)
			}

			log.Debugf("password from pipe: %s", redactPassword(password))

			if filename != "" && interactive {
				return errors.New("can not use '-f' and '-i' flags at the same time")
			}
			if filename != "" && password != "" {
				return errors.New("can not use '-f' flag and read from stdin")
			}
			if interactive && password != "" {
				return errors.New("can not use '-i' flag and read from stdin")
			}
			if quiet && filename != "" {
				return errors.New("flag '-q' can be used only with '-i' flag or read from stdin")
			}
			if interactive && c.IsSet("limit") {
				return errors.New("flag '-l' can be used only with '-f' flag")
			}
			if c.IsSet("limit") && (limit < 0 || limit > 4) {
				return errors.New("show only passwords with score less than value (must be between 0 and 4)")
			}
			if interactive {
				username, password, err = askUsernamePassword()
				if err != nil {
					return err
				}
			}

			if filename != "" {
				return checkMultiplePassword(filename, customDict, stats, limit)
			}
			return checkSinglePassword(username, password, customDict, quiet, stats)

		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
