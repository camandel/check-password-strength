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
				Usage:       "Load custom dictionary from `JSONFILE`",
				Destination: &customDict,
			},
			&cli.BoolFlag{Name: "interactive",
				Aliases:     []string{"i"},
				Destination: &interactive,
				Value:       false,
				Usage:       "enable interactive mode asking data from console"},
			&cli.BoolFlag{Name: "stats",
				Aliases:     []string{"s"},
				Destination: &stats,
				Value:       false,
				Usage:       "display only statistics"},
			&cli.BoolFlag{Name: "quiet",
				Aliases:     []string{"q"},
				Destination: &quiet,
				Value:       false,
				Usage:       "return score as exit code (valid only with single password)"},
			&cli.BoolFlag{Name: "debug",
				Aliases:     []string{"d"},
				Destination: &debug,
				Value:       false,
				Usage:       "show debug logs"},
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
				return errors.New("Can not use '-f' and '-i' flags at the same time")
			}
			if filename != "" && password != "" {
				return errors.New("Can not use '-f' flag and read from stdin")
			}
			if interactive && password != "" {
				return errors.New("Can not use '-i' flag and read from stdin")
			}
			if quiet && filename != "" {
				return errors.New("Flag '-q' can be used only with '-i' flag or read from stdin")
			}
			if interactive {
				username, password, err = askUsernamePassword()
				if err != nil {
					return err
				}
			}

			if filename != "" {
				return checkMultiplePassword(filename, customDict, interactive, stats)
			}
			return checkSinglePassword(username, password, customDict, quiet, stats)

		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
