package bootstrap

import (
	"errors"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
)

// Finalizer is implemented by configs and commands that need a pass over the
// parsed values, e.g. to derive one option from another. It runs before the
// config is handed out or the command executes; its error aborts parsing.
type Finalizer interface {
	Finalize() error
}

// Command is a subcommand: Options is the struct go-flags fills in, and its
// Execute runs the command once the command line has parsed.
type Command struct {
	Name        string
	Description string
	Options     flags.Commander
}

// CommandError carries the error a subcommand returned, so a caller can tell
// a command that ran and failed from a command line that did not parse.
type CommandError struct {
	Err error
}

func (e *CommandError) Error() string { return e.Err.Error() }
func (e *CommandError) Unwrap() error { return e.Err }

func ParseConfig[T any]() (*T, error) {
	var config T
	if err := parse(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func MustParseConfig[T any]() *T {
	config, err := ParseConfig[T]()
	if err != nil {
		exit(err)
	}

	return config
}

// RunCommand parses the command line, picks one of commands and executes it.
// A failed command comes back wrapped in CommandError.
func RunCommand(commands ...Command) error {
	return parse(&struct{}{}, commands...)
}

func MustRunCommand(commands ...Command) {
	if err := RunCommand(commands...); err != nil {
		exit(err)
	}
}

func parse(config any, commands ...Command) error {
	parser := flags.NewParser(config, flags.PassDoubleDash|flags.HelpFlag)
	for _, command := range commands {
		if _, err := parser.AddCommand(command.Name, command.Description, command.Description, command.Options); err != nil {
			return fmt.Errorf("can't register command %q: %w", command.Name, err)
		}
	}

	parser.CommandHandler = func(command flags.Commander, args []string) error {
		if err := finalize(config); err != nil {
			return err
		}
		if command == nil {
			return nil
		}
		if err := finalize(command); err != nil {
			return err
		}
		if err := command.Execute(args); err != nil {
			return &CommandError{Err: err}
		}
		return nil
	}

	if _, err := parser.Parse(); err != nil {
		return err //nolint:wrapcheck // go-flags errors are the message shown to the user
	}

	return nil
}

func finalize(target any) error {
	finalizer, ok := target.(Finalizer)
	if !ok {
		return nil
	}
	if err := finalizer.Finalize(); err != nil {
		return fmt.Errorf("can't finalize config: %w", err)
	}

	return nil
}

func exit(err error) {
	if commandErr := (&CommandError{}); errors.As(err, &commandErr) {
		// Addressed to the person at the terminal; it may span several lines
		// of advice, so it is printed rather than logged.
		_, _ = fmt.Fprintf(os.Stderr, "\nerror: %v\n", commandErr.Err) //nolint:errcheck // not important
		os.Exit(1)
	}

	out, code := os.Stderr, 2
	if flagsErr := (&flags.Error{}); errors.As(err, &flagsErr) && errors.Is(flagsErr.Type, flags.ErrHelp) {
		out, code = os.Stdout, 0 // err is a help message (-h or --help)
	}
	_, _ = fmt.Fprintln(out, err) //nolint:errcheck // not important

	os.Exit(code)
}
