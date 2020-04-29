package main

import (
	"github.com/pomerium/pomerium/internal/cmd"
	"github.com/pomerium/pomerium/internal/log"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}
