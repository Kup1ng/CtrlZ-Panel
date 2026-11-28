package app

import (
	"errors"
	"fmt"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// IntakeConfig names the two public intake key files the admin seals an uploaded private key to (p4-nodes 3.3). They are
// public halves, mounted as Docker secrets beside the private ones the hub and domain-apply hold; the admin never holds a
// private half (N8), so what it stores it cannot open again.
//
//	CTRLZ_WILDCARD_INTAKE_PUB_FILE   the key a wildcard certificate's private key is sealed to (the hub opens it)
//	CTRLZ_WEB_INTAKE_PUB_FILE        the key a panel or admin certificate's private key is sealed to (domain-apply opens it)
//
// Both are set or neither; with neither, POST /certificates answers service_unavailable.
type IntakeConfig struct {
	WildcardPubFile, WebPubFile string
}

// Enabled says whether the admin can take an uploaded certificate.
func (i IntakeConfig) Enabled() bool { return i.WildcardPubFile != "" }

func loadIntakeConfig(role Role, getenv Getenv, c *Config) error {
	i := IntakeConfig{WildcardPubFile: getenv("CTRLZ_WILDCARD_INTAKE_PUB_FILE"), WebPubFile: getenv("CTRLZ_WEB_INTAKE_PUB_FILE")}
	if role != RoleAdmin {
		if i.WildcardPubFile != "" || i.WebPubFile != "" {
			return errors.New("the intake public keys are for the admin only")
		}
		return nil
	}
	if (i.WildcardPubFile == "") != (i.WebPubFile == "") {
		return errors.New("an uploaded certificate needs CTRLZ_WILDCARD_INTAKE_PUB_FILE and CTRLZ_WEB_INTAKE_PUB_FILE together")
	}
	c.Intake = i
	return nil
}

// newIntake reads the two public keys, or returns nil when the deployment mounts none. A file that is not an X25519 public
// key stops the start, so a wrong mount shows at deploy time and not at the first upload.
func newIntake(cfg Config) (*adminapi.Intake, error) {
	if !cfg.Intake.Enabled() {
		return nil, nil
	}
	read := func(name, path string) (intakeseal.PublicKey, error) {
		s, err := secret.FromFile(path)
		if err != nil {
			return intakeseal.PublicKey{}, err
		}
		k, err := intakeseal.ParsePublicKey([]byte(s.Reveal()))
		if err != nil {
			return intakeseal.PublicKey{}, fmt.Errorf("%s: %w", name, err)
		}
		return k, nil
	}
	w, err := read("CTRLZ_WILDCARD_INTAKE_PUB_FILE", cfg.Intake.WildcardPubFile)
	if err != nil {
		return nil, err
	}
	web, err := read("CTRLZ_WEB_INTAKE_PUB_FILE", cfg.Intake.WebPubFile)
	if err != nil {
		return nil, err
	}
	return &adminapi.Intake{Wildcard: w, Web: web}, nil
}
