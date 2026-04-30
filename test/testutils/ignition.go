package testutils

import (
	"encoding/json"
	"net/url"
	"os"
)

// Minimal Ignition config schema (v3.2) for FCOS boot with SSH access.
// Uses flat structs to avoid the json:",inline" tag which Go stdlib doesn't support.

type IgnitionConfig struct {
	Ignition Ignition `json:"ignition"`
	Passwd   Passwd   `json:"passwd,omitempty"`
	Storage  Storage  `json:"storage,omitempty"`
	Systemd  Systemd  `json:"systemd,omitempty"`
}

type Ignition struct {
	Version string `json:"version,omitempty"`
}

type Passwd struct {
	Users []PasswdUser `json:"users,omitempty"`
}

type PasswdUser struct {
	Name              string   `json:"name"`
	PasswordHash      *string  `json:"passwordHash,omitempty"`
	SSHAuthorizedKeys []string `json:"sshAuthorizedKeys,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

type StorageFile struct {
	Group     *string  `json:"group,omitempty"`
	Overwrite *bool    `json:"overwrite,omitempty"`
	Path      string   `json:"path"`
	User      *string  `json:"user,omitempty"`
	Contents  Resource `json:"contents,omitempty"`
	Mode      *int     `json:"mode,omitempty"`
}

type StorageDir struct {
	Group *string `json:"group,omitempty"`
	Path  string  `json:"path"`
	User  *string `json:"user,omitempty"`
	Mode  *int    `json:"mode,omitempty"`
}

type StorageLink struct {
	Group    *string `json:"group,omitempty"`
	Path     string  `json:"path"`
	User     *string `json:"user,omitempty"`
	Hard     *bool   `json:"hard,omitempty"`
	Target   string  `json:"target"`
}

type Storage struct {
	Files       []StorageFile `json:"files,omitempty"`
	Directories []StorageDir  `json:"directories,omitempty"`
	Links       []StorageLink `json:"links,omitempty"`
}

type Resource struct {
	Source *string `json:"source,omitempty"`
}

type Systemd struct {
	Units []SystemdUnit `json:"units,omitempty"`
}

type SystemdUnit struct {
	Name     string  `json:"name"`
	Enabled  *bool   `json:"enabled,omitempty"`
	Mask     *bool   `json:"mask,omitempty"`
	Contents *string `json:"contents,omitempty"`
}

// CreateIgnition writes an Ignition config file for FCOS.
// publicKey should be in OpenSSH authorized_keys format.
func CreateIgnition(path, publicKey, user, passwordHash string) error {
	yes := true
	no := false
	mode644 := 0644
	mode755 := 0755
	root := "root"

	config := IgnitionConfig{
		Ignition: Ignition{Version: "3.2.0"},
		Passwd: Passwd{
			Users: []PasswdUser{
				{
					Name:              user,
					PasswordHash:      &passwordHash,
					SSHAuthorizedKeys: []string{publicKey},
					Groups:            []string{"wheel", "sudo"},
				},
				{
					Name:              "root",
					PasswordHash:      &passwordHash,
					SSHAuthorizedKeys: []string{publicKey},
				},
			},
		},
		Storage: Storage{
			Files: []StorageFile{
				{
					Group:     &root,
					Path:      "/etc/resolv.conf",
					User:      &root,
					Overwrite: &yes,
					Contents:  Resource{Source: encodeData("")},
					Mode:      &mode644,
				},
			},
			Directories: []StorageDir{
				{
					Group: &user,
					Path:  "/home/" + user + "/.ssh",
					User:  &user,
					Mode:  &mode755,
				},
			},
			Links: []StorageLink{
				{
					Group:  &user,
					Path:   "/home/" + user + "/.ssh/authorized_keys",
					User:   &user,
					Hard:   &no,
					Target: "/home/" + user + "/.ssh/authorized_keys.d/ignition",
				},
			},
		},
		Systemd: Systemd{
			Units: []SystemdUnit{
				{
					Name:    "systemd-resolved.service",
					Enabled: &no,
					Mask:    &yes,
				},
			},
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func encodeData(data string) *string {
	s := "data:," + url.PathEscape(data)
	return &s
}
