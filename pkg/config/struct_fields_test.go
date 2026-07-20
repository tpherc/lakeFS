package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestMapLoggingFields(t *testing.T) {
	t.Parallel()
	f := 64.0
	value := struct {
		A  int
		B  string
		C  *float64
		D  []rune
		E  bool
		AA struct {
			A int
			B string
			C *float64
			D []rune
			E bool
		}
		BB *struct {
			A int
			B string
			C *float64
			D []rune
			E bool
		}
		CC struct {
			A int      `mapstructure:"a1"`
			B string   `mapstructure:"b1"`
			C *float64 `mapstructure:"c1"`
			D []rune   `mapstructure:"d1"`
			E bool     `mapstructure:"e1"`
		} `mapstructure:"c_c"`
		DD struct {
			Squash struct {
				A int
				B string
				C *float64
				D []rune
				E bool
			} `mapstructure:"squash"`
		}
		EE1 config.SecureString
		EE2 config.SecureString
	}{
		A: 1,
		B: "2",
		C: &f,
		D: []rune{1, 2, 3},
		E: true,
		AA: struct {
			A int
			B string
			C *float64
			D []rune
			E bool
		}{
			A: 1,
			B: "2",
			C: &f,
			D: []rune{1, 2, 3},
			E: true,
		},
		BB: nil,
		CC: struct {
			A int      `mapstructure:"a1"`
			B string   `mapstructure:"b1"`
			C *float64 `mapstructure:"c1"`
			D []rune   `mapstructure:"d1"`
			E bool     `mapstructure:"e1"`
		}{
			A: 1,
			B: "2",
			C: &f,
			D: []rune{1, 2, 3, 4},
			E: true,
		},
		DD: struct {
			Squash struct {
				A int
				B string
				C *float64
				D []rune
				E bool
			} `mapstructure:"squash"`
		}{
			Squash: struct {
				A int
				B string
				C *float64
				D []rune
				E bool
			}{
				A: 1,
				B: "2",
				C: &f,
				D: []rune{1, 2, 3},
				E: true,
			},
		},
		EE1: "ee1ee1ee1",
		EE2: "",
	}
	expected := logging.Fields{
		"a":           "1",
		"aa.a":        "1",
		"aa.b":        "2",
		"aa.c":        "64",
		"aa.d":        "[1 2 3]",
		"aa.e":        "true",
		"b":           "2",
		"c":           "64",
		"c_c.a1":      "1",
		"c_c.b1":      "2",
		"c_c.c1":      "64",
		"c_c.d1":      "[1 2 3 4]",
		"c_c.e1":      "true",
		"d":           "[1 2 3]",
		"dd.squash.a": "1",
		"dd.squash.b": "2",
		"dd.squash.c": "64",
		"dd.squash.d": "[1 2 3]",
		"dd.squash.e": "true",
		"e":           "true",
		"ee1":         config.FieldMaskedValue,
		"ee2":         config.FieldMaskedNoValue,
	}

	fields := config.MapLoggingFields(value)
	if len(expected) != len(fields) {
		t.Fatalf("Expected %d fields, got %d", len(expected), len(fields))
	}
	for k, v := range fields {
		expectedString := expected[k]
		vString := fmt.Sprint(v)
		if vString != expectedString {
			t.Errorf("Value for '%s' is '%s', expected '%s'", k, vString, expectedString)
		}
	}
}

func TestMapLoggingFieldsSkipsUnexportedFields(t *testing.T) {
	t.Parallel()
	value := struct {
		Visible string `mapstructure:"visible"`
		hidden  string `mapstructure:"hidden"`
	}{
		Visible: "logged",
		hidden:  "not logged",
	}

	fields := config.MapLoggingFields(value)

	if fmt.Sprint(fields["visible"]) != "logged" {
		t.Fatalf("visible field is %q, expected %q", fields["visible"], "logged")
	}
	if _, ok := fields["hidden"]; ok {
		t.Fatal("unexported field should not be logged")
	}
}

func TestMapLoggingFieldsSkipsInternalMultiStorageState(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: alpha
      type: mem
      backward_compatible: true
`)
	if err != nil {
		t.Fatal(err)
	}

	storageConfig := cfg.StorageConfig()
	if !storageConfig.IsMultiStorage() {
		t.Fatal("expected resolved multi-storage configuration")
	}
	storageIDs := storageConfig.GetStorageIDs()
	if len(storageIDs) != 1 || storageIDs[0] != "alpha" {
		t.Fatalf("storage IDs are %v, expected [alpha]", storageIDs)
	}

	fields := config.MapLoggingFields(cfg.GetBaseConfig())

	if fmt.Sprint(fields["blockstore.signing.secret_key"]) != config.FieldMaskedValue {
		t.Fatalf("signing secret is %q, expected masked value", fields["blockstore.signing.secret_key"])
	}
	for key := range fields {
		if strings.Contains(key, "storages") ||
			strings.Contains(key, "storageids") ||
			strings.Contains(key, "compatiblestorageid") ||
			strings.Contains(key, "storageid") {
			t.Fatalf("internal storage registry field %q should not be logged", key)
		}
	}
}
