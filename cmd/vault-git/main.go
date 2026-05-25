package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	vault "github.com/ryzanstein/vault-git"
	"github.com/ryzanstein/vault-git/escrow"
	"github.com/spf13/cobra"
)

var (
	vaultPath     string
	modeName      string
	keyFilePath   string
	escrowBackend string
)

func loadKey() ([]byte, error) {
	if keyFilePath != "" {
		data, err := os.ReadFile(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
			data = data[:len(data)-1]
		}
		return data, nil
	}
	envKey := os.Getenv("VAULT_MASTER_KEY")
	if envKey != "" {
		return []byte(envKey), nil
	}
	return nil, fmt.Errorf("master key required: use --key-file or VAULT_MASTER_KEY env var")
}

func parseMode(name string) vault.EncryptionMode {
	switch name {
	case "searchable":
		return vault.ModeSearchable
	case "computable":
		return vault.ModeComputable
	case "provable":
		return vault.ModeProvable
	default:
		return vault.ModeHybrid
	}
}

func openVault() (*vault.Vault, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}
	cfg := vault.DefaultConfig()
	cfg.StorePath = vaultPath
	cfg.EncryptionMode = parseMode(modeName)
	return vault.New(cfg, key)
}

func withPersist(v *vault.Vault, fn func() error) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		v.Persist() //nolint
		os.Exit(1)
	}()
	defer signal.Stop(sigCh)

	err := fn()
	if persistErr := v.Persist(); persistErr != nil && err == nil {
		err = persistErr
	}
	return err
}

// openEscrow returns a KeyEscrow for the configured backend.
// masterKey is used as the escrow password for the file backend.
func openEscrow(masterKey []byte) (escrow.KeyEscrow, error) {
	escrowPath := vaultPath + ".escrow.yaml"
	return escrow.New(escrowBackend, escrowPath, masterKey)
}

// escrowProof derives the proof value expected by FileEscrow.Retrieve/Rotate.
// FileEscrow sets aesKey = sha256(masterPassword), and unwrap checks
// sha256(proof) == sha256(aesKey), so proof = sha256(masterKey).
func escrowProof(masterKey []byte) []byte {
	h := sha256.Sum256(masterKey)
	return h[:]
}

var rootCmd = &cobra.Command{
	Use:   "vault-git",
	Short: "Encrypted content-addressable git-compatible storage",
}

var storeCmd = &cobra.Command{
	Use:   "store <file>",
	Short: "Encrypt and store a file, prints its content hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		var data []byte
		if args[0] == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(args[0])
		}
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		return withPersist(v, func() error {
			obj, err := v.Store(data)
			if err != nil {
				return err
			}
			fmt.Println(obj.Hash)
			return nil
		})
	},
}

var retrieveCmd = &cobra.Command{
	Use:   "retrieve <hash>",
	Short: "Decrypt and print content by hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		content, err := v.Retrieve(args[0])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(content)
		return err
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify <hash>",
	Short: "Verify content integrity (ZK proof)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		ok, err := v.Verify(args[0])
		if err != nil {
			return err
		}
		if ok {
			fmt.Printf("OK %s\n", args[0])
		} else {
			fmt.Fprintf(os.Stderr, "FAIL %s: hash mismatch\n", args[0])
			os.Exit(1)
		}
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored object hashes and sizes",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		objects := v.List()
		if len(objects) == 0 {
			fmt.Println("(empty vault)")
			return nil
		}
		for _, obj := range objects {
			fmt.Printf("%s  %d bytes  [%s]\n", obj.Hash, obj.Size, obj.Mode)
		}
		return nil
	},
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Print vault statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		s := v.Stats()
		fmt.Printf("Objects:        %d\n", s.TotalObjects)
		fmt.Printf("Unique hashes:  %d\n", s.UniqueHashes)
		fmt.Printf("Plaintext size: %d bytes\n", s.TotalSize)
		fmt.Printf("Encrypted size: %d bytes\n", s.EncryptedSize)
		return nil
	},
}

var persistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Flush in-memory vault to disk",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		if err := v.Persist(); err != nil {
			return fmt.Errorf("persist: %w", err)
		}
		fmt.Println("vault persisted")
		return nil
	},
}

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load vault from disk and report object count",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}
		if err := v.Load(); err != nil {
			return fmt.Errorf("load: %w", err)
		}
		s := v.Stats()
		fmt.Printf("Loaded %d objects from %s\n", s.TotalObjects, vaultPath)
		return nil
	},
}

var escrowCmd = &cobra.Command{
	Use:   "escrow",
	Short: "Key escrow operations (deposit / retrieve / rotate)",
}

var escrowDepositCmd = &cobra.Command{
	Use:   "deposit <key-id> <key-material>",
	Short: "Deposit key material into escrow under key-id",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		masterKey, err := loadKey()
		if err != nil {
			return err
		}
		e, err := openEscrow(masterKey)
		if err != nil {
			return err
		}
		if err := e.Deposit(args[0], []byte(args[1])); err != nil {
			return err
		}
		fmt.Printf("deposited key %q\n", args[0])
		return nil
	},
}

var escrowRetrieveCmd = &cobra.Command{
	Use:   "retrieve <key-id>",
	Short: "Retrieve key material from escrow",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		masterKey, err := loadKey()
		if err != nil {
			return err
		}
		e, err := openEscrow(masterKey)
		if err != nil {
			return err
		}
		proof := escrowProof(masterKey)
		key, err := e.Retrieve(args[0], proof)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(key)
		return err
	},
}

var escrowRotateCmd = &cobra.Command{
	Use:   "rotate <key-id> <new-key-material>",
	Short: "Rotate the key stored under key-id",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		masterKey, err := loadKey()
		if err != nil {
			return err
		}
		e, err := openEscrow(masterKey)
		if err != nil {
			return err
		}
		proof := escrowProof(masterKey)
		if err := e.Rotate(args[0], proof, []byte(args[1])); err != nil {
			return err
		}
		fmt.Printf("rotated key %q\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultPath, "vault-path", ".vault", "path to vault store directory")
	rootCmd.PersistentFlags().StringVar(&modeName, "mode", "hybrid", "encryption mode: searchable|computable|provable|hybrid")
	rootCmd.PersistentFlags().StringVar(&keyFilePath, "key-file", "", "path to master key file (or set VAULT_MASTER_KEY)")
	rootCmd.PersistentFlags().StringVar(&escrowBackend, "escrow-backend", "file", "key escrow backend: file|local")

	escrowCmd.AddCommand(escrowDepositCmd, escrowRetrieveCmd, escrowRotateCmd)
	rootCmd.AddCommand(storeCmd, retrieveCmd, verifyCmd, listCmd, statsCmd, persistCmd, loadCmd, escrowCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
