package cmd

import (
	"fmt"
	"os"

	"github.com/brawdev/guardian/internal/emailanalyzer"
	"github.com/brawdev/guardian/pkg/report"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var emailJSONOutput bool
var emailPasteMode bool

var emailCmd = &cobra.Command{
	Use:   "analyze-email <archivo.eml | ->",
	Short: "Analiza un email (.eml) en busca de señales de phishing",
	Example: `  guardian analyze-email phishing.eml
  guardian analyze-email ~/Downloads/sospechoso.eml --json
  guardian analyze-email --paste
  pbpaste | guardian analyze-email -`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		var path string

		if emailPasteMode {
			fmt.Println()
			fmt.Println("  Pega el contenido del correo y presiona Enter + Ctrl+D cuando termines:")
			fmt.Println()
			path = "-"
		} else {
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Error: especifica un archivo o usa --paste para pegar el texto\n")
				os.Exit(1)
			}
			path = args[0]
			if path != "-" {
				if _, err := os.Stat(path); os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "Error: archivo no encontrado: %s\n", path)
					os.Exit(1)
				}
				fmt.Printf("  Analizando %s...\n", path)
			} else {
				fmt.Println("  Leyendo desde stdin...")
			}
		}

		sbKey := viper.GetString("GOOGLE_SAFE_BROWSING_KEY")
		vtKey := viper.GetString("VIRUSTOTAL_KEY")
		result, err := emailanalyzer.Analyze(path, sbKey, vtKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al parsear email: %v\n", err)
			os.Exit(1)
		}

		report.PrintEmail(result, emailJSONOutput)
	},
}

func init() {
	emailCmd.Flags().BoolVar(&emailJSONOutput, "json", false, "output en formato JSON")
	emailCmd.Flags().BoolVar(&emailPasteMode, "paste", false, "pega el texto del correo directamente en la terminal")
	rootCmd.AddCommand(emailCmd)
}
