package cmd

import (
	"fmt"
	"net/http"

	"github.com/brawdev/guardian/internal/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Levanta el servidor REST de Guardian",
	Example: `  guardian serve
  guardian serve --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := api.Config{
			SafeBrowsingKey: viper.GetString("GOOGLE_SAFE_BROWSING_KEY"),
			VirusTotalKey:   viper.GetString("VIRUSTOTAL_KEY"),
		}

		router := api.NewRouter(cfg)
		addr := fmt.Sprintf(":%d", servePort)
		fmt.Printf("Guardian API escuchando en http://localhost%s\n", addr)
		return http.ListenAndServe(addr, router)
	},
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "puerto del servidor")
	rootCmd.AddCommand(serveCmd)
}
