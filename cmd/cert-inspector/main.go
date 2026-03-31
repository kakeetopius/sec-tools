package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/kakeetopius/sec-tools/internal/util"
	"github.com/pterm/pterm"
	"github.com/spf13/pflag"
)

type Options struct {
	pem   bool
	chain bool
}

type TLSServer struct {
	Name             string
	PeerCertificates []*x509.Certificate
	Error            error
}

func main() {
	hostNames, options, err := parseArgs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	servers := dialServers(hostNames)
	printTLSServerDetails(servers, &options)
}

func parseArgs() ([]string, Options, error) {
	flagSet := pflag.NewFlagSet("cert-inspector", pflag.ExitOnError)
	pem := flagSet.BoolP("pem", "p", false, "Print the certificate chain in pem format")
	chain := flagSet.BoolP("chain", "c", false, "Print full certificate chain")

	flagSet.Usage = util.UsageFunc("cert-inspector", "hosts", flagSet.FlagUsages(), "Host Names should be provided in the format hostname:port")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		return nil, Options{}, err
	}

	args := flagSet.Args()
	if len(args) < 1 {
		return nil, Options{}, fmt.Errorf("no hostname or ip address provided")
	}
	return args, Options{
		pem:   *pem,
		chain: *chain,
	}, nil
}

func dialServers(hosts []string) []TLSServer {
	servers := make([]TLSServer, 0, len(hosts))
	for _, host := range hosts {
		server := TLSServer{
			Name: host,
		}
		conn, err := tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			server.Error = err
			servers = append(servers, server)
			continue
		}
		certs := conn.ConnectionState().PeerCertificates
		server.PeerCertificates = certs
		servers = append(servers, server)
		conn.Close()
	}

	return servers
}

func printTLSServerDetails(servers []TLSServer, options *Options) {
	headerStyle := pterm.NewStyle(pterm.FgBlue, pterm.Bold)
	errStr := strings.Builder{}

	for _, server := range servers {
		name := server.Name
		if server.Error != nil {
			fmt.Fprintf(&errStr, "Error for %v -> %v", name, server.Error)
			continue
		}
		headerStyle.Println(name)

		for i, cert := range server.PeerCertificates {
			if !options.chain && i != 0 {
				break
			}
			if options.pem {
				printPEMCert(cert, i+1)
				continue
			}
			err := printCertTable(cert, i+1)
			if err != nil {
				fmt.Fprintf(&errStr, "Error for %v -> %v", name, err)
			}
		}
	}

	if errStr.String() != "" {
		fmt.Println("\nErrors: ")
		fmt.Println(errStr.String())
	}
}

func printCertTable(cert *x509.Certificate, certIndex int) error {
	tableData := pterm.TableData{}
	certNameStyle := pterm.NewStyle(pterm.FgYellow)
	name := certNameStyle.Sprintf("Certificate %v", certIndex)
	if cert.IsCA {
		name = certNameStyle.Sprintf("%v (CA)", name)
	}

	pubkey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	pubKeyStr := wrapString(hex.EncodeToString(pubkey), 50)
	tableData = append(tableData, []string{name})
	tableData = append(tableData, []string{"Version", fmt.Sprint(cert.Version)})
	tableData = append(tableData, []string{"Serial Number", cert.SerialNumber.Text(16)})
	tableData = append(tableData, []string{"Subject", wrapString(cert.Subject.String(), 50)})
	tableData = append(tableData, []string{"Issuer", wrapString(cert.Issuer.String(), 50)})
	tableData = append(tableData, []string{"Subject Public Key Algorithm", cert.PublicKeyAlgorithm.String()})
	tableData = append(tableData, []string{"Public Key", pubKeyStr})
	tableData = append(tableData, []string{"Signature Algorithm", cert.SignatureAlgorithm.String()})
	tableData = append(tableData, []string{"Signature", wrapString(hex.EncodeToString(cert.Signature), 50)})
	tableData = append(tableData, []string{"Valid From", cert.NotBefore.String()})
	tableData = append(tableData, []string{"Valid To", cert.NotAfter.String()})

	table := pterm.DefaultTable.WithBoxed(true).WithData(tableData).WithRowSeparator("-")
	table.Render()

	return nil
}

func printPEMCert(cert *x509.Certificate, certIndex int) {
	certStyle := pterm.NewStyle(pterm.FgYellow)
	name := certStyle.Sprintf("Certificate %v", certIndex)
	fmt.Println(name)
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fmt.Println(string(pemCert))
}

func wrapString(s string, width int) string {
	wrappedStr := strings.Builder{}
	for len(s) > width {
		fmt.Fprintf(&wrappedStr, "%s\n", s[:width])
		s = s[width:]
	}
	fmt.Fprintf(&wrappedStr, "%s", s)
	return wrappedStr.String()
}
