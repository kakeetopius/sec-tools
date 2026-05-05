package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kakeetopius/sec-tools/internal/util"
	"github.com/pterm/pterm"
	"github.com/spf13/pflag"
)

type Options struct {
	pem    bool
	chain  bool
	pubkey bool
	verify bool
}

type TLSServer struct {
	Name             string
	PeerCertificates []*x509.Certificate
	Error            error
}

func main() {
	hostNames, options, err := parseArgs()
	util.CheckErr(err)

	servers := dialServers(hostNames)
	displayTLSServerDetails(servers, &options)
}

func parseArgs() ([]string, Options, error) {
	flagSet := pflag.NewFlagSet("cert-inspector", pflag.ExitOnError)
	pem := flagSet.Bool("pem", false, "Print the certificate chain in pem format")
	chain := flagSet.Bool("chain", false, "Print full certificate chain")
	pubkey := flagSet.Bool("pubkey", false, "Print the public key only in pem format")
	verify := flagSet.Bool("verify", false, "Verify the leaf certificate using the intermediate certificates returned")

	flagSet.Usage = util.UsageFunc("cert-inspector", "hosts...", flagSet.FlagUsages(), "Host Names should be provided in the format hostname:port")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		return nil, Options{}, err
	}

	args := flagSet.Args()
	if len(args) < 1 {
		return nil, Options{}, fmt.Errorf("no hostname or ip address provided")
	}
	return args, Options{
		pem:    *pem,
		chain:  *chain,
		pubkey: *pubkey,
		verify: *verify,
	}, nil
}

func dialServers(hosts []string) []TLSServer {
	servers := make([]TLSServer, 0, len(hosts))
	for _, host := range hosts {
		server := TLSServer{
			Name: host,
		}
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: 2 * time.Second,
			},
			Config: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		conn, err := dialer.Dial("tcp", host)
		if err != nil {
			server.Error = err
			servers = append(servers, server)
			continue
		}
		tlsConn := conn.(*tls.Conn)
		certs := tlsConn.ConnectionState().PeerCertificates
		server.PeerCertificates = certs
		servers = append(servers, server)
		conn.Close()
	}

	return servers
}

func displayTLSServerDetails(servers []TLSServer, options *Options) {
	headerStyle := pterm.NewStyle(pterm.FgBlue, pterm.Bold)
	errStr := strings.Builder{}

	for _, server := range servers {
		name := server.Name
		if server.Error != nil {
			fmt.Fprintf(&errStr, "Error for %v -> %v", name, server.Error)
			continue
		}
		if len(servers) > 1 {
			headerStyle.Println(name)
		}

		certPool := x509.NewCertPool()
		for i, cert := range server.PeerCertificates {
			certPool.AddCert(cert)
			if !options.chain && i != 0 {
				continue
			}
			if options.pem {
				printPEMCert(cert)
			} else if options.pubkey {
				printCertPubKey(cert)
			} else {
				err := printCertTable(cert, i+1)
				if err != nil {
					fmt.Fprintf(&errStr, "Error for %v -> %v", name, err)
				}
			}
		}

		if options.verify {
			err := verifyCertificate(server.PeerCertificates[0], certPool)
			fmt.Print("Verification Status: ")
			if err != nil {
				errString := err.Error()
				if strings.Contains(errString, ":") {
					errString = strings.TrimSpace(strings.Split(errString, ":")[1])
				}
				fmt.Println("[✘] Failed -> ", errString)
			} else {
				fmt.Println("[✔] Successfully verified")
			}
		}
		fmt.Println()
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
	commonData := [][]string{
		{name},
		{"Version", fmt.Sprint(cert.Version)},
		{"Serial Number", cert.SerialNumber.Text(16)},
		{"Subject", wrapString(cert.Subject.String(), 50)},
		{"Issuer", wrapString(cert.Issuer.String(), 50)},
		{"Subject Public Key Algorithm", cert.PublicKeyAlgorithm.String()},
		{"Public Key", pubKeyStr},
		{"Signature Algorithm", cert.SignatureAlgorithm.String()},
		{"Signature", wrapString(hex.EncodeToString(cert.Signature), 50)},
	}
	tableData = append(tableData, commonData...)

	if len(cert.EmailAddresses) > 0 {
		tableData = append(tableData, []string{"Email Addresses", strings.Join(cert.EmailAddresses, ", ")})
	}
	if len(cert.DNSNames) > 0 {
		tableData = append(tableData, []string{"DNS Names", strings.Join(cert.DNSNames, "\n")})
	}
	if len(cert.IPAddresses) > 0 {
		tableData = append(tableData, []string{"IP Addresses", strings.Join(IPsToStringSlice(cert.IPAddresses), ", ")})
	}
	if len(cert.URIs) > 0 {
		tableData = append(tableData, []string{"URIs", strings.Join(URIsToStringSlice(cert.URIs), ", ")})
	}
	tableData = append(tableData, []string{"Valid From", cert.NotBefore.String()})
	tableData = append(tableData, []string{"Valid To", cert.NotAfter.String()})

	table := pterm.DefaultTable.WithBoxed(true).WithData(tableData).WithRowSeparator("-")
	table.Render()

	return nil
}

func printCertPubKey(cert *x509.Certificate) {
	pubkey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: cert.RawSubjectPublicKeyInfo,
	})
	fmt.Println(string(pubkey))
}

func printPEMCert(cert *x509.Certificate) {
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fmt.Println(string(pemCert))
}

func verifyCertificate(leaf *x509.Certificate, intermediates *x509.CertPool) error {
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
	})

	return err
}

func IPsToStringSlice(ips []net.IP) []string {
	ipsAsStr := make([]string, 0, len(ips))

	for _, ip := range ips {
		ipsAsStr = append(ipsAsStr, ip.String())
	}

	return ipsAsStr
}

func URIsToStringSlice(URIs []*url.URL) []string {
	uriStrs := make([]string, 0, len(URIs))

	for _, url := range URIs {
		uriStrs = append(uriStrs, url.String())
	}

	return uriStrs
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
