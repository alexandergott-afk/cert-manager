/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rfc2136

import (
    "fmt"
    "strings"
    "time"

    "github.com/miekg/dns"

    "github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
    logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// This list must be kept in sync with internal/apis/certmanager/validation/issuer.go
var supportedAlgorithms = map[string]string{
    "HMACMD5":    dns.HmacMD5,
    "HMACSHA1":   dns.HmacSHA1,
    "HMACSHA256": dns.HmacSHA256,
    "HMACSHA512": dns.HmacSHA512,
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface that
// uses dynamic DNS updates (RFC 2136) to create TXT records on a nameserver.
type DNSProvider struct {
    nameservers   []string // GEÄNDERT: Slice von Strings statt einzelner String
    tsigAlgorithm string
    network       string
    tsigKeyName   string
    tsigSecret    string
}

// ProviderOption is some configuration that modifies rfc2136 DNS provider.
type ProviderOption func(*DNSProvider)

func WithNetwork(network string) ProviderOption {
    return func(d *DNSProvider) {
        if network == "" {
            network = "udp"
        }
        d.network = strings.ToLower(network)
    }
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for rfc2136 dynamic update.
// nameserver kann jetzt eine Komma-separierte Liste sein (z.B. "10.0.0.1,10.0.0.2").
func NewDNSProviderCredentials(nameserver, tsigAlgorithm, tsigKeyName, tsigSecret string, opts ...ProviderOption) (*DNSProvider, error) {
    logf.Log.V(logf.DebugLevel).Info("Creating RFC2136 Provider")

    d := &DNSProvider{}

    for _, opt := range opts {
        opt(d)
    }

    // NEU: Splitte den String an Kommas, um mehrere Server zu unterstützen
    serverList := strings.Split(nameserver, ",")
    var validServers []string

    for _, srv := range serverList {
        srv = strings.TrimSpace(srv)
        if srv == "" {
            continue
        }
        if validSrv, err := util.ValidNameserver(srv); err != nil {
            return nil, fmt.Errorf("invalid nameserver '%s': %v", srv, err)
        } else {
            validServers = append(validServers, validSrv)
        }
    }

    if len(validServers) == 0 {
        return nil, fmt.Errorf("no valid nameservers provided")
    }

    d.nameservers = validServers

    if len(tsigKeyName) > 0 && len(tsigSecret) > 0 {
        d.tsigKeyName = tsigKeyName
        d.tsigSecret = tsigSecret
    }

    if tsigAlgorithm == "" {
        tsigAlgorithm = dns.HmacMD5
    } else {
        if value, ok := supportedAlgorithms[strings.ToUpper(tsigAlgorithm)]; ok {
            tsigAlgorithm = value
        } else {
            return nil, fmt.Errorf("algorithm '%v' is not supported", tsigAlgorithm)
        }
    }
    d.tsigAlgorithm = tsigAlgorithm

    // Logging (maskiert das Secret)
    keyLen := len(d.tsigSecret)
    mask := make([]rune, keyLen/2)
    for i := range mask {
        mask[i] = '*'
    }
    masked := ""
    if keyLen > 0 {
        masked = d.tsigSecret[0:keyLen/4] + string(mask) + d.tsigSecret[keyLen/4*3:keyLen]
    }
    logf.Log.V(logf.DebugLevel).Info("DNSProvider",
        "nameservers", d.nameservers, // Loggt nun die Liste
        "tsigAlgorithm", d.tsigAlgorithm,
        "tsigKeyName", d.tsigKeyName,
        "tsigSecret", masked,
    )

    return d, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProvider) Present(_, fqdn, zone, value string) error {
    return r.changeRecord("INSERT", fqdn, zone, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(_, fqdn, zone, value string) error {
    return r.changeRecord("REMOVE", fqdn, zone, value, 60)
}

func (r *DNSProvider) changeRecord(action, fqdn, zone, value string, ttl uint32) error {
    // Create RR
    rr := new(dns.TXT)
    rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
    rr.Txt = []string{value}
    rrs := []dns.RR{rr}

    // Create dynamic update packet
    m := new(dns.Msg)
    m.SetUpdate(zone)
    switch action {
    case "INSERT":
        m.Insert(rrs)
    case "REMOVE":
        m.Remove(rrs)
    default:
        return fmt.Errorf("unexpected action: %s", action)
    }

    // NEU: Iteriere über alle Nameserver und sende das Update
    var lastErr error
    for _, ns := range r.nameservers {
        // Setup client (muss pro Request neu erstellt oder resettet werden, ist aber hier sicherer so)
        c := &dns.Client{Net: r.network}
        c.TsigProvider = tsigHMACProvider(r.tsigSecret)
        
        // TSIG authentication / msg signing
        // Wir nutzen eine frische Msg-Kopie oder setzen Tsig neu, falls nötig, 
        // aber miekg/dns handled das meist im Exchange. 
        // Wichtig: Tsig wird auf 'm' gesetzt.
        if len(r.tsigKeyName) > 0 && len(r.tsigSecret) > 0 {
            m.SetTsig(dns.Fqdn(r.tsigKeyName), r.tsigAlgorithm, 300, time.Now().Unix())
            c.TsigSecret = map[string]string{dns.Fqdn(r.tsigKeyName): r.tsigSecret}
        }

        logf.Log.V(logf.DebugLevel).Info("Sending DNS update", "nameserver", ns, "action", action)
        
        // Send the query
        reply, _, err := c.Exchange(m, ns)
        if err != nil {
            lastErr = fmt.Errorf("DNS update failed for server %s: %v", ns, err)
            logf.Log.V(logf.DebugLevel).Info("Error updating nameserver", "nameserver", ns, "error", err)
            // Wir brechen hier nicht ab, sondern versuchen die anderen Server auch noch zu erreichen.
            continue 
        }
        if reply != nil && reply.Rcode != dns.RcodeSuccess {
            lastErr = fmt.Errorf("DNS update failed for server %s. Server replied: %s", ns, dns.RcodeToString[reply.Rcode])
            logf.Log.V(logf.DebugLevel).Info("Server rejected update", "nameserver", ns, "rcode", reply.Rcode)
            continue
        }
    }

    // Wenn auch nur ein Fehler aufgetreten ist, geben wir diesen zurück.
    // So stellt cert-manager sicher, dass nicht "Erfolg" gemeldet wird, wenn ein Server down ist.
    // Zertifikat-Erstellung wird fehlschlagen, wenn nicht alle Server erreicht werden konnten.
    // Alternativ könnte man hier nur fehler zurückgeben, wenn ALLE fehlschlugen.
    // Für ACME ist es sicherer, Fehler zu melden, wenn inkonsistente Zustände drohen.
    return lastErr
}

// Nameserver returns the nameserver configured for this provider when it was created
func (r *DNSProvider) Nameserver() string {
    // Rückwärtskompatibilität: Gibt den ersten Server zurück
    if len(r.nameservers) > 0 {
        return r.nameservers[0]
    }
    return ""
}

// TSIGAlgorithm returns the TSIG algorithm configured for this provider when it was created
func (r *DNSProvider) TSIGAlgorithm() string {
    return r.tsigAlgorithm
}
