/*
Copyright The Helm Authors.

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

package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/errdefs"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

var (
	testWorkspaceDir         = "helm-registry-test"
	testHtpasswdFileBasename = "authtest.htpasswd"
	testUsername             = "myuser"
	testPassword             = "mypass"
)

type RegistryClientTestSuite struct {
	suite.Suite
	Out                     io.Writer
	DockerRegistryHost      string
	CompromisedRegistryHost string
	WorkspaceDir            string
	RegistryClient          *Client
}

func (suite *RegistryClientTestSuite) SetupSuite() {
	suite.WorkspaceDir = testWorkspaceDir
	os.RemoveAll(suite.WorkspaceDir)
	os.Mkdir(suite.WorkspaceDir, 0700)

	var out bytes.Buffer
	suite.Out = &out
	credentialsFile := filepath.Join(suite.WorkspaceDir, CredentialsFileBasename)

	// before test client
	var err error
	suite.RegistryClient, err = NewClient(
		ClientOptDebug(true),
		ClientOptEnableCache(true),
		ClientOptWriter(suite.Out),
		ClientOptCredentialsFile(credentialsFile),
	)
	suite.Nil(err, "no error creating registry client")

	// create htpasswd file (w BCrypt, which is required)
	pwBytes, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	suite.Nil(err, "no error generating bcrypt password for test htpasswd file")
	htpasswdPath := filepath.Join(suite.WorkspaceDir, testHtpasswdFileBasename)
	err = ioutil.WriteFile(htpasswdPath, []byte(fmt.Sprintf("%s:%s\n", testUsername, string(pwBytes))), 0644)
	suite.Nil(err, "no error creating test htpasswd file")

	// Registry config
	config := &configuration.Configuration{}
	port, err := freeport.GetFreePort()
	suite.Nil(err, "no error finding free port for test registry")
	suite.DockerRegistryHost = fmt.Sprintf("localhost:%d", port)
	config.HTTP.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	config.Auth = configuration.Auth{
		"htpasswd": configuration.Parameters{
			"realm": "localhost",
			"path":  htpasswdPath,
		},
	}
	dockerRegistry, err := registry.NewRegistry(context.Background(), config)
	suite.Nil(err, "no error creating test registry")

	suite.CompromisedRegistryHost = initCompromisedRegistryTestServer()

	// Start Docker registry
	go dockerRegistry.ListenAndServe()
}

func (suite *RegistryClientTestSuite) TearDownSuite() {
	os.RemoveAll(suite.WorkspaceDir)
}

func (suite *RegistryClientTestSuite) Test_0_Login() {
	err := suite.RegistryClient.Login(suite.DockerRegistryHost,
		LoginOptBasicAuth("badverybad", "ohsobad"),
		LoginOptInsecure(false))
	suite.NotNil(err, "error logging into registry with bad credentials")

	err = suite.RegistryClient.Login(suite.DockerRegistryHost,
		LoginOptBasicAuth("badverybad", "ohsobad"),
		LoginOptInsecure(true))
	suite.NotNil(err, "error logging into registry with bad credentials, insecure mode")

	err = suite.RegistryClient.Login(suite.DockerRegistryHost,
		LoginOptBasicAuth(testUsername, testPassword),
		LoginOptInsecure(false))
	suite.Nil(err, "no error logging into registry with good credentials")

	err = suite.RegistryClient.Login(suite.DockerRegistryHost,
		LoginOptBasicAuth(testUsername, testPassword),
		LoginOptInsecure(true))
	suite.Nil(err, "no error logging into registry with good credentials, insecure mode")
}

func (suite *RegistryClientTestSuite) Test_1_Push() {
	// Bad bytes
	ref := fmt.Sprintf("%s/testrepo/testchart:1.2.3", suite.DockerRegistryHost)
	_, err := suite.RegistryClient.Push([]byte("hello"), ref)
	suite.NotNil(err, "error pushing non-chart bytes")

	// Load a test chart
	chartData, err := ioutil.ReadFile("../repo/repotest/testdata/examplechart-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err := extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")

	// non-strict ref (chart name)
	ref = fmt.Sprintf("%s/testrepo/boop:%s", suite.DockerRegistryHost, meta.Version)
	_, err = suite.RegistryClient.Push(chartData, ref)
	suite.NotNil(err, "error pushing non-strict ref (bad basename)")

	// non-strict ref (chart name), with strict mode disabled
	_, err = suite.RegistryClient.Push(chartData, ref, PushOptStrictMode(false))
	suite.Nil(err, "no error pushing non-strict ref (bad basename), with strict mode disabled")

	// non-strict ref (chart version)
	ref = fmt.Sprintf("%s/testrepo/%s:latest", suite.DockerRegistryHost, meta.Name)
	_, err = suite.RegistryClient.Push(chartData, ref)
	suite.NotNil(err, "error pushing non-strict ref (bad tag)")

	// non-strict ref (chart version), with strict mode disabled
	_, err = suite.RegistryClient.Push(chartData, ref, PushOptStrictMode(false))
	suite.Nil(err, "no error pushing non-strict ref (bad tag), with strict mode disabled")

	// basic push, good ref
	chartData, err = ioutil.ReadFile("../downloader/testdata/local-subchart-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err = extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")
	ref = fmt.Sprintf("%s/testrepo/%s:%s", suite.DockerRegistryHost, meta.Name, meta.Version)
	_, err = suite.RegistryClient.Push(chartData, ref)
	suite.Nil(err, "no error pushing good ref")

	_, err = suite.RegistryClient.Pull(ref)
	suite.Nil(err, "no error pulling a simple chart")

	// Load another test chart
	chartData, err = ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err = extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")

	// Load prov file
	provData, err := ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz.prov")
	suite.Nil(err, "no error loading test prov")

	// push with prov
	ref = fmt.Sprintf("%s/testrepo/%s:%s", suite.DockerRegistryHost, meta.Name, meta.Version)
	fmt.Println("ref:", ref)
	result, err := suite.RegistryClient.Push(chartData, ref, PushOptProvData(provData))
	suite.Nil(err, "no error pushing good ref with prov")

	_, err = suite.RegistryClient.Pull(ref)
	suite.Nil(err, "no error pulling a simple chart")

	// Validate the output
	// Note: these digests/sizes etc may change if the test chart/prov files are modified,
	// or if the format of the OCI manifest changes
	suite.Equal(ref, result.Ref)
	suite.Equal(meta.Name, result.Chart.Meta.Name)
	suite.Equal(meta.Version, result.Chart.Meta.Version)
	suite.Equal(int64(512), result.Manifest.Size)
	suite.Equal(int64(99), result.Config.Size)
	suite.Equal(int64(973), result.Chart.Size)
	suite.Equal(int64(695), result.Prov.Size)
	suite.Equal(
		"sha256:af4c20a1df1431495e673c14ecfa3a2ba24839a7784349d6787cd67957392e83",
		result.Manifest.Digest)
	suite.Equal(
		"sha256:8d17cb6bf6ccd8c29aace9a658495cbd5e2e87fc267876e86117c7db681c9580",
		result.Config.Digest)
	suite.Equal(
		"sha256:e5ef611620fb97704d8751c16bab17fedb68883bfb0edc76f78a70e9173f9b55",
		result.Chart.Digest)
	suite.Equal(
		"sha256:b0a02b7412f78ae93324d48df8fcc316d8482e5ad7827b5b238657a29a22f256",
		result.Prov.Digest)
}

func (suite *RegistryClientTestSuite) Test_2_Pull() {
	// bad/missing ref
	ref := fmt.Sprintf("%s/testrepo/no-existy:1.2.3", suite.DockerRegistryHost)
	_, err := suite.RegistryClient.Pull(ref)
	suite.NotNil(err, "error on bad/missing ref")

	// Load test chart (to build ref pushed in previous test)
	chartData, err := ioutil.ReadFile("../downloader/testdata/local-subchart-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err := extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")
	ref = fmt.Sprintf("%s/testrepo/%s:%s", suite.DockerRegistryHost, meta.Name, meta.Version)

	// Simple pull, chart only
	_, err = suite.RegistryClient.Pull(ref)
	suite.Nil(err, "no error pulling a simple chart")

	// Simple pull with prov (no prov uploaded)
	_, err = suite.RegistryClient.Pull(ref, PullOptWithProv(true))
	suite.NotNil(err, "error pulling a chart with prov when no prov exists")

	// Simple pull with prov, ignoring missing prov
	_, err = suite.RegistryClient.Pull(ref,
		PullOptWithProv(true),
		PullOptIgnoreMissingProv(true))
	suite.Nil(err,
		"no error pulling a chart with prov when no prov exists, ignoring missing")

	// Load test chart (to build ref pushed in previous test)
	chartData, err = ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err = extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")
	ref = fmt.Sprintf("%s/testrepo/%s:%s", suite.DockerRegistryHost, meta.Name, meta.Version)

	// Load prov file
	provData, err := ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz.prov")
	suite.Nil(err, "no error loading test prov")

	// no chart and no prov causes error
	_, err = suite.RegistryClient.Pull(ref,
		PullOptWithChart(false),
		PullOptWithProv(false))
	suite.NotNil(err, "error on both no chart and no prov")

	// full pull with chart and prov
	result, err := suite.RegistryClient.Pull(ref, PullOptWithProv(true))
	suite.Nil(err, "no error pulling a chart with prov")

	// Validate the output
	// Note: these digests/sizes etc may change if the test chart/prov files are modified,
	// or if the format of the OCI manifest changes
	suite.Equal(ref, result.Ref)
	suite.Equal(meta.Name, result.Chart.Meta.Name)
	suite.Equal(meta.Version, result.Chart.Meta.Version)
	suite.Equal(int64(512), result.Manifest.Size)
	suite.Equal(int64(99), result.Config.Size)
	suite.Equal(int64(973), result.Chart.Size)
	suite.Equal(int64(695), result.Prov.Size)
	suite.Equal(
		"sha256:af4c20a1df1431495e673c14ecfa3a2ba24839a7784349d6787cd67957392e83",
		result.Manifest.Digest)
	suite.Equal(
		"sha256:8d17cb6bf6ccd8c29aace9a658495cbd5e2e87fc267876e86117c7db681c9580",
		result.Config.Digest)
	suite.Equal(
		"sha256:e5ef611620fb97704d8751c16bab17fedb68883bfb0edc76f78a70e9173f9b55",
		result.Chart.Digest)
	suite.Equal(
		"sha256:b0a02b7412f78ae93324d48df8fcc316d8482e5ad7827b5b238657a29a22f256",
		result.Prov.Digest)
	suite.Equal("{\"schemaVersion\":2,\"config\":{\"mediaType\":\"application/vnd.cncf.helm.config.v1+json\",\"digest\":\"sha256:8d17cb6bf6ccd8c29aace9a658495cbd5e2e87fc267876e86117c7db681c9580\",\"size\":99},\"layers\":[{\"mediaType\":\"application/vnd.cncf.helm.chart.provenance.v1.prov\",\"digest\":\"sha256:b0a02b7412f78ae93324d48df8fcc316d8482e5ad7827b5b238657a29a22f256\",\"size\":695},{\"mediaType\":\"application/vnd.cncf.helm.chart.content.v1.tar+gzip\",\"digest\":\"sha256:e5ef611620fb97704d8751c16bab17fedb68883bfb0edc76f78a70e9173f9b55\",\"size\":973}]}",
		string(result.Manifest.Data))
	suite.Equal("{\"name\":\"signtest\",\"version\":\"0.1.0\",\"description\":\"A Helm chart for Kubernetes\",\"apiVersion\":\"v1\"}",
		string(result.Config.Data))
	suite.Equal(chartData, result.Chart.Data)
	suite.Equal(provData, result.Prov.Data)
}

func (suite *RegistryClientTestSuite) Test_3_Tags() {

	// Load test chart (to build ref pushed in previous test)
	chartData, err := ioutil.ReadFile("../downloader/testdata/local-subchart-0.1.0.tgz")
	suite.Nil(err, "no error loading test chart")
	meta, err := extractChartMeta(chartData)
	suite.Nil(err, "no error extracting chart meta")
	ref := fmt.Sprintf("%s/testrepo/%s", suite.DockerRegistryHost, meta.Name)

	// Query for tags and validate length
	tags, err := suite.RegistryClient.Tags(ref)
	suite.Nil(err, "no error retrieving tags")
	suite.Equal(1, len(tags))

}

func (suite *RegistryClientTestSuite) Test_4_Logout() {
	err := suite.RegistryClient.Logout("this-host-aint-real:5000")
	suite.NotNil(err, "error logging out of registry that has no entry")

	err = suite.RegistryClient.Logout(suite.DockerRegistryHost)
	suite.Nil(err, "no error logging out of registry")
}

func (suite *RegistryClientTestSuite) Test_5_ManInTheMiddle() {
	ref := fmt.Sprintf("%s/testrepo/supposedlysafechart:9.9.9", suite.CompromisedRegistryHost)

	// returns content that does not match the expected digest
	_, err := suite.RegistryClient.Pull(ref)
	suite.NotNil(err)
	suite.True(errdefs.IsFailedPrecondition(err))
}

func TestRegistryClientTestSuite(t *testing.T) {
	suite.Run(t, new(RegistryClientTestSuite))
}

func initCompromisedRegistryTestServer() string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "manifests") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.WriteHeader(200)

			// layers[0] is the blob []byte("a")
			w.Write([]byte(
				fmt.Sprintf(`{ "schemaVersion": 2, "config": {
    "mediaType": "%s",
    "digest": "sha256:a705ee2789ab50a5ba20930f246dbd5cc01ff9712825bb98f57ee8414377f133",
    "size": 181
  },
  "layers": [
    {
      "mediaType": "%s",
      "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "size": 1
    }
  ]
}`, ConfigMediaType, ChartLayerMediaType)))
		} else if r.URL.Path == "/v2/testrepo/supposedlysafechart/blobs/sha256:a705ee2789ab50a5ba20930f246dbd5cc01ff9712825bb98f57ee8414377f133" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte("{\"name\":\"mychart\",\"version\":\"0.1.0\",\"description\":\"A Helm chart for Kubernetes\\n" +
				"an 'application' or a 'library' chart.\",\"apiVersion\":\"v2\",\"appVersion\":\"1.16.0\",\"type\":" +
				"\"application\"}"))
		} else if r.URL.Path == "/v2/testrepo/supposedlysafechart/blobs/sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" {
			w.Header().Set("Content-Type", ChartLayerMediaType)
			w.WriteHeader(200)
			w.Write([]byte("b"))
		} else {
			w.WriteHeader(500)
		}
	}))

	u, _ := url.Parse(s.URL)
	return fmt.Sprintf("localhost:%s", u.Port())
}

func TestNewTLSConfig(t *testing.T) {
	tests := []struct {
		name   string
		args   *Client
		before func() error
		err    error
		done   func() error
	}{
		{
			name: "caFile_is_not_exist",
			args: &Client{
				caFile: "/tmp/ca1.crt",
			},
			err: os.ErrNotExist,
		},
		{
			name: "caFile_is_exist",
			before: func() error {
				file, err := os.Create("/tmp/ca.crt")
				if err != nil {
					return err
				}
				defer file.Close()
				fmt.Fprint(file, "a")
				return nil
			},
			args: &Client{
				caFile: "/tmp/ca.crt",
			},
			done: func() error {
				os.RemoveAll("/tmp/ca.crt")
				return nil
			},
		},
		{
			name: "keyFile_and_certFile_exist",
			before: func() error {
				max := new(big.Int).Lsh(big.NewInt(1), 128)
				serialNumber, _ := rand.Int(rand.Reader, max)
				subject := pkix.Name{
					Country:            []string{"CN"},
					Province:           []string{"BeiJing"},
					Organization:       []string{"Devops"},
					OrganizationalUnit: []string{"certDevops"},
					CommonName:         "127.0.0.1",
				}

				template := x509.Certificate{
					SerialNumber: serialNumber,
					Subject:      subject,
					NotBefore:    time.Now(),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
				}

				pk, _ := rsa.GenerateKey(rand.Reader, 2048)

				derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
				certOut, _ := os.Create("/tmp/server.pem")
				pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
				certOut.Close()

				keyOut, _ := os.Create("/tmp/server.key")
				pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
				keyOut.Close()
				return nil
			},
			args: &Client{
				keyFile:  "/tmp/server.key",
				certFile: "/tmp/server.pem",
			},
			err: nil,
			done: func() error {
				os.RemoveAll("/tmp/server.key")
				os.RemoveAll("/tmp/server.pem")
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if tt.done != nil {
					tt.done()
				}
			}()
			if tt.before != nil {
				err := tt.before()
				if err != nil {
					t.Fatalf("tt.before() run error,err is %+v", err)
				}
			}
			_, err := newTLSConfig(tt.args)
			if err == nil && tt.err == nil {
				return
			}
			if err != nil && tt.err == nil {
				t.Fatalf("newTLSConfig error, excepte error is %+v, current error is %+v", tt.err, err)
				return
			}
			if err == nil && tt.err != nil {
				t.Fatalf("newTLSConfig error, excepte error is %+v, current error is %+v", tt.err, err)
				return
			}
			if strings.Contains(err.Error(), tt.err.Error()) {
				t.Fatalf("newTLSConfig error, excepte error is %+v, current error is %+v", tt.err, err)
			}

		})
	}
}

func TestNewClient(t *testing.T) {
	getLocalIP := func() (string, error) {
		addrs, err := net.InterfaceAddrs()

		if err != nil {
			return "", err
		}
		for _, address := range addrs {
			// filter loopback ip
			if ipNet, ok := address.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet.IP.String(), nil
				}
			}
		}
		return "", errors.New("can not find the client ip address")
	}
	ip, err := getLocalIP()
	if err != nil {
		t.Fatalf("getLocalIP is error %+v", err)
	}
	type ServerAndClientTSL struct {
		ServerKey  string
		ServerCert string
		ClientKey  string
		ClientCert string
		CAKey      string
		CaCert     string
	}
	doneRemoveFunc := func(keyAndCret *ServerAndClientTSL) error {
		if keyAndCret != nil {
			os.Remove(keyAndCret.CAKey)
			os.Remove(keyAndCret.CaCert)
			os.Remove(keyAndCret.ClientKey)
			os.Remove(keyAndCret.ClientCert)
			os.Remove(keyAndCret.ServerKey)
			os.Remove(keyAndCret.ServerCert)
		}
		return nil
	}
	createCertificateFile := func(name string, cert *x509.Certificate, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
		if caKey == nil {
			caKey = key
		}
		derBytes, _ := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
		certOut, _ := os.Create(name + ".pem")
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()

		keyOut, _ := os.Create(name + ".key")
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		keyOut.Close()
	}
	serverAndClientTSLKeyAndCret := func(i string) (*ServerAndClientTSL, error) {
		max := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, _ := rand.Int(rand.Reader, max)
		subject := pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"BeiJing"},
			Organization:       []string{"Devops"},
			OrganizationalUnit: []string{"certDevops"},
			CommonName:         ip,
		}
		ca := &x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IPAddresses:           []net.IP{net.ParseIP(ip)},
		}
		privCa, _ := rsa.GenerateKey(rand.Reader, 2048)
		var (
			caFileName     = fmt.Sprintf("%s_%s", "/tmp/ca", i)
			serverFileName = fmt.Sprintf("%s_%s", "/tmp/server", i)
			clientFileName = fmt.Sprintf("%s_%s", "/tmp/client", i)
		)
		createCertificateFile(caFileName, ca, privCa, ca, nil)
		server := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			SubjectKeyId: []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IPAddresses:  []net.IP{net.ParseIP(ip)},
		}
		privSer, _ := rsa.GenerateKey(rand.Reader, 2048)
		createCertificateFile(serverFileName, server, privSer, ca, privCa)
		client := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			SubjectKeyId: []byte{1, 2, 3, 4, 7},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IPAddresses:  []net.IP{net.ParseIP(ip)},
		}
		privCli, _ := rsa.GenerateKey(rand.Reader, 2048)
		createCertificateFile(clientFileName, client, privCli, ca, privCa)

		return &ServerAndClientTSL{
			ServerCert: fmt.Sprintf("%s.pem", serverFileName),
			ServerKey:  fmt.Sprintf("%s.key", serverFileName),
			ClientCert: fmt.Sprintf("%s.pem", clientFileName),
			ClientKey:  fmt.Sprintf("%s.key", clientFileName),
			CaCert:     fmt.Sprintf("%s.pem", caFileName),
			CAKey:      fmt.Sprintf("%s.key", caFileName),
		}, nil
	}
	startRegistryServer := func(config *configuration.Configuration) (string, error) {
		// Registry config
		port, err := freeport.GetFreePort()
		if err != nil {
			return "", err
		}
		config.HTTP.Addr = fmt.Sprintf("%s:%d", ip, port)
		config.HTTP.DrainTimeout = time.Duration(10) * time.Second
		config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
		dockerRegistry, err := registry.NewRegistry(context.Background(), config)
		if err != nil {
			return "", err
		}
		// Start Docker registry
		go func() {
			err = dockerRegistry.ListenAndServe()
			if err != nil {
				panic(err)
				return
			}
		}()
		return config.HTTP.Addr, nil
	}
	tests := []struct {
		name   string
		args   []ClientOption
		before func() ([]ClientOption, string, *ServerAndClientTSL, error)
		err    error
		done   func(keyAndCret *ServerAndClientTSL) error
		ctx    context.Context
	}{
		{
			name: "ServerHttp_ClientOCI_NoOpenRegistryInsecurity_Fail", //OCI is default use https
			before: func() ([]ClientOption, string, *ServerAndClientTSL, error) {
				// start registry
				config := &configuration.Configuration{}
				refHostAndPort, err := startRegistryServer(config)
				if err != nil {
					return nil, "", nil, err
				}
				// config option
				time.Sleep(1 * time.Second)
				return nil, refHostAndPort, nil, nil
			},
			args: nil,
			done: doneRemoveFunc,
			err:  errors.New("http: server gave HTTP response to HTTPS client"),
		},
		{
			name: "ServerHttp_ClientOCI_OpenRegistryInsecurity_PAAS", //OCI is default use https
			before: func() ([]ClientOption, string, *ServerAndClientTSL, error) {
				// start registry
				config := &configuration.Configuration{}
				refHostAndPort, err := startRegistryServer(config)
				if err != nil {
					return nil, "", nil, err
				}
				// config option
				options := []ClientOption{
					ClientPlainHTTP(),
				}
				time.Sleep(1 * time.Second)
				return options, refHostAndPort, nil, nil
			},
			args: nil,
			done: doneRemoveFunc,
			err:  nil,
		},
		{
			name: "ServerHttps_ClientNoUserHttps_Fail",
			before: func() ([]ClientOption, string, *ServerAndClientTSL, error) {
				keyAndCret, err := serverAndClientTSLKeyAndCret("3")
				if err != nil {
					return nil, "", nil, err
				}
				// start https registry
				config := &configuration.Configuration{}
				config.HTTP.TLS.Key = keyAndCret.ServerKey
				config.HTTP.TLS.Certificate = keyAndCret.ServerCert
				refHostAndPort, err := startRegistryServer(config)
				if err != nil {
					return nil, "", keyAndCret, err
				}
				// config option
				time.Sleep(1 * time.Second)
				return nil, refHostAndPort, keyAndCret, nil
			},
			args: nil,
			done: doneRemoveFunc,
			err:  errors.New("certificate is not trusted"),
		},
		{
			name: "ServerHttps_ClientUserSkipVerifyTLS_PASS",
			before: func() ([]ClientOption, string, *ServerAndClientTSL, error) {
				keyAndCret, err := serverAndClientTSLKeyAndCret("4")
				if err != nil {
					return nil, "", nil, err
				}
				// start https registry
				config := &configuration.Configuration{}
				config.HTTP.TLS.Key = keyAndCret.ServerKey
				config.HTTP.TLS.Certificate = keyAndCret.ServerCert
				refHostAndPort, err := startRegistryServer(config)
				if err != nil {
					return nil, "", keyAndCret, err
				}
				// config option
				options := []ClientOption{
					ClientOptInsecureSkipVerifyTLS(true),
				}
				time.Sleep(1 * time.Second)
				return options, refHostAndPort, keyAndCret, nil
			},
			args: nil,
			done: doneRemoveFunc,
			err:  nil,
		},
		{
			name: "ServerHttps_ClientUserHttps_PASS",
			before: func() ([]ClientOption, string, *ServerAndClientTSL, error) {
				keyAndCret, err := serverAndClientTSLKeyAndCret("5")
				if err != nil {
					return nil, "", nil, err
				}
				// start https registry
				config := &configuration.Configuration{}
				config.HTTP.TLS.Key = keyAndCret.ServerKey
				config.HTTP.TLS.Certificate = keyAndCret.ServerCert
				refHostAndPort, err := startRegistryServer(config)
				if err != nil {
					return nil, "", keyAndCret, err
				}
				// config option
				options := []ClientOption{
					ClientOptTLSConfig(keyAndCret.CaCert, "", ""),
				}
				time.Sleep(1 * time.Second)
				return options, refHostAndPort, keyAndCret, nil
			},
			args: nil,
			done: doneRemoveFunc,
			err:  nil,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {

			var (
				refHostAndPort string
				options        []ClientOption
				err            error
				keyAndCret     *ServerAndClientTSL
			)
			defer func() {
				if tt.done != nil {
					tt.done(keyAndCret)
				}
			}()
			if tt.before != nil {
				options, refHostAndPort, keyAndCret, err = tt.before()
				if err != nil {
					t.Fatalf("%s test task fail,error is %+v", tt.name, err)
					return
				}
				tt.args = options
			}
			client, err := NewClient(tt.args...)
			if err != nil {
				t.Fatalf("%s test task fail,error is %+v", tt.name, err)
				return
			}

			chartData, err := ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz")
			if err != nil {
				t.Fatalf("no error loading test chart")
				return
			}
			meta, err := extractChartMeta(chartData)
			if err != nil {
				t.Fatalf("no error extracting chart meta")
				return
			}
			// Load prov file
			provData, err := ioutil.ReadFile("../downloader/testdata/signtest-0.1.0.tgz.prov")
			if err != nil {
				t.Fatalf("no error loading test prov")
				return
			}

			// push with prov
			href := fmt.Sprintf("%s/testrepo", refHostAndPort)
			ref := fmt.Sprintf("%s:%s",
				path.Join(strings.TrimPrefix(href, fmt.Sprintf("%s://", "oci")), meta.Name),
				meta.Version)
			t.Logf("helm push to:%s", ref)
			result, err := client.Push(chartData, ref, PushOptProvData(provData))
			if err != nil {
				t.Logf(err.Error())
				if tt.err == nil {
					t.Fatalf("client push error, expect error is %+v,current error is %+v", tt.err, err)
					return
				}
				if tt.err != nil && !strings.Contains(err.Error(), tt.err.Error()) {
					t.Fatalf("client push error, expect error is %+v,current error is %+v", tt.err, err)
					return
				}
			}
			_, err = client.Pull(ref)
			if err != nil {
				if tt.err == nil {
					t.Fatalf("no error pulling a simple chart")
					return
				}
				if tt.err != nil && !strings.Contains(err.Error(), tt.err.Error()) {
					t.Fatalf("no error pulling a simple chart")
					return
				}
			}

			if tt.err != nil {
				return
			}

			// Validate the output
			// Note: these digests/sizes etc may change if the test chart/prov files are modified,
			// or if the format of the OCI manifest changes
			assertions := assert.New(t)
			assertions.Equal(ref, result.Ref)
			assertions.Equal(meta.Name, result.Chart.Meta.Name)
			assertions.Equal(meta.Version, result.Chart.Meta.Version)
			assertions.Equal(int64(512), result.Manifest.Size)
			assertions.Equal(int64(99), result.Config.Size)
			assertions.Equal(int64(973), result.Chart.Size)
			assertions.Equal(int64(695), result.Prov.Size)
			assertions.Equal(
				"sha256:af4c20a1df1431495e673c14ecfa3a2ba24839a7784349d6787cd67957392e83",
				result.Manifest.Digest)
			assertions.Equal(
				"sha256:8d17cb6bf6ccd8c29aace9a658495cbd5e2e87fc267876e86117c7db681c9580",
				result.Config.Digest)
			assertions.Equal(
				"sha256:e5ef611620fb97704d8751c16bab17fedb68883bfb0edc76f78a70e9173f9b55",
				result.Chart.Digest)
			assertions.Equal(
				"sha256:b0a02b7412f78ae93324d48df8fcc316d8482e5ad7827b5b238657a29a22f256",
				result.Prov.Digest)
		})
	}

}
