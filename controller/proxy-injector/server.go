package injector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/linkerd/linkerd2/pkg/k8s"
	pkgTls "github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Server is the HTTP server that serves inject requests coming from both the
// CLI and admission controller webhook. It has an embedded webhook which mutate
// all the requests.
type Server struct {
	*http.Server
	*Webhook
	*Injector
}

// NewServer returns a new instance of the Server.
func NewServer(client kubernetes.Interface, addr, controllerNamespace string, noInitContainer, tlsEnabled bool, rootCA *pkgTls.CA) (*Server, error) {
	c, err := tlsConfig(rootCA, controllerNamespace)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: c,
	}
	serveMux := http.NewServeMux()

	webhook, err := NewWebhook(client, controllerNamespace, noInitContainer, tlsEnabled)
	if err != nil {
		return nil, err
	}

	injector, err := NewInjector()
	if err != nil {
		return nil, err
	}

	ws := &Server{server, webhook, injector}

	serveMux.HandleFunc("/webhook", ws.serveWebhook)
	serveMux.HandleFunc("/injector", ws.serveInjector)
	ws.Handler = serveMux
	return ws, nil
}

func (w *Server) serveWebhook(res http.ResponseWriter, req *http.Request) {
	var (
		data []byte
		err  error
	)
	if req.Body != nil {
		data, err = ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if len(data) == 0 {
		return
	}

	response := w.Mutate(data)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := res.Write(responseJSON); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (w *Server) serveInjector(res http.ResponseWriter, req *http.Request) {
	var (
		data []byte
		err  error
	)
	if req.Body != nil {
		data, err = ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if len(data) == 0 {
		return
	}

	log.Infof("received inject request: %s\n", data)
	result, err := w.Inject(data)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	patch, err := json.Marshal(result)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("returning inject patch: %s\n", patch)
	if _, err := res.Write(patch); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Shutdown initiates a graceful shutdown of the underlying HTTP server.
func (w *Server) Shutdown() error {
	return w.Server.Shutdown(context.Background())
}

func tlsConfig(rootCA *pkgTls.CA, controllerNamespace string) (*tls.Config, error) {
	tlsIdentity := k8s.TLSIdentity{
		Name:                "linkerd-proxy-injector",
		Kind:                k8s.Service,
		Namespace:           controllerNamespace,
		ControllerNamespace: controllerNamespace,
	}
	dnsName := tlsIdentity.ToDNSName()
	cred, err := rootCA.GenerateEndEntityCred(dnsName)
	if err != nil {
		return nil, err
	}

	certPEM := cred.EncodePEM()
	log.Debugf("PEM-encoded certificate: %s\n", certPEM)

	keyPEM := cred.EncodePrivateKeyPEM()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
