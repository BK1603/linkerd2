package injector

import (
	"bytes"
	"encoding/json"
	"io/ioutil"

	"github.com/golang/protobuf/jsonpb"
	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/inject"
	"github.com/linkerd/linkerd2/pkg/k8s"
)

// Injector responds to the CLI requests to to inject proxy specs into
// Kubernetes resources manifests.
type Injector struct {
	config *inject.ResourceConfig
}

// NewInjector returns a new instance of Injector.
func NewInjector() (*Injector, error) {
	gcRaw, err := ioutil.ReadFile(k8s.MountPathGlobalConfig)
	if err != nil {
		return nil, err
	}

	pcRaw, err := ioutil.ReadFile(k8s.MountPathProxyConfig)
	if err != nil {
		return nil, err
	}

	unmarshaler := &jsonpb.Unmarshaler{}
	var gc pb.GlobalConfig
	if err := unmarshaler.Unmarshal(bytes.NewReader(gcRaw), &gc); err != nil {
		return nil, err
	}

	var pc pb.ProxyConfig
	if err := unmarshaler.Unmarshal(bytes.NewReader(pcRaw), &pc); err != nil {
		return nil, err
	}

	return &Injector{
		config: inject.NewResourceConfig(&gc, &pc),
	}, nil
}

// Inject uses the provided Kubernetes resource YAML to generate JSON patches containing
// the proxy container specs.
func (i *Injector) Inject(yaml []byte) (*InjectResult, error) {
	patch, report, err := i.config.PatchForYaml(yaml)
	if err != nil {
		return nil, err
	}

	reportRaw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}

	return &InjectResult{Patch: patch, Report: reportRaw}, nil
}

// InjectResult encapsulates the proxy specs JSON patches and report content
// for the CLI.
type InjectResult struct {
	// Patch contains the proxy specs in the form of JSON patches per definition
	// in RFC 6902.
	Patch []byte

	// Report contains the report content for the CLI.
	Report []byte
}
