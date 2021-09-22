module custom-kms

go 1.16

require (
	go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/exporters/metric/prometheus v0.20.0
	go.opentelemetry.io/otel/metric v0.20.0
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	google.golang.org/grpc v1.38.0
	k8s.io/apiserver v0.21.1
	k8s.io/component-base v0.21.1
	k8s.io/klog/v2 v2.9.0
)
