package telemetry

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

func Start(ctx context.Context) (func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}
	e, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	p := trace.NewTracerProvider(trace.WithBatcher(e), trace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", "aegis-gateway"))))
	otel.SetTracerProvider(p)
	return p.Shutdown, nil
}
