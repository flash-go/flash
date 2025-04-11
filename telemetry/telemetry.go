package telemetry

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"runtime/metrics"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	metricSdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	traceSdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

type Telemetry interface {
	Tracer(name string) trace.Tracer
	Meter(name string) metric.Meter

	NewMetricInt64Counter(meter, name string, register bool, options ...metric.Int64CounterOption) (metric.Int64Counter, error)
	NewMetricInt64UpDownCounter(meter, name string, register bool, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error)
	NewMetricInt64Histogram(meter, name string, register bool, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error)
	NewMetricInt64Gauge(meter, name string, register bool, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error)
	NewMetricFloat64Counter(meter, name string, register bool, options ...metric.Float64CounterOption) (metric.Float64Counter, error)
	NewMetricFloat64UpDownCounter(meter, name string, register bool, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error)
	NewMetricFloat64Histogram(meter, name string, register bool, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error)
	NewMetricFloat64Gauge(meter, name string, register bool, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error)

	GetMetricInt64Counter(name string) metric.Int64Counter
	GetMetricInt64UpDownCounter(name string) metric.Int64UpDownCounter
	GetMetricInt64Histogram(name string) metric.Int64Histogram
	GetMetricInt64Gauge(name string) metric.Int64Gauge
	GetMetricFloat64Counter(name string) metric.Float64Counter
	GetMetricFloat64UpDownCounter(name string) metric.Float64UpDownCounter
	GetMetricFloat64Histogram(name string) metric.Float64Histogram
	GetMetricFloat64Gauge(name string) metric.Float64Gauge

	CollectGoRuntimeMetrics(timeout time.Duration) Telemetry
	GetMetricsHttpHandler() http.Handler
}

type telemetry struct {
	traceProvider *traceSdk.TracerProvider
	meterProvider *metricSdk.MeterProvider
	// metrics
	metricInt64Counter         map[string]metric.Int64Counter
	metricInt64UpDownCounter   map[string]metric.Int64UpDownCounter
	metricInt64Histogram       map[string]metric.Int64Histogram
	metricInt64Gauge           map[string]metric.Int64Gauge
	metricFloat64Counter       map[string]metric.Float64Counter
	metricFloat64UpDownCounter map[string]metric.Float64UpDownCounter
	metricFloat64Histogram     map[string]metric.Float64Histogram
	metricFloat64Gauge         map[string]metric.Float64Gauge
}

// trace exporters

func NewTraceExporterStdout(options ...stdouttrace.Option) (traceSdk.SpanExporter, error) {
	exporter, err := stdouttrace.New(options...)
	if err != nil {
		return nil, err
	}
	return exporter, nil
}

func NewTraceExporterOtlpGrpc(ctx context.Context, options ...otlptracegrpc.Option) (traceSdk.SpanExporter, error) {
	return otlptracegrpc.New(ctx, options...)
}

// metric exporters

func NewMetricExporterPeriodicStdout(interval, timeout time.Duration, options ...stdoutmetric.Option) (metricSdk.Reader, error) {
	exporter, err := stdoutmetric.New(options...)
	if err != nil {
		return nil, err
	}
	return metricSdk.NewPeriodicReader(
		exporter,
		metricSdk.WithInterval(interval),
		metricSdk.WithTimeout(timeout),
	), nil
}

func NewMetricExporterPeriodicOtlpGrpc(interval, timeout time.Duration, ctx context.Context, options ...otlpmetricgrpc.Option) (metricSdk.Reader, error) {
	exporter, err := otlpmetricgrpc.New(
		ctx,
		options...,
	/*
		otlpmetrichttp.WithProxy(
			otlpmetrichttp.HTTPTransportProxyFunc(
				func(req *http.Request) (*url.URL, error) {
					bodyBytes, err := io.ReadAll(req.Body)
					if err != nil {
						fmt.Println("err read:", err)
						return nil, err
					}
					fmt.Println("Raw Protobuf Data:", bodyBytes)
					var metricsRequest v1.ExportMetricsServiceRequest
					if err := proto.Unmarshal(bodyBytes, &metricsRequest); err != nil {
						fmt.Println("err dec protobuf:", err)
					} else {
						fmt.Println("decoded metrics:", &metricsRequest)
					}
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					return req.URL, nil
				},
			),
		),
	*/
	)
	if err != nil {
		return nil, err
	}
	return metricSdk.NewPeriodicReader(
		exporter,
		metricSdk.WithInterval(interval),
		metricSdk.WithTimeout(timeout),
	), nil
}

func NewMetricExporterPrometheus() (metricSdk.Reader, error) {
	return prometheus.New()
}

// providers

func NewTraceProvider(service string, traceExporter traceSdk.SpanExporter) *traceSdk.TracerProvider {
	return traceSdk.NewTracerProvider(
		traceSdk.WithBatcher(traceExporter),
		traceSdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(service),
		)),
	)
}

func NewMeterProvider(service string, metricExporter metricSdk.Reader) *metricSdk.MeterProvider {
	return metricSdk.NewMeterProvider(
		metricSdk.WithReader(metricExporter),
		metricSdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(service),
		)),
		//metricSdk.WithExemplarFilter(exemplar.TraceBasedFilter),
	)
}

// service

func New(service string, traceExporter traceSdk.SpanExporter, metricExporter metricSdk.Reader) Telemetry {
	// Sets the global way of passing context between services, via headers.
	// It is used for:
	// - Context injection (Inject) - when you send a request to another service.
	// - Extract context - when you receive an incoming request with headers.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &telemetry{
		// providers
		traceProvider: NewTraceProvider(service, traceExporter),
		meterProvider: NewMeterProvider(service, metricExporter),
		// metrics
		metricInt64Counter:         make(map[string]metric.Int64Counter),
		metricInt64UpDownCounter:   make(map[string]metric.Int64UpDownCounter),
		metricInt64Histogram:       make(map[string]metric.Int64Histogram),
		metricInt64Gauge:           make(map[string]metric.Int64Gauge),
		metricFloat64Counter:       make(map[string]metric.Float64Counter),
		metricFloat64UpDownCounter: make(map[string]metric.Float64UpDownCounter),
		metricFloat64Histogram:     make(map[string]metric.Float64Histogram),
		metricFloat64Gauge:         make(map[string]metric.Float64Gauge),
	}
}

func (t *telemetry) Tracer(name string) trace.Tracer {
	return t.traceProvider.Tracer(name)
}

func (t *telemetry) Meter(name string) metric.Meter {
	return t.meterProvider.Meter(name)
}

func (t *telemetry) NewMetricInt64Counter(meter, name string, register bool, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	metric, err := t.meterProvider.Meter(meter).Int64Counter(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Int64Counter): %w", err)
	}
	if register {
		t.metricInt64Counter[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricInt64UpDownCounter(meter, name string, register bool, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	metric, err := t.meterProvider.Meter(meter).Int64UpDownCounter(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Int64UpDownCounter): %w", err)
	}
	if register {
		t.metricInt64UpDownCounter[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricInt64Histogram(meter, name string, register bool, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	metric, err := t.meterProvider.Meter(meter).Int64Histogram(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Int64Histogram): %w", err)
	}
	if register {
		t.metricInt64Histogram[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricInt64Gauge(meter, name string, register bool, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	metric, err := t.meterProvider.Meter(meter).Int64Gauge(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Int64Gauge): %w", err)
	}
	if register {
		t.metricInt64Gauge[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricFloat64Counter(meter, name string, register bool, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	metric, err := t.meterProvider.Meter(meter).Float64Counter(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Float64Counter): %w", err)
	}
	if register {
		t.metricFloat64Counter[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricFloat64UpDownCounter(meter, name string, register bool, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	metric, err := t.meterProvider.Meter(meter).Float64UpDownCounter(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Float64UpDownCounter): %w", err)
	}
	if register {
		t.metricFloat64UpDownCounter[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricFloat64Histogram(meter, name string, register bool, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	metric, err := t.meterProvider.Meter(meter).Float64Histogram(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Float64Histogram): %w", err)
	}
	if register {
		t.metricFloat64Histogram[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) NewMetricFloat64Gauge(meter, name string, register bool, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	metric, err := t.meterProvider.Meter(meter).Float64Gauge(name, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating metric (Float64Gauge): %w", err)
	}
	if register {
		t.metricFloat64Gauge[meter+"-"+name] = metric
	}
	return metric, nil
}

func (t *telemetry) GetMetricInt64Counter(name string) metric.Int64Counter {
	return t.metricInt64Counter[name]
}

func (t *telemetry) GetMetricInt64UpDownCounter(name string) metric.Int64UpDownCounter {
	return t.metricInt64UpDownCounter[name]
}

func (t *telemetry) GetMetricInt64Histogram(name string) metric.Int64Histogram {
	return t.metricInt64Histogram[name]
}

func (t *telemetry) GetMetricInt64Gauge(name string) metric.Int64Gauge {
	return t.metricInt64Gauge[name]
}

func (t *telemetry) GetMetricFloat64Counter(name string) metric.Float64Counter {
	return t.metricFloat64Counter[name]
}

func (t *telemetry) GetMetricFloat64UpDownCounter(name string) metric.Float64UpDownCounter {
	return t.metricFloat64UpDownCounter[name]
}

func (t *telemetry) GetMetricFloat64Histogram(name string) metric.Float64Histogram {
	return t.metricFloat64Histogram[name]
}

func (t *telemetry) GetMetricFloat64Gauge(name string) metric.Float64Gauge {
	return t.metricFloat64Gauge[name]
}

func (t *telemetry) CollectGoRuntimeMetrics(timeout time.Duration) Telemetry {
	meter := "runtime"
	allMetrics := metrics.All()
	samples := make([]metrics.Sample, 0, len(allMetrics))
	cumulative := make(map[string]bool)

	for _, item := range allMetrics {
		samples = append(samples, metrics.Sample{Name: item.Name})

		name, unit, err := parseGoMetricName(item.Name)
		if err != nil {
			log.Printf("error parsing metric name: %s", item.Name)
		}

		var cError error

		switch item.Kind {
		case metrics.KindUint64:
			if item.Cumulative {
				_, cError = t.NewMetricInt64Counter(
					meter,
					name,
					true,
					metric.WithDescription(item.Description),
					metric.WithUnit(unit),
				)
			} else {
				_, cError = t.NewMetricInt64Gauge(
					meter,
					name,
					true,
					metric.WithDescription(item.Description),
					metric.WithUnit(unit),
				)
			}
		case metrics.KindFloat64:
			if item.Cumulative {
				_, cError = t.NewMetricFloat64Counter(
					meter,
					name,
					true,
					metric.WithDescription(item.Description),
					metric.WithUnit(unit),
				)
			} else {
				_, cError = t.NewMetricFloat64Gauge(
					meter,
					name,
					true,
					metric.WithDescription(item.Description),
					metric.WithUnit(unit),
				)
			}
		case metrics.KindFloat64Histogram:
			_, cError = t.NewMetricFloat64Histogram(
				meter,
				name,
				true,
				metric.WithDescription(item.Description),
				metric.WithUnit(unit),
			)
		}

		if cError != nil {
			log.Printf("error creating metric: %v", err)
		}

		cumulative[name] = item.Cumulative
	}

	go func() {
		for range time.Tick(timeout) {
			metrics.Read(samples)
			for _, sample := range samples {
				name, _, err := parseGoMetricName(sample.Name)
				if err != nil {
					log.Printf("error parsing metric name: %s", sample.Name)
				}

				index := meter + "-" + name
				ctx := context.Background()

				switch sample.Value.Kind() {
				case metrics.KindUint64:
					if cumulative[name] {
						t.metricInt64Counter[index].Add(ctx, int64(sample.Value.Uint64()))
					} else {
						t.metricInt64Gauge[index].Record(ctx, int64(sample.Value.Uint64()))
					}
				case metrics.KindFloat64:
					value := sample.Value.Float64()
					if cumulative[name] {
						if !math.IsNaN(value) && !math.IsInf(value, 0) {
							t.metricFloat64Counter[index].Add(ctx, value)
						}
					} else {
						if !math.IsNaN(value) && !math.IsInf(value, 0) {
							t.metricFloat64Gauge[index].Record(ctx, value)
						} else {
							t.metricFloat64Gauge[index].Record(ctx, 0)
						}
					}
				case metrics.KindFloat64Histogram:
					if cumulative[name] {
						var sum float64
						for i, count := range sample.Value.Float64Histogram().Counts {
							bucket := sample.Value.Float64Histogram().Buckets[i]
							if !math.IsNaN(bucket) && !math.IsInf(bucket, 0) {
								sum += float64(count) * bucket
							}
						}
						if !math.IsNaN(sum) && !math.IsInf(sum, 0) {
							t.metricFloat64Histogram[index].Record(ctx, sum)
						} else {
							t.metricFloat64Histogram[index].Record(ctx, 0)
						}
					} else {
						var sum float64
						var totalCount uint64
						for i, count := range sample.Value.Float64Histogram().Counts {
							bucket := sample.Value.Float64Histogram().Buckets[i]
							if !math.IsNaN(bucket) && !math.IsInf(bucket, 0) {
								sum += float64(count) * bucket
								totalCount += count
							}
						}
						if totalCount > 0 {
							avg := sum / float64(totalCount)
							if !math.IsNaN(avg) && !math.IsInf(avg, 0) {
								t.metricFloat64Histogram[index].Record(ctx, avg)
							} else {
								t.metricFloat64Histogram[index].Record(ctx, 0)
							}
						} else {
							t.metricFloat64Histogram[index].Record(ctx, 0)
						}
					}
				}
			}
		}
	}()

	return t
}

func (t *telemetry) GetMetricsHttpHandler() http.Handler {
	return promhttp.Handler()
}

// internal

func parseGoMetricName(input string) (string, string, error) {
	matches := regexp.MustCompile(`^(?P<name>/[^:]+):(?P<unit>[^:*/]+(?:[*/][^:*/]+)*)$`).FindStringSubmatch(input)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("error parsing metric name: %s", input)
	}
	return sanitizeMetricName(matches[1]), matches[2], nil
}

func sanitizeMetricName(input string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	sanitized := re.ReplaceAllString(input, "_")
	return strings.Trim(sanitized, "_")
}
