# Flash framework
```
███████╗██╗      █████╗ ███████╗██╗  ██╗
██╔════╝██║     ██╔══██╗██╔════╝██║  ██║
█████╗  ██║     ███████║███████╗███████║
██╔══╝  ██║     ██╔══██║╚════██║██╔══██║
██║     ███████╗██║  ██║███████║██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

A high-performance web framework written in Go for building enterprise-grade distributed applications based on microservice architecture.

### Features

- HTTP transport
  - Extreme client/server performance built on the [FastHTTP](https://github.com/valyala/fasthttp)
  - Up to 10x faster than net/http
  - Designed for high-performance edge cases
  - Zero memory allocations in hot paths
  - Lightweight high performance HTTP [router](https://github.com/fasthttp/router)
  - Outgoing requests to services with loadbalancer
  - Middleware support

- Log aggregation
  - Based on [zerolog](https://github.com/rs/zerolog)
  - Zero memory allocations
  - Supports data export to
    - io.Writer
	- Console
    - Elasticsearch

- Distributed tracing and metrics
  - Go Runtime metrics
  - Incoming requests metrics
  - Application-specific metrics
  - Custom tracer exporters
    - io.Writer
	- OpenTelemetry collector (gRPC)
  - Custom metric exporters
    - io.Writer
	- OpenTelemetry collector (gRPC)
    - Prometheus
  - Inject/extract tracers from requests
  - Based on OpenTelemetry

- Service discovery and distributed KV storage
  - Get/watch services and values by keys
  - Get target service with loadbalancer
  - Based on Consul

- Automatic Swagger documentation generation

- Support for pprof profiling

### Install

```bash
go get github.com/flash-go/flash
```

## State

Service discovery and hot configuration updates via distributed KV storage on the Consul base.

### Create service

```go
package main

import (
	"github.com/flash-go/flash/state"
	"github.com/hashicorp/consul/api"
)

func main() {
	// Define Consul address
	consulAddress := "localhost:8500"

	// Create state config
	config := api.DefaultConfig()
	config.Address = consulAddress

	// Create state service
	stateService, err := state.New(config)
}
```

### Register service

```go
package main

import (
	"fmt"
	"github.com/hashicorp/consul/api"
)

func main() {
	serviceName := "api"
	instanceHostname := "host.docker.internal"
	instancePort := 8001

	// Create state service
	stateService := {...}

	// Register service
	err := stateService.ServiceRegister(
		&api.AgentServiceRegistration{
			// Instance ID
			ID:      fmt.Sprintf("%s-%s-%d", serviceName, instanceHostname, instancePort),
			// Service name
			Name:    serviceName,
			// Instance port
			Port:    instancePort,
			// Instance hostname
			Address: instanceHostname,
			// Check health settings
			Check: &api.AgentServiceCheck{
				HTTP:                           fmt.Sprintf("http://%s:%d/health", instanceHostname, instancePort),
				Interval:                       "10s",
				Timeout:                        "1s",
				DeregisterCriticalServiceAfter: "1m",
			},
		},
	)
}
```

### Deregister service

```go
package main

func main() {
	// Create state service
	stateService := {...}

	// Target instance id
	instanceId := "api"

	// Deregister service
	err := stateService.ServiceDeregister(instanceId)
}
```

### Get value

Getting a value by key "host" once

```go
package main

import (
	"fmt"
)

func main() {
	// Create state service
	stateService := {...}

	// Target key
	key := "host"

	// Get value by key
	value, err := stateService.GetValue(key)

	// Current value
	fmt.Printf(value)
}
```

### Watch value

Tracking value changes by key "host"

```go
package main

import (
	"fmt"
)

func main() {
	// Create state service
	stateService := {...}

	// Target key
	key := "host"

	// Watch value by key
	value, err := stateService.WatchValue(key, func(value string) {
		// Updated value
		fmt.Printf(value)
	})

	// Current value
	fmt.Printf(value)
}
```

### Get instances

One-time retrieval of a list of instances by service name "api"

```go
package main

import (
	"fmt"
)

func main() {
	// Create state service
	stateService := {...}

	// Service name
	service := "api"

	// Get instances by service
	instances, err := stateService.GetInstances(service)

	// Current instances
	fmt.Println(instances)
}
```

### Watch instances

Subscribe to update the instance list of services by service name "api"

```go
package main

import (
	"fmt"
	"github.com/hashicorp/consul/api"
)

func main() {
	// Create state service
	stateService := {...}

	// Service name
	service := "api"

	// Watch instances by service
	instances, err := stateService.WatchInstances(service, func(instances []*api.CatalogService) {
		// Updated instances
		fmt.Println(instances)
	})

	// Current instances
	fmt.Println(instances)
}
```

### Get instance

Get a random instance of service "api"

```go
package main

import (
	"fmt"
)

func main() {
	// Create state service
	stateService := {...}

	// Service name
	service := "api"

	// Get random instance by service
	service, err := stateService.GetInstance(service)

	// Random instance
	fmt.Println(service)
}
```

## Logger

Log aggregation system based on [zerolog](https://github.com/rs/zerolog) with data export to Elasticsearch or other storage.

### Create service

io.Writer

```go
package main

import (
	"os"
	"github.com/flash-go/flash/logger"
)

func main() {
	// Create logger service
	loggerService := logger.New(os.Stdout)
}
```

Console

```go
package main

import (
	"os"
	"time"
	"github.com/flash-go/flash/logger"
	"github.com/rs/zerolog"
)

func main() {
	// Define console logger settings
	consoleLoggerSettings := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	// Create console logger
	consoleLogger := logger.NewConsole(consoleLoggerSettings)

	// Create logger service
	loggerService := logger.New(consoleLogger)
}
```

Elasticsearch

```go
package main

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/flash-go/flash/logger"
)

func main() {
	// Define elasticsearch config
	elasticSearchConfig := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200",
		},
	}

	// Create elasticsearch client
	client, err := elasticsearch.NewClient(elasticSearchConfig)

	// Create elasticsearch logger
	elasticsearchLogger := logger.NewElasticsearch(
		client,	// client
		"logs",	// index
	)

	// Create logger service
	loggerService := logger.New(elasticsearchLogger)
}
```

### Set level

```go
loggerService.SetLevel(zerolog.DebugLevel)
```

### Write

Levels

```go
loggerService.Log().Trace()
loggerService.Log().Debug()
loggerService.Log().Info()
loggerService.Log().Warn()
loggerService.Log().Error()
loggerService.Log().Fatal()
loggerService.Log().Panic()
```

Messages

```go
loggerService.Log().Info().Msg("message")
loggerService.Log().Info().Msgf("message: %s", message)
```

## Telemetry

Distributed tracing system and runtime state and incoming request metrics collection with support for custom metrics to track application-specific data based on OpenTelemetry.

### Create service

Traces and metrics are handled via the telemetry service. To create a telemetry service, you need to create exporters for traces and metrics. Exporters define the strategy for processing traces and metrics.

```go
package main

import (
	"github.com/flash-go/flash/telemetry"
)

func main() {
	// Create trace exporter
	traceExporter := {...}

	// Create metric exporter
	metricExporter := {...}

	// Define telemetry service name
	serviceName := "api"

	// Create telemetry service
	telemetryService := telemetry.New(serviceName, traceExporter, metricExporter)
}
```

### Create trace exporter

Uses standard output to collect traces. Behavior is configurable via optional.

```go
package main

import (
	"os"
	"github.com/flash-go/flash/telemetry"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
)

func main() {
	// Create trace exporter
	traceExporter, err := telemetry.NewTraceExporterStdout(
		// optional
		stdouttrace.WithWriter(os.Stdout),
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithoutTimestamps(),
		stdouttrace.With...
	)
}
```

Uses OTEL collector via gRPC to collect traces. Behavior is configurable via optional.

```go
package main

import (
	"context"
	"github.com/flash-go/flash/telemetry"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
)

func main() {
	otelCollectorGrpcEndpoint := "localhost:4317"

	// Create trace exporter
	traceExporter, err := telemetry.NewTraceExporterOtlpGrpc(
		context.TODO(),
		// optional
		otlptracegrpc.WithEndpoint(otelCollectorGrpcEndpoint), 
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.With...
	)
}
```

### Create metric exporter

Uses standard output to collect metrics. Metrics are collected once every [interval] waiting for [timeout]. Behavior is configurable via optional.

```go
package main

import (
	"os"
	"time"
	"github.com/flash-go/flash/telemetry"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
)

func main() {
	// Create metric exporter
	metricExporter, err := telemetry.NewMetricExporterPeriodicStdout(
		30*time.Second, // interval
		10*time.Second, // timeout
		// optional
		stdoutmetric.WithWriter(os.Stdout),
		stdoutmetric.WithPrettyPrint(),
		stdoutmetric.WithoutTimestamps(),
		stdoutmetric.With...
	)
}
```

Uses OTEL collector via gRPC to collect metrics. Metrics are collected once every [interval] waiting for [timeout]. Behavior is configurable via optional.

```go
package main

import (
	"os"
	"context"
	"time"
	"github.com/flash-go/flash/telemetry"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
)

func main() {
	otelCollectorGrpcEndpoint := "localhost:4317"

	// Create metric exporter
	metricExporter, err := telemetry.NewMetricExporterPeriodicOtlpGrpc(
		30*time.Second, // interval
		10*time.Second, // timeout
		context.TODO(),
		// optional
		otlpmetricgrpc.WithEndpoint(otelCollectorGrpcEndpoint), 
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.With...
	)
}
```

Uses Prometheus collector via HTTP-endpoint to collect metrics.

```go
package main

import (
	"net/http"
	"github.com/flash-go/flash/telemetry"
)

func main() {
	// Create trace exporter
	traceExporter := {...}

	// Create metric exporter
	metricExporter, err := telemetry.NewMetricExporterPrometheus()

	// Create telemetry service
	telemetryService := telemetry.New("service", traceExporter, metricExporter)

	// Register /metrics handler
	http.Handle("/metrics", telemetryService.GetMetricsHttpHandler())

	// Run HTTP-server
	http.ListenAndServe(":8080", nil)
}
```

### Use metrics

With register

```go
package main

import (
	"context"
	"go.opentelemetry.io/otel/metric"
)

func main() {
	// Create telemetry service
	telemetryService := {...}

	// Create with register metric
	telemetryService.NewMetricInt64Counter(
		"meter", 	// meter name
		"metric", 	// metric name
		true, 		// register flag
		// optional
		metric.WithDescription("description"),
		metric.WithUnit("unit"),
		metric.With...
	)

	// Create context
	ctx := context.TODO()

	// Use metric
	telemetryService.GetMetricInt64Counter("meter-metric").Add(ctx, 1)
}
```

Without register

```go
package main

import (
	"context"
	"go.opentelemetry.io/otel/metric"
)

func main() {
	// Create telemetry service
	telemetryService := {...}

	// Create without register metric
	metric, err := telemetryService.NewMetricInt64Counter(
		"meter", 	// meter name
		"metric", 	// metric name
		false, 		// register flag
		// optional
		metric.WithDescription("description"),
		metric.WithUnit("unit"),
		metric.With...
	)
	
	// Create context
	ctx := context.TODO()

	// Use metric
	metric.Add(ctx, 1)
}
```

### Collecting Go Runtime metrics

Automatic collection of Go Runtime metrics. Timeout determines how often to collect all metrics. All collected metrics are registered with "runtime" meter.

```go
package main

import (
	"time"
)

func main() {
	// Create telemetry service
	telemetryService := {...}

	// Timeout
	timeout := 10 * time.Second

	// Collect metrics
	telemetryService.CollectGoRuntimeMetrics(timeout)
}
```


## HTTP-server

### Create server

```go
package main

import (
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := server.New()
}
```

### Set server name

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Set server name
	httpServer.SetServerName("name")
}
```

### Disable logo on startup

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Disable logo on startup
	httpServer.DisableLogo(true)
}
```

### Add route

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Request handler
	handler := func(ctx server.ReqCtx) {
		// Read json request body
		ctx.ReadJson(data any) error
		// Read bytes request body
		ctx.Body() []byte
		// Set KV to context
		ctx.SetUserValue(key any, value any)
		// Get KV from context
		ctx.UserValue(key any) any
		// Get telemetry context
		ctx.Telemetry() context.Context
		// Set content-type header
		ctx.SetContentType(contentType string)
		// Set status code
		ctx.SetStatusCode(statusCode int)
		// Write error response message with status code
		ctx.Error(msg string, statusCode int)
		// Write bytes response body
		ctx.Write(p []byte) (int, error)
		// Write string response body
		ctx.WriteString(s string) (int, error)
		// Write json response body
		ctx.WriteJson(data any) error
		// Write default json response
		ctx.WriteResponse(response *Response) error
		// Create default json response
		ctx.NewResponse(statusCode int, status, code string, data any) *Response
	}

	// Add route
	httpServer.AddRoute(
		http.MethodGet,	// Method
		"/", 			// URI
		handler,		// Handler
		// middlewares (optional)
		// ...
	)
}
```

#### Send json response

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Request handler
	handler := func(ctx server.ReqCtx) {
		// Create response
		response := ctx.NewResponse(
			201,							// http status code
			"success",						// response status
			"user_registered_successfully",	// response code
			struct {						// optional response data (if no data then nil)
				Id          int		`json:"id"`
				Username	string	`json:"username"`
			}{
				1,		// id
				"user",	// username
			},
		)

		// Write response
		err := ctx.WriteResponse(response)
	}

	// Add route
	httpServer.AddRoute(
		http.MethodGet,	// Method
		"/", 			// URI
		handler,		// Handler
		// middlewares (optional)
		// ...
	)
}
```

A json object with http code 201 will be sent

```json
{
    "status": "success",
    "code": "user_registered_successfully",
    "data": {
        "id": 1,
        "username": "user",
    }
}
```

### Add middleware

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Request handler
	handler := {...}

	// Create middleware
	middleware := func(handler server.ReqHandler) server.ReqHandler {
		return func(ctx server.ReqCtx) {
			handler(ctx)
		}
	}

	// Add route
	httpServer.AddRoute(
		http.MethodGet,	// Method
		"/", 			// URI
		handler,		// Handler
		// middlewares (optional)
		middleware,
		// ...
	)
}
```

### Use state

When the server is launched, the instance is registered in the store. The instance ID is generated using the template [service]-http-[hostname]-[port]. The postfix "-http" is added to the service name. The /health route is added to monitor the health of the instance. Health is checked at intervals of 10 seconds. The instance is deleted 1 minute after the crash. The instance is deleted immediately when the server is stopped.

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Create state service
	stateService := {...}
	
	// Use logger service
	httpServer.UseState(stateService)
}
```

### Use logger

Enable logging of all incoming requests and system notifications from the server.

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Create logger service
	loggerService := {...}
	
	// Use logger service
	httpServer.UseLogger(loggerService)
}
```

### Use telemetry

Adding support for basic metrics and tracing.

| Metric Name         | Description                                    |
|---------------------|------------------------------------------------|
| `requests_total`    | Total number of processed requests             |
| `requests_in_flight`| Current number of requests being processed     |
| `request_duration`  | Histogram of response time for handler         |

For all incoming requests, traceparent is picked up (if passed) and the "incoming request" span is created. For "incoming request", path, method, status code are bound. Telemetry context is available via req.Telemetry() in handlers.

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Create telemetry service
	telemetryService := {...}
	
	// Use telemetry service
	httpServer.UseTelemetry(telemetryService)
}
```

Create span with telemetry context on request handlers

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Create telemetry service
	telemetryService := {...}
	
	// Use logger service
	httpServer.UseTelemetry(telemetryService)

	// Request handler
	handler := func(ctx server.ReqCtx) {
		// Get http telemetry tracer
		tracer := telemetryService.Tracer("http")
		// Start span with parse traceparent
		tctx, span := tracer.Start(
			ctx.Telemetry(),	// Telemetry context
			"handler",			// Span name
		)
		// End span
		defer span.End()
		// Set attributes (optional)
		span.SetAttributes(attribute.String("key", "value"))
		// Send response
		ctx.WriteString("index")
	}

	// Add route
	httpServer.AddRoute(
		http.MethodGet,	// Method
		"/", 			// URI
		handler,		// Handler
		// middlewares (optional)
		// ...
	)
}
```

### Use Swagger

Install Swag

```bash
go install github.com/swaggo/swag/cmd/swag@latest
```

```go
package main

// @title           flash
// @version         1.0
// @description     flash framework
// @BasePath        /

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
	_ "project/docs" // Import docs
)

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 8081

	// Create http server
	httpServer := {...}

	// Use Swagger
	httpServer.UseSwagger()

	// Add route
	httpServer.AddRoute(
		http.MethodGet,	// Method
		"/", 			// URI
		handler,		// Handler
		// middlewares (optional)
		// ...
	)

	// Start listen
	<-httpServer.Listen(serviceName, instanceHostname, instancePort)
}

// PingExample godoc
// @Summary      ping example
// @Description  do ping
// @Tags         example
// @Accept       json
// @Produce      json
// @Router       /test [post]
func handler(ctx server.ReqCtx) {
	{...}
}
```

Once you have extracted the handler into a named function with annotations, you can now start generating Swagger documentation.

```bash
// Entry point and handlers at the root
swag init

// Entry point in cmd and handlers in internal
swag init -d cmd,internal
```

The documentation will be available at

```
http://localhost:8081/swagger/index.html
```

### Use profiling

```go
package main

func main() {
	// Create http server
	httpServer := {...}

	// Use profiling
	httpServer.UseProfiling()
}
```

### Use CORS

```go
package main

import (
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Create CORS
	cors := server.Cors{
		Origin:  "*",
		Methods: "*",
		Headers: "*",
	},
	
	// Use CORS
	httpServer.UseCors(cors)
}
```

### Listen

Simple

```go
package main

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 8081

	// Create http server
	httpServer := {...}

	// Start listen
	<-httpServer.Listen(serviceName, instanceHostname, instancePort)
}
```

With errors handle

```go
package main

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 8081

	// Create http server
	httpServer := {...}

	// Start listen
	err := <-httpServer.Listen(serviceName, instanceHostname, instancePort)

	if err == nil {
		// The server has been graceful shutdown
	} else {
		// An error occurred while starting or reason of terminate the server
	}
}
```

### Listen (TLS)

Here is a short and complete example of how to run a TLS server and use a self-signed certificate to test ListenTLS.

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

```go
package main

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 8081

	// Create http server
	httpServer := {...}

	// Start listen
	<-httpServer.ListenTLS(serviceName, instanceHostname, instancePort, "cert.pem", "key.pem")
}
```

### Serve with custom listener

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 9055

	// Create http server
	httpServer := {...}

	// Create exit channel
	exit := make(chan error, 1)

	// Create listener
	listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", instanceHostname, instancePort))

	// Set listener
	httpServer.SetListener(listener)

	// Serve with custom listener
	<-httpServer.Serve(serviceName, instanceHostname, instancePort, exit)
}

```

with TLS

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 9055

	// Create http server
	httpServer := {...}

	// Create exit channel
	exit := make(chan error, 1)

	// Create listener
	listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", instanceHostname, instancePort))

	// Set listener
	httpServer.SetListener(listener)

	// Serve with custom listener (TLS)
	<-httpServer.ServeTLS(serviceName, instanceHostname, instancePort, exit, "cert.pem", "key.pem")
}
```

### Shutdown

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	serviceName := "api"
	instanceHostname := "localhost"
	instancePort := 8081

	// Create http server
	httpServer := {...}

	done := make(chan struct{})

	go func() {
		// Start listen
		<-httpServer.Listen(serviceName, instanceHostname, instancePort)
		close(done)
	}()

	time.Sleep(10 * time.Second)
	go httpServer.Shutdown()

	<-done
	fmt.Println("done")
}
```

## HTTP-client

### Create client

```go
package main

import (
	"github.com/flash-go/flash/http/client"
)

func main() {
	// Create http client
	httpClient := client.New()
}
```

### Set read timeout

Default read timeout 10 sec.

```go
package main

func main() {
	// Create http client
	httpClient := {...}

	// Set read timeout
	httpClient.SetReadTimeout(10 * time.Second)
}
```

### Set write timeout

Default write timeout 10 sec.

```go
package main

func main() {
	// Create http client
	httpClient := {...}

	// Set write timeout
	httpClient.SetWriteTimeout(10 * time.Second)
}
```

### Set max idle connection duration

Defaultmax idle connection duration 1 hour.

```go
package main

func main() {
	// Create http client
	httpClient := {...}

	// Set max idle connection duration
	httpClient.SetMaxIdleConnDuration(1 * time.Hour)
}
```

### Use telemetry

For all outgoing requests, a span "outgoing request" is created with the attribute "url". Activation of support for telemetry context for outgoing requests.

```go
package main

func main() {
	// Create http client
	httpClient := {...}

	// Create telemetry service
	telemetryService := {...}

	// Use telemetry
	httpClient.UseTelemetry(telemetryService)
}
```

### Use state

Ability to use the ServiceRequest function to send outgoing HTTP requests to services by service name using load balancing.

```go
package main

func main() {
	// Create http client
	httpClient := {...}

	// Create state service
	stateService := {...}

	// Use state
	httpClient.UseState(stateService)
}
```

### Send requests

Available methods for sending requests in http package

```go
import "github.com/flash-go/flash/http"
```

```go
package http

const (
	MethodGet     = "GET"     // RFC 7231
	MethodHead    = "HEAD"    // RFC 7231
	MethodPost    = "POST"    // RFC 7231
	MethodPut     = "PUT"     // RFC 7231
	MethodPatch   = "PATCH"   // RFC 5789
	MethodDelete  = "DELETE"  // RFC 7231
	MethodConnect = "CONNECT" // RFC 7231
	MethodOptions = "OPTIONS" // RFC 7231
	MethodTrace   = "TRACE"   // RFC 7231
)
```

Sending a request and receiving the body and response code.

```go
package main

import (
	"github.com/flash-go/flash/http"
)

func main() {
	// Create http client
	httpClient := {...}

	// Send GET request
	res, err := httpClient.Request(
		ctx, 							// Context
		http.MethodGet, 				// Method
		"http://localhost:8080/test",	// URL
		// options (optional)
		// client.WithRequest...
	)

	// Get body
	body := res.Body()

	// Get status code
	statusCode := res.StatusCode()
}
```

Sending a request with additional headers.

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/client"
)

func main() {
	// Create http client
	httpClient := {...}

	// Create headers
	headersOpt := client.WithRequestHeadersOption(
		client.NewRequestHeader("User-Agent", "MyCustomClient/1.0"),
		// client.NewRequestHeader...
	)

	// Send request
	res, err := httpClient.Request(
		ctx, 							// Context
		http.MethodGet, 				// Method
		"http://localhost:8080/test", 	// URL
		// options (optional)
		headersOpt, 
		// client.WithRequest...
	)
}
```

Sending request with json body.

```go
package main

import (
	"encoding/json"
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/client"
)

func main() {
	// Create http client
	httpClient := {...}

	// Create body byte slice
	body, err := json.Marshal(
		struct {
			Name string `json:"name"`
			ID   int    `json:"id"`
		}{
			"New entity",
			123,
		},
	)

	// Create body
	bodyOpt := client.WithRequestBodyOption(body)

	// Create headers
	headersOpt := client.WithRequestHeadersOption(
		client.NewRequestHeader("Content-Type", "application/json"),
	)

	// Send request
	res, err := httpClient.Request(
		ctx, 							// Context
		http.MethodPost, 				// Method
		"http://localhost:8080/test", 	// URL
		// options (optional)
		bodyOpt,
		headersOpt, 
		// client.WithRequest...
	)
}
```

Sending a request to a service by service name using load balancing. If you do not integrate the state into the client beforehand, the function returns an error.

```go
package main

import (
	"github.com/flash-go/flash/http"
)

func main() {
	// Create http client
	httpClient := {...}

	// Create state service
	stateService := {...}

	// Use state
	httpClient.UseState(stateService)

	// Send GET request to service
	res, err := httpClient.ServiceRequest(
		ctx,			// Context
		http.MethodGet,	// Method
		"service-http",	// Service name
		"/",			// URI
		// options
		// client.WithRequest...
	)
}
```

Sending a request to a service from a server handler while preserving the telemetry context.

```go
package main

import (
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"
)

func main() {
	// Create http server
	httpServer := {...}

	// Create http client
	httpClient := {...}

	// Create telemetry service
	telemetryService := {...}
	
	// Use logger service
	httpServer.UseTelemetry(telemetryService)

	// Create state service
	stateService := {...}

	// Use state
	httpClient.UseState(stateService)

	// Request handler
	handler := func(req server.ReqCtx) {
		// Send GET request to service with telemetry context
		res, err := httpClient.ServiceRequest(
			req.Telemetry(),	// Telemetry context
			http.MethodGet,		// Method
			"service-http",		// Service name
			"/",				// URI
			// options
			// client.WithRequest...
		)
	}

	// Add route
	httpServer.AddRoute("GET", "/", handler)
}
```

## Examples

### Hot reload server port

Complete example of loading the HTTP server port from the state with hot swapping of the port and restarting the server.

It may be necessary to add an entry to the /etc/hosts file.

```
127.0.0.1 host.docker.internal
```

```go
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/flash-go/flash/http/server"
	"github.com/flash-go/flash/logger"
	"github.com/flash-go/flash/state"
	"github.com/hashicorp/consul/api"
	"github.com/rs/zerolog"
)

func main() {
	// State service address
	stateAddress := "localhost:8500"

	// Service name
	serviceName := "api"

	// Instance hostname
	instanceHostname := "host.docker.internal"

	// Create http server
	httpServer := server.New()

	// Create state service with config
	config := api.DefaultConfig()
	config.Address = stateAddress
	stateService, _ := state.New(config)

	// Use state service
	httpServer.UseState(stateService)

	// Create console logger service
	loggerService := logger.New(
		logger.NewConsole(
			zerolog.ConsoleWriter{
				Out:        os.Stdout,
				TimeFormat: time.RFC3339,
			},
		),
	)

	// Use logger service
	httpServer.UseLogger(loggerService)

	// Create exit channel
	exit := make(chan struct{})

	// Watch server port
	stateService.WatchValue("port", func(value string) {
		// Convert port string to int
		port, err := strconv.Atoi(value)

		// If port not defined
		if err != nil {
			fmt.Println("No port defined. Retry...")
			return
		}

		// Shutdown http server if running
		httpServer.Shutdown()

		go func() {
			// Run http server
			err := <-httpServer.Listen(serviceName, instanceHostname, port)

			// If the server terminates with an error
			if err != nil {
				loggerService.Log().Info().Msgf("Terminate server reason: %s", err)
				close(exit)
			}
		}()
	})

	<-exit
}
```
