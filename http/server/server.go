package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fasthttp/router"
	"github.com/flash-go/flash/logger"
	"github.com/flash-go/flash/state"
	"github.com/flash-go/flash/telemetry"
	"github.com/hashicorp/consul/api"
	fastHttpSwagger "github.com/swaggo/fasthttp-swagger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"github.com/valyala/fasthttp/pprofhandler"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

//go:embed logo.txt
var startupLogo string

var (
	defaultErrorResponseStatus = 503
	defaultErrorResponseMsg    = "service_unavailable"
)

const (
	// Server name for sending in response headers.
	serverName = "Flash"

	// The maximum number of concurrent connections the server may serve.
	serverConcurrency = 256 * 1024

	// Per-connection buffer size for requests' reading.
	// This also limits the maximum header size.
	//
	// Increase this buffer if your clients send multi-KB RequestURIs
	// and/or multi-KB headers (for example, BIG cookies).
	serverReadBufferSize = 4096

	// Per-connection buffer size for responses writing.
	serverWriteBufferSize = 4096

	// ReadTimeout is the amount of time allowed to read
	// the full request including body. The connection's read
	// deadline is reset when the connection opens, or for
	// keep-alive connections after the first byte has been read.
	serverReadTimeout = 10 * time.Second

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset after the request handler
	// has returned.
	serverWriteTimeout = 10 * time.Second

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alive is enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used.
	serverIdleTimeout = 10 * time.Second

	// Maximum number of concurrent client connections allowed per IP.
	serverMaxConnsPerIP = 0 // unlimited

	// Maximum number of requests served per connection.
	//
	// The server closes connection after the last request.
	// 'Connection: close' header is added to the last response.
	serverMaxRequestsPerConn = 0 // unlimited

	// Maximum request body size.
	// The server rejects requests with bodies exceeding this limit.
	serverMaxRequestBodySize = 4 * 1024 * 1024

	// Whether to disable keep-alive connections.
	//
	// The server will close all the incoming connections after sending
	// the first response to client if this option is set to true.
	serverDisableKeepalive = false

	// Whether to enable tcp keep-alive connections.
	// Whether the operating system should send tcp keep-alive messages
	// on the tcp connection.
	serverTCPKeepalive = false

	// Logs all errors, including the most frequent
	// 'connection reset by peer', 'broken pipe' and 'connection timeout'
	// errors. Such errors are common in production serving real-world
	// clients.
	serverLogAllErrors = true

	disableLogoOnStartup = false

	// TODO: Add processing (graceful/forceful)
	osSignalBuffer = 2
)

type Server interface {
	SetServerName(string) Server
	SetServerConcurrency(int) Server
	SetServerReadBufferSize(int) Server
	SetServerWriteBufferSize(int) Server
	SetServerReadTimeout(time.Duration) Server
	SetServerWriteTimeout(time.Duration) Server
	SetServerIdleTimeout(time.Duration) Server
	SetServerMaxConnsPerIP(int) Server
	SetServerMaxRequestsPerConn(int) Server
	SetServerMaxRequestBodySize(int) Server
	SetServerDisableKeepalive(bool) Server
	SetServerTCPKeepalive(bool) Server
	SetServerLogAllErrors(bool) Server
	SetErrorResponseStatusMap(*ErrorResponseStatusMap) Server
	DisableLogo(bool) Server
	AddRoute(method, path string, handler func(request ReqCtx), middlewares ...func(handler ReqHandler) ReqHandler) Server
	UseCors(Cors) Server
	UseLogger(logger.Logger) Server
	UseTelemetry(telemetry.Telemetry) Server
	UseSwagger() Server
	UseState(state.State) Server
	UseProfiling() Server
	SetListener(net.Listener)
	GetListener() net.Listener
	Listen(hostname string, port int) <-chan error
	ListenTLS(hostname string, port int, certFile, keyFile string) <-chan error
	Serve(hostname string, port int, exit chan error) <-chan error
	ServeTLS(hostname string, port int, exit chan error, certFile, keyFile string) <-chan error
	Shutdown() error
	RegisterService(service, hostname string, port int) error
	DeregisterService() error
}

type ReqCtx interface {
	Request() *fasthttp.Request
	RemoteAddr() net.Addr
	UserAgent() string
	ReadJson(any) error
	Body() []byte
	SetContentType(string)
	SetStatusCode(int)
	SetUserValue(key any, value any)
	GetHeader(key string) string
	UserValue(key any) any
	Context() context.Context
	GetBearerToken() (string, error)
	GetIpAddr() string
	Error(msg string, statusCode int)
	Write([]byte) (int, error)
	WriteString(string) (int, error)
	WriteJson(any) error
	WriteResponse(statusCode int, data any) error
	WriteErrorResponse(err error)
	SetTraceIdHeader()
	FormFile(key string) (*multipart.FileHeader, error)
	FormValue(key string) []byte
}

type ErrorResponseStatusMap map[error]int

type ReqHandler func(ReqCtx)

type server struct {
	listener               net.Listener
	server                 *fasthttp.Server
	router                 *router.Router
	middleware             fasthttpMiddleware
	disableLogo            bool
	logger                 logger.Logger
	state                  state.State
	instanceId             string
	errorResponseStatusMap *ErrorResponseStatusMap
}

func New() Server {
	return &server{
		server: &fasthttp.Server{
			Name:                  serverName,
			Concurrency:           serverConcurrency,
			ReadBufferSize:        serverReadBufferSize,
			WriteBufferSize:       serverWriteBufferSize,
			ReadTimeout:           serverReadTimeout,
			WriteTimeout:          serverWriteTimeout,
			IdleTimeout:           serverIdleTimeout,
			MaxConnsPerIP:         serverMaxConnsPerIP,
			MaxRequestsPerConn:    serverMaxRequestsPerConn,
			MaxRequestBodySize:    serverMaxRequestBodySize,
			DisableKeepalive:      serverDisableKeepalive,
			TCPKeepalive:          serverTCPKeepalive,
			LogAllErrors:          serverLogAllErrors,
			CloseOnShutdown:       true,
			NoDefaultServerHeader: true,
			NoDefaultContentType:  true,
			NoDefaultDate:         true,
		},
		router:      router.New(),
		middleware:  fasthttpMiddleware{},
		disableLogo: disableLogoOnStartup,
	}
}

func (s *server) SetServerName(v string) Server {
	s.server.Name = v
	return s
}

func (s *server) SetServerConcurrency(v int) Server {
	s.server.Concurrency = v
	return s
}

func (s *server) SetServerReadBufferSize(v int) Server {
	s.server.ReadBufferSize = v
	return s
}

func (s *server) SetServerWriteBufferSize(v int) Server {
	s.server.WriteBufferSize = v
	return s
}

func (s *server) SetServerReadTimeout(v time.Duration) Server {
	s.server.ReadTimeout = v
	return s
}

func (s *server) SetServerWriteTimeout(v time.Duration) Server {
	s.server.WriteTimeout = v
	return s
}

func (s *server) SetServerIdleTimeout(v time.Duration) Server {
	s.server.IdleTimeout = v
	return s
}

func (s *server) SetServerMaxConnsPerIP(v int) Server {
	s.server.MaxConnsPerIP = v
	return s
}

func (s *server) SetServerMaxRequestsPerConn(v int) Server {
	s.server.MaxRequestsPerConn = v
	return s
}

func (s *server) SetServerMaxRequestBodySize(v int) Server {
	s.server.MaxRequestBodySize = v
	return s
}

func (s *server) SetServerDisableKeepalive(v bool) Server {
	s.server.DisableKeepalive = v
	return s
}

func (s *server) SetServerTCPKeepalive(v bool) Server {
	s.server.TCPKeepalive = v
	return s
}

func (s *server) SetServerLogAllErrors(v bool) Server {
	s.server.LogAllErrors = v
	return s
}

func (s *server) SetErrorResponseStatusMap(m *ErrorResponseStatusMap) Server {
	s.errorResponseStatusMap = m
	return s
}

func (s *server) DisableLogo(disable bool) Server {
	s.disableLogo = disable
	return s
}

func (s *server) AddRoute(method, path string, handler func(request ReqCtx), middlewares ...func(handler ReqHandler) ReqHandler) Server {
	h := ReqHandler(handler)
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	s.addRoute(method, path, h)
	return s
}

func (s *server) UseCors(cors Cors) Server {
	s.appendMiddleware(func(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			ctx.Response.Header.Set("Access-Control-Allow-Origin", cors.Origin)
			ctx.Response.Header.Set("Access-Control-Allow-Methods", cors.Methods)
			ctx.Response.Header.Set("Access-Control-Allow-Headers", cors.Headers)
			handler(ctx)
		}
	})
	return s
}

func (s *server) UseLogger(logger logger.Logger) Server {
	s.logger = logger
	s.server.Logger = logger
	s.appendMiddleware(func(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			handler(ctx)
			logger.Log().Info().
				Str("method", string(ctx.Method())).
				Str("path", string(ctx.Path())).
				Int("status", ctx.Response.StatusCode()).
				Msg("->")
		}
	})
	return s
}

func (s *server) UseTelemetry(telemetry telemetry.Telemetry) Server {
	requestsTotalMetric, _ := telemetry.NewMetricInt64Counter(
		"requests_total",
		false,
		metric.WithDescription("Total number of processed requests"),
		metric.WithUnit("req"),
	)
	requestsInFlightMetric, _ := telemetry.NewMetricInt64UpDownCounter(
		"requests_in_flight",
		false,
		metric.WithDescription("Current number of requests being processed"),
		metric.WithUnit("req"),
	)
	requestDurationMetric, _ := telemetry.NewMetricFloat64Histogram(
		"request_duration",
		false,
		metric.WithDescription("Histogram of response time for handler"),
		metric.WithUnit("sec"),
	)

	s.appendMiddleware(func(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			tctx := otel.GetTextMapPropagator().Extract(context.Background(), fasthttpRequestCtxHeaderCarrier{ctx})
			tctx, span := telemetry.Tracer().Start(tctx, "incoming request")
			defer span.End()

			ctx.SetUserValue("ctx", tctx)

			requestsInFlightMetric.Add(tctx, 1)
			defer requestsInFlightMetric.Add(tctx, -1)

			start := time.Now()
			handler(ctx)
			duration := time.Since(start).Seconds()

			attr := []attribute.KeyValue{
				attribute.String("path", string(ctx.Path())),
				attribute.String("method", string(ctx.Method())),
				attribute.String("status", fmt.Sprintf("%d", ctx.Response.StatusCode())),
			}

			requestDurationMetric.Record(tctx, duration, metric.WithAttributes(attr...))
			requestsTotalMetric.Add(tctx, 1, metric.WithAttributes(attr...))

			span.SetAttributes(attr...)
		}
	})

	s.router.Handle("GET", "/metrics", fasthttpadaptor.NewFastHTTPHandler(telemetry.GetMetricsHttpHandler()))

	return s
}

func (s *server) UseSwagger() Server {
	s.router.Handle("GET", "/swagger/{filepath:*}", func(ctx *fasthttp.RequestCtx) {
		fastHttpSwagger.WrapHandler(fastHttpSwagger.InstanceName("swagger"))(ctx)
	})
	return s
}

func (s *server) UseState(state state.State) Server {
	s.state = state
	return s
}

func (s *server) UseProfiling() Server {
	s.router.Handle("GET", "/debug/pprof/{profile:*}", pprofhandler.PprofHandler)
	return s
}

func (s *server) SetListener(listener net.Listener) {
	s.listener = listener
}

func (s *server) GetListener() net.Listener {
	return s.listener
}

func (s *server) Listen(hostname string, port int) <-chan error {
	exit := make(chan error, 1)
	listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		exit <- err
		close(exit)
		return exit
	}
	s.SetListener(listener)
	return s.Serve(hostname, port, exit)
}

func (s *server) ListenTLS(hostname string, port int, certFile, keyFile string) <-chan error {
	exit := make(chan error, 1)
	listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		exit <- err
		close(exit)
		return exit
	}
	s.SetListener(listener)
	return s.ServeTLS(hostname, port, exit, certFile, keyFile)
}

func (s *server) Serve(hostname string, port int, exit chan error) <-chan error {
	go func() {
		if err := s.serve(); err != nil {
			exit <- err
		}
		close(exit)
	}()
	go s.gracefulShutdown(exit)
	return exit
}

func (s *server) ServeTLS(hostname string, port int, exit chan error, certFile, keyFile string) <-chan error {
	go func() {
		if err := s.serveTLS(certFile, keyFile); err != nil {
			exit <- err
		}
		close(exit)
	}()
	go s.gracefulShutdown(exit)
	return exit
}

func (s *server) Shutdown() error {
	s.DeregisterService()
	return s.server.Shutdown()
}

func (s *server) RegisterService(service, hostname string, port int) error {
	if s.state == nil {
		return errors.New("state not set")
	}
	s.router.Handle("GET", "/health", func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	instanceId := s.setInstanceId(service, hostname, port)
	return s.state.ServiceRegister(
		&api.AgentServiceRegistration{
			ID:      instanceId,
			Name:    service + "-http",
			Port:    port,
			Address: hostname,
			Check: &api.AgentServiceCheck{
				HTTP:                           fmt.Sprintf("http://%s:%d/health", hostname, port),
				Interval:                       "10s",
				Timeout:                        "1s",
				DeregisterCriticalServiceAfter: "1m",
			},
		},
	)
}

func (s *server) DeregisterService() error {
	if s.state == nil {
		return errors.New("state not set")
	}
	return s.state.ServiceDeregister(
		s.instanceId,
	)
}

func (s *server) printLogo() {
	if s.disableLogo {
		fmt.Println("\nFlash")
	} else {
		fmt.Println(startupLogo)
	}
}

func (s *server) serve() error {
	s.server.Handler = s.getHandler()
	s.printLogo()
	if s.logger != nil {
		s.logger.Log().Info().Msgf(
			"Server is running at %s on %s network",
			s.listener.Addr().String(),
			s.listener.Addr().Network(),
		)
	}
	return s.server.Serve(s.listener)
}

func (s *server) serveTLS(certFile, keyFile string) error {
	s.server.Handler = s.getHandler()
	s.printLogo()
	if s.logger != nil {
		s.logger.Log().Info().Msgf(
			"Server is running at %s on %s network (TLS)",
			s.listener.Addr().String(),
			s.listener.Addr().Network(),
		)
	}
	return s.server.ServeTLS(s.listener, certFile, keyFile)
}

func (s *server) getHandler() func(ctx *fasthttp.RequestCtx) {
	h := s.router.Handler
	for i := len(s.middleware) - 1; i >= 0; i-- {
		h = s.middleware[i](h)
	}
	return h
}

func (s *server) gracefulShutdown(exit chan error) {
	catch := make(chan os.Signal, osSignalBuffer)
	signal.Notify(catch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer func() {
		signal.Stop(catch)
		close(catch)
	}()
	for {
		select {
		case <-exit:
			return
		case action := <-catch:
			switch action {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				exit <- fmt.Errorf("syscall (%s)", action)
				s.Shutdown()
				return
			}
		}
	}
}

func (s *server) addRoute(method string, path string, handler ReqHandler) {
	s.router.Handle(method, path, s.wrapCtx(handler))
}

func (s *server) wrapCtx(handler ReqHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		handler(&reqCtx{ctx, s})
	}
}

func (s *server) appendMiddleware(fn func(handler fasthttp.RequestHandler) fasthttp.RequestHandler) {
	s.middleware = append(s.middleware, fn)
}

func (s *server) setInstanceId(service, hostname string, port int) string {
	s.instanceId = fmt.Sprintf("%s-http-%s-%d", service, hostname, port)
	return s.instanceId
}

type fasthttpMiddleware = []func(handler fasthttp.RequestHandler) fasthttp.RequestHandler

type fasthttpRequestCtxHeaderCarrier struct {
	ctx *fasthttp.RequestCtx
}

func (c fasthttpRequestCtxHeaderCarrier) Get(key string) string {
	return string(c.ctx.Request.Header.Peek(key))
}

func (c fasthttpRequestCtxHeaderCarrier) Set(key, value string) {
	c.ctx.Request.Header.Set(key, value)
}

func (c fasthttpRequestCtxHeaderCarrier) Keys() []string {
	keys := []string{}
	c.ctx.Request.Header.VisitAll(func(k, v []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

type reqCtx struct {
	*fasthttp.RequestCtx
	*server
}

func (ctx *reqCtx) Request() *fasthttp.Request {
	return &ctx.RequestCtx.Request
}

func (ctx *reqCtx) RemoteAddr() net.Addr {
	return ctx.RequestCtx.Response.RemoteAddr()
}

func (ctx *reqCtx) UserAgent() string {
	return string(ctx.RequestCtx.Request.Header.UserAgent())
}

func (ctx *reqCtx) ReadJson(data any) error {
	return json.Unmarshal(ctx.RequestCtx.Request.Body(), data)
}

func (ctx *reqCtx) Body() []byte {
	return ctx.RequestCtx.Request.Body()
}

func (ctx *reqCtx) SetContentType(contentType string) {
	ctx.RequestCtx.SetContentType(contentType)
}

func (ctx *reqCtx) SetStatusCode(statusCode int) {
	ctx.RequestCtx.SetStatusCode(statusCode)
}

func (ctx *reqCtx) SetUserValue(key any, value any) {
	ctx.RequestCtx.SetUserValue(key, value)
}

func (ctx *reqCtx) GetHeader(key string) string {
	return string(ctx.Request().Header.Peek(key))
}

func (ctx *reqCtx) UserValue(key any) any {
	return ctx.RequestCtx.UserValue(key)
}

func (ctx *reqCtx) Context() context.Context {
	if c := ctx.RequestCtx.UserValue("ctx"); c != nil {
		return c.(context.Context)
	} else {
		return context.Background()
	}
}

func (ctx *reqCtx) GetBearerToken() (string, error) {
	authHeader := ctx.GetHeader("Authorization")

	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("missing bearer prefix")
	}

	// Trim Bearer prefix
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))

	return token, nil
}

func (ctx *reqCtx) GetIpAddr() string {
	ip := string(ctx.GetHeader("X-Real-IP"))
	if ip == "" {
		ip = string(ctx.GetHeader("X-Forwarded-For"))
	}
	if ip == "" {
		if addr := ctx.RemoteAddr(); addr != nil {
			ip = addr.String()
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
		}
	}
	return ip
}

func (ctx *reqCtx) Error(msg string, statusCode int) {
	ctx.SetTraceIdHeader()
	ctx.SetStatusCode(statusCode)
	ctx.SetContentTypeBytes([]byte("text/plain; charset=utf-8"))
	ctx.SetBodyString(msg)
}

func (ctx *reqCtx) Write(p []byte) (int, error) {
	ctx.SetTraceIdHeader()
	return ctx.RequestCtx.Write(p)
}

func (ctx *reqCtx) WriteString(s string) (int, error) {
	ctx.SetTraceIdHeader()
	return ctx.RequestCtx.WriteString(s)
}

func (ctx *reqCtx) WriteJson(data any) error {
	ctx.SetContentTypeBytes([]byte("application/json; charset=utf-8"))
	ctx.SetTraceIdHeader()
	return json.NewEncoder(ctx).Encode(data)
}

func (ctx *reqCtx) WriteResponse(statusCode int, data any) error {
	ctx.SetStatusCode(statusCode)
	if data == nil {
		ctx.SetTraceIdHeader()
		return nil
	}
	return ctx.WriteJson(data)
}

func (ctx *reqCtx) WriteErrorResponse(err error) {
	// Set default status and error codes
	statusCode := defaultErrorResponseStatus
	msg := defaultErrorResponseMsg

	parseMap := func(e error, m *ErrorResponseStatusMap, statusCode *int, msg *string) {
		for customErr, customStatus := range *m {
			if errors.Is(e, customErr) {
				*statusCode = customStatus
				*msg = err.Error()
				break
			}
		}
	}

	// Parse global error response map
	if ctx.server.errorResponseStatusMap != nil {
		parseMap(err, ctx.server.errorResponseStatusMap, &statusCode, &msg)
	}

	// Parse local error response map
	if e := ctx.UserValue("error_response"); e != nil {
		m := e.(ErrorResponseStatusMap)
		parseMap(err, &m, &statusCode, &msg)
	}

	// Logging errors
	if statusCode == defaultErrorResponseStatus && ctx.server.logger != nil {
		ctx.server.logger.Log().Err(err).Send()
	}

	// Write error response
	ctx.Error(msg, statusCode)
}

func (ctx *reqCtx) SetTraceIdHeader() {
	spanCtx := trace.SpanContextFromContext(ctx.Context())
	if spanCtx.HasTraceID() {
		ctx.Response.Header.Set("X-Trace-Id", spanCtx.TraceID().String())
	}
}

func (ctx *reqCtx) FormFile(key string) (*multipart.FileHeader, error) {
	return ctx.RequestCtx.FormFile(key)
}

func (ctx *reqCtx) FormValue(key string) []byte {
	return ctx.RequestCtx.FormValue(key)
}

type Cors struct {
	Origin  string
	Methods string
	Headers string
}
