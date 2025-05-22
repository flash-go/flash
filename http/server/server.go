package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
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
)

//go:embed logo.txt
var startupLogo string

const (
	fasthttpHttpServerLogAllErrors    = true
	fasthttpHttpServerCloseOnShutdown = true
	fasthttpHttpServerConcurrency     = fasthttp.DefaultConcurrency
	defaultServerName                 = "Flash"
	disableLogoOnStartup              = false
	// TODO: Add processing (graceful/forceful)
	osSignalBuffer = 2
)

type Server interface {
	SetServerName(name string) Server
	DisableLogo(disable bool) Server
	AddRoute(method, path string, handler func(request ReqCtx), middlewares ...func(handler ReqHandler) ReqHandler) Server
	UseState(state state.State) Server
	UseCors(cors Cors) Server
	UseLogger(logger logger.Logger) Server
	UseTelemetry(telemetry telemetry.Telemetry) Server
	UseSwagger() Server
	UseProfiling() Server
	SetListener(listener net.Listener)
	GetListener() net.Listener
	Listen(service, hostname string, port int) <-chan error
	ListenTLS(service, hostname string, port int, certFile, keyFile string) <-chan error
	Serve(service, hostname string, port int, exit chan error) <-chan error
	ServeTLS(service, hostname string, port int, exit chan error, certFile, keyFile string) <-chan error
	Shutdown() error
}

type ReqCtx interface {
	Request() *fasthttp.Request
	ReadJson(data any) error
	Body() []byte
	SetUserValue(key any, value any)
	UserValue(key any) any
	Telemetry() context.Context
	SetContentType(contentType string)
	SetStatusCode(statusCode int)
	Error(msg string, statusCode int)
	Write(p []byte) (int, error)
	WriteString(s string) (int, error)
	WriteJson(data any) error
	WriteResponse(response *Response) error
	NewResponse(statusCode int, status, code string, data any) *Response
}

type Response struct {
	StatusCode int
	Status     string
	Code       string
	Data       any
}

type ReqHandler func(ReqCtx)

type server struct {
	service     string
	hostname    string
	port        int
	listener    net.Listener
	server      *fasthttp.Server
	router      *router.Router
	middleware  fasthttpMiddleware
	disableLogo bool
	logger      logger.Logger
	state       state.State
}

func New() Server {
	return &server{
		server: &fasthttp.Server{
			Name:                  defaultServerName,
			LogAllErrors:          fasthttpHttpServerLogAllErrors,
			Concurrency:           fasthttpHttpServerConcurrency,
			CloseOnShutdown:       fasthttpHttpServerCloseOnShutdown,
			NoDefaultServerHeader: true,
			NoDefaultContentType:  true,
			NoDefaultDate:         true,
			ReadTimeout:           10 * time.Second,
			IdleTimeout:           300 * time.Second,
		},
		router:      router.New(),
		middleware:  fasthttpMiddleware{},
		disableLogo: disableLogoOnStartup,
	}
}

func (s *server) SetServerName(name string) Server {
	s.server.Name = name
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
			start := time.Now()
			handler(ctx)
			logger.Log().Info().
				Str("method", string(ctx.Method())).
				Str("path", string(ctx.Path())).
				Int("status", ctx.Response.StatusCode()).
				Dur("latency", time.Since(start)).
				Msg("->")
		}
	})
	return s
}

func (s *server) UseTelemetry(telemetry telemetry.Telemetry) Server {
	requestsTotalMetric, _ := telemetry.NewMetricInt64Counter(
		"http",
		"requests_total",
		false,
		metric.WithDescription("Total number of processed requests"),
		metric.WithUnit("req"),
	)
	requestsInFlightMetric, _ := telemetry.NewMetricInt64UpDownCounter(
		"http",
		"requests_in_flight",
		false,
		metric.WithDescription("Current number of requests being processed"),
		metric.WithUnit("req"),
	)
	requestDurationMetric, _ := telemetry.NewMetricFloat64Histogram(
		"http",
		"request_duration",
		false,
		metric.WithDescription("Histogram of response time for handler"),
		metric.WithUnit("sec"),
	)

	s.appendMiddleware(func(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			tctx := otel.GetTextMapPropagator().Extract(context.Background(), fasthttpRequestCtxHeaderCarrier{ctx})
			tctx, span := telemetry.Tracer("http").Start(tctx, "incoming request")
			defer span.End()

			ctx.SetUserValue("tctx", tctx)

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
	s.router.Handle("GET", "/health", func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(200)
	})
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

func (s *server) Listen(service, hostname string, port int) <-chan error {
	exit := make(chan error, 1)
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		exit <- err
		close(exit)
		return exit
	}
	s.SetListener(listener)
	return s.Serve(service, hostname, port, exit)
}

func (s *server) ListenTLS(service, hostname string, port int, certFile, keyFile string) <-chan error {
	exit := make(chan error, 1)
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		exit <- err
		close(exit)
		return exit
	}
	s.SetListener(listener)
	return s.ServeTLS(service, hostname, port, exit, certFile, keyFile)
}

func (s *server) Serve(service, hostname string, port int, exit chan error) <-chan error {
	go func() {
		if err := s.serve(); err != nil {
			exit <- err
		}
		close(exit)
	}()
	s.registerService(service, hostname, port)
	go s.gracefulShutdown(exit)
	return exit
}

func (s *server) ServeTLS(service, hostname string, port int, exit chan error, certFile, keyFile string) <-chan error {
	go func() {
		if err := s.serveTLS(certFile, keyFile); err != nil {
			exit <- err
		}
		close(exit)
	}()
	s.registerService(service, hostname, port)
	go s.gracefulShutdown(exit)
	return exit
}

func (s *server) Shutdown() error {
	s.deregisterService()
	return s.server.Shutdown()
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
	s.router.Handle(method, path, wrapCtx(handler))
}

func (s *server) appendMiddleware(fn func(handler fasthttp.RequestHandler) fasthttp.RequestHandler) {
	s.middleware = append(s.middleware, fn)
}

func (s *server) getInstanceId() string {
	return fmt.Sprintf("%s-http-%s-%d", s.service, s.hostname, s.port)
}

func (s *server) registerService(service, hostname string, port int) error {
	s.service = service
	s.hostname = hostname
	s.port = port
	if s.state != nil {
		return s.state.ServiceRegister(
			&api.AgentServiceRegistration{
				ID:      s.getInstanceId(),
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
	return nil
}

func (s *server) deregisterService() error {
	if s.state != nil {
		s.state.ServiceDeregister(
			s.getInstanceId(),
		)
	}
	return nil
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
}

func (ctx *reqCtx) Request() *fasthttp.Request {
	return &ctx.RequestCtx.Request
}

func (ctx *reqCtx) ReadJson(data any) error {
	return json.Unmarshal(ctx.RequestCtx.Request.Body(), data)
}

func (ctx *reqCtx) Body() []byte {
	return ctx.RequestCtx.Request.Body()
}

func (ctx *reqCtx) SetUserValue(key any, value any) {
	ctx.RequestCtx.SetUserValue(key, value)
}

func (ctx *reqCtx) UserValue(key any) any {
	return ctx.RequestCtx.UserValue(key)
}

func (ctx *reqCtx) Telemetry() context.Context {
	tctx := ctx.RequestCtx.UserValue("tctx"); if tctx != nil {
		return tctx.(context.Context)
	} else {
		return context.Background()
	}
}

func (ctx *reqCtx) SetContentType(contentType string) {
	ctx.RequestCtx.SetContentType(contentType)
}

func (ctx *reqCtx) SetStatusCode(statusCode int) {
	ctx.RequestCtx.SetStatusCode(statusCode)
}

func (ctx *reqCtx) Error(msg string, statusCode int) {
	ctx.RequestCtx.Error(msg, statusCode)
}

func (ctx *reqCtx) Write(p []byte) (int, error) {
	return ctx.RequestCtx.Write(p)
}

func (ctx *reqCtx) WriteString(s string) (int, error) {
	return ctx.RequestCtx.WriteString(s)
}

func (ctx *reqCtx) WriteJson(data any) error {
	ctx.RequestCtx.Response.Header.SetContentType("application/json")
	return json.NewEncoder(ctx).Encode(data)
}

func (ctx *reqCtx) WriteResponse(response *Response) error {
	ctx.SetStatusCode(response.StatusCode)
	return ctx.WriteJson(
		struct {
			Status string `json:"status"`
			Code   string `json:"code"`
			Data   any    `json:"data"`
		}{
			response.Status,
			response.Code,
			response.Data,
		},
	)
}

func (ctx *reqCtx) NewResponse(statusCode int, status, code string, data any) *Response {
	return &Response{statusCode, status, code, data}
}

func wrapCtx(handler ReqHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		handler(&reqCtx{ctx})
	}
}

type Cors struct {
	Origin  string
	Methods string
	Headers string
}
