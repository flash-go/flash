package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/flash-go/flash/state"
	"github.com/flash-go/flash/telemetry"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Client name. Used in User-Agent request header.
	clientName = "Flash"

	// Maximum number of connections per each host which may be established.
	clientMaxConnsPerHost = 512

	// Idle keep-alive connections are closed after this duration.
	clientMaxIdleConnDuration = 10 * time.Second

	// Keep-alive connections are closed after this duration.
	clientMaxConnDuration = time.Duration(0)

	// Maximum number of attempts for idempotent calls.
	clientMaxIdemponentCallAttempts = 5

	// Per-connection buffer size for responses' reading.
	// This also limits the maximum header size.
	clientReadBufferSize = 4096

	// Per-connection buffer size for requests' writing.
	clientWriteBufferSize = 4096

	// Maximum duration for full response reading (including body).
	clientReadTimeout = 10 * time.Second

	// Maximum duration for full request writing (including body).
	clientWriteTimeout = 10 * time.Second
)

type Client interface {
	SetClientName(string) Client
	SetClientMaxConnsPerHost(int) Client
	SetClientMaxIdleConnDuration(time.Duration) Client
	SetClientMaxConnDuration(time.Duration) Client
	SetClientMaxIdemponentCallAttempts(int) Client
	SetClientReadBufferSize(int) Client
	SetClientWriteBufferSize(int) Client
	SetClientReadTimeout(time.Duration) Client
	SetClientWriteTimeout(time.Duration) Client
	UseTelemetry(telemetry.Telemetry) Client
	UseState(state.State) Client
	Request(ctx context.Context, method string, url string, options ...RequestOption) (Response, error)
	ServiceRequest(ctx context.Context, method string, service, uri string, options ...RequestOption) (Response, error)
}

type client struct {
	client    *fasthttp.Client
	telemetry telemetry.Telemetry
	state     state.State
}

func New() Client {
	return &client{
		client: &fasthttp.Client{
			Name:                          clientName,
			MaxConnsPerHost:               clientMaxConnsPerHost,
			MaxIdleConnDuration:           clientMaxIdleConnDuration,
			MaxConnDuration:               clientMaxConnDuration,
			MaxIdemponentCallAttempts:     clientMaxIdemponentCallAttempts,
			ReadBufferSize:                clientReadBufferSize,
			WriteBufferSize:               clientWriteBufferSize,
			ReadTimeout:                   clientReadTimeout,
			WriteTimeout:                  clientWriteTimeout,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			// increase DNS cache time to an hour instead of default minute
			Dial: (&fasthttp.TCPDialer{
				Concurrency:      4096,
				DNSCacheDuration: time.Hour,
			}).Dial,
		},
	}
}

func (c *client) SetClientName(v string) Client {
	c.client.Name = v
	return c
}

func (c *client) SetClientMaxConnsPerHost(v int) Client {
	c.client.MaxConnsPerHost = v
	return c
}

func (c *client) SetClientMaxIdleConnDuration(v time.Duration) Client {
	c.client.MaxIdleConnDuration = v
	return c
}

func (c *client) SetClientMaxConnDuration(v time.Duration) Client {
	c.client.MaxConnDuration = v
	return c
}

func (c *client) SetClientMaxIdemponentCallAttempts(v int) Client {
	c.client.MaxIdemponentCallAttempts = v
	return c
}

func (c *client) SetClientReadBufferSize(v int) Client {
	c.client.ReadBufferSize = v
	return c
}

func (c *client) SetClientWriteBufferSize(v int) Client {
	c.client.WriteBufferSize = v
	return c
}

func (c *client) SetClientReadTimeout(v time.Duration) Client {
	c.client.ReadTimeout = v
	return c
}

func (c *client) SetClientWriteTimeout(v time.Duration) Client {
	c.client.WriteTimeout = v
	return c
}

func (c *client) UseTelemetry(telemetry telemetry.Telemetry) Client {
	c.telemetry = telemetry
	return c
}

func (c *client) UseState(state state.State) Client {
	c.state = state
	return c
}

func (c *client) Request(ctx context.Context, method string, url string, options ...RequestOption) (Response, error) {
	resCh := make(chan Response, 1)
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("request error: %v", r)
			}
		}()
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		req.SetRequestURI(url)
		req.Header.SetMethod(method)
		var span trace.Span
		if c.telemetry != nil {
			ctx, span = c.telemetry.Tracer().Start(ctx, "outgoing request")
			defer span.End()
			span.SetAttributes(
				attribute.String("url", url),
			)
			otel.GetTextMapPropagator().Inject(ctx, fasthttpRequestHeaderCarrier{&req.Header})
		}
		for _, option := range options {
			option.Apply(req)
		}
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)
		err := c.client.Do(req, resp)
		if err != nil {
			errCh <- err
			return
		}
		cResp := &fasthttp.Response{}
		resp.CopyTo(cResp)
		resCh <- &response{cResp}
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("request failed due to context error: %w", ctx.Err())
	case r := <-resCh:
		return r, nil
	case e := <-errCh:
		return nil, e
	}
}

func (c *client) ServiceRequest(ctx context.Context, method string, service, uri string, options ...RequestOption) (Response, error) {
	if c.state == nil {
		return nil, errors.New("state service not set")
	}
	instance, err := c.state.GetInstance(service)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance: %w", err)
	}
	url := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", instance.ServiceAddress, instance.ServicePort),
		Path:   uri,
	}
	return c.Request(ctx, method, url.String(), options...)
}

type response struct {
	*fasthttp.Response
}

func (r *response) Body() []byte {
	return r.Response.Body()
}

func (r *response) StatusCode() int {
	return r.Response.Header.StatusCode()
}

func (r *response) ContentType() []byte {
	return r.Response.Header.ContentType()
}

type fasthttpRequestHeaderCarrier struct {
	header *fasthttp.RequestHeader
}

func (f fasthttpRequestHeaderCarrier) Get(key string) string {
	return string(f.header.Peek(key))
}

func (f fasthttpRequestHeaderCarrier) Set(key, value string) {
	f.header.Set(key, value)
}

func (f fasthttpRequestHeaderCarrier) Keys() []string {
	keys := []string{}
	f.header.VisitAll(func(k, v []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

type Response interface {
	Body() []byte
	StatusCode() int
	ContentType() []byte
}

type RequestOption interface {
	Apply(req *fasthttp.Request)
}

type RequestBodyOption struct {
	Body []byte
}

func (h RequestBodyOption) Apply(req *fasthttp.Request) {
	req.SetBodyRaw(h.Body)
}

func WithRequestBodyOption(body []byte) RequestBodyOption {
	return RequestBodyOption{body}
}

type RequestHeadersOption struct {
	Headers []RequestHeader
}

func (h RequestHeadersOption) Apply(req *fasthttp.Request) {
	for _, header := range h.Headers {
		req.Header.Set(header.Key, header.Value)
	}
}

func WithRequestHeadersOption(headers ...RequestHeader) RequestHeadersOption {
	return RequestHeadersOption{headers}
}

type RequestHeader struct {
	Key   string
	Value string
}

func NewRequestHeader(key, value string) RequestHeader {
	return RequestHeader{key, value}
}
