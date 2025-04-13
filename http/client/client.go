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
	defaultReadTimeout         = 10 * time.Second
	defaultWriteTimeout        = 10 * time.Second
	defaultMaxIdleConnDuration = 1 * time.Hour
)

type Client interface {
	UseTelemetry(telemetry telemetry.Telemetry) Client
	UseState(state state.State) Client
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
			ReadTimeout:                   defaultReadTimeout,
			WriteTimeout:                  defaultWriteTimeout,
			MaxIdleConnDuration:           defaultMaxIdleConnDuration,
			NoDefaultUserAgentHeader:      true, // Don't send: User-Agent: fasthttp
			DisableHeaderNamesNormalizing: true, // If you set the case on your headers correctly you can enable this
			DisablePathNormalizing:        true,
			// increase DNS cache time to an hour instead of default minute
			Dial: (&fasthttp.TCPDialer{
				Concurrency:      4096,
				DNSCacheDuration: time.Hour,
			}).Dial,
		},
	}
}

func (c *client) SetReadTimeout(d time.Duration) Client {
	c.client.ReadTimeout = d
	return c
}

func (c *client) SetWriteTimeout(d time.Duration) Client {
	c.client.WriteTimeout = d
	return c
}

func (c *client) SetMaxIdleConnDuration(d time.Duration) Client {
	c.client.MaxIdleConnDuration = d
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
				errCh <- fmt.Errorf("panic in request: %v", r)
			}
		}()
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		req.SetRequestURI(url)
		req.Header.SetMethod(method)
		var span trace.Span
		if c.telemetry != nil {
			ctx, span = c.telemetry.Tracer("http").Start(ctx, "outgoing request")
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
	u := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", instance.ServiceAddress, instance.ServicePort),
		Path:   uri,
	}
	return c.Request(ctx, method, u.String(), options...)
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
