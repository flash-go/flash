package state

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/consul/api"
)

const watchTimeoutOnError = 5 * time.Second

type State interface {
	ServiceRegister(reg *api.AgentServiceRegistration) error
	ServiceDeregister(service string) error
	GetValue(key string) (string, error)
	WatchValue(key string, cb func(value string)) (string, error)
	GetInstance(service string) (*api.CatalogService, error)
	GetInstances(service string) ([]*api.CatalogService, error)
	WatchInstances(service string, cb func(value []*api.CatalogService)) ([]*api.CatalogService, error)
}

type state struct {
	client *api.Client
}

func New(config *api.Config) (State, error) {
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to Consul: %w", err)
	}
	return &state{client}, nil
}

func (s *state) ServiceRegister(reg *api.AgentServiceRegistration) error {
	if err := s.client.Agent().ServiceRegister(reg); err != nil {
		return fmt.Errorf("Service registration error: %w", err)
	}
	return nil
}

func (s *state) ServiceDeregister(service string) error {
	if err := s.client.Agent().ServiceDeregister(service); err != nil {
		return fmt.Errorf("Service deregistration error: %w", err)
	}
	return nil
}

func (s *state) GetValue(key string) (string, error) {
	kvPair, _, err := s.client.KV().Get(key, nil)
	if err != nil {
		return "", fmt.Errorf("Error read KV: %w", err)
	}
	if kvPair == nil {
		return "", fmt.Errorf("Key %s not found", key)
	}
	return string(kvPair.Value), nil
}

func (s *state) WatchValue(key string, cb func(val string)) (string, error) {
	go func() {
		var lastIndex uint64
		for {
			kvPair, meta, err := s.client.KV().Get(key, &api.QueryOptions{
				WaitIndex: lastIndex,
			})
			if err != nil {
				time.Sleep(watchTimeoutOnError)
				continue
			}
			if kvPair == nil {
				cb("")
				time.Sleep(watchTimeoutOnError)
				continue
			}
			if meta.LastIndex > lastIndex {
				cb(string(kvPair.Value))
				lastIndex = meta.LastIndex
			}
		}
	}()
	return s.GetValue(key)
}

func (s *state) GetInstances(service string) ([]*api.CatalogService, error) {
	services, _, err := s.client.Catalog().Service(service, "", nil)
	if err != nil {
		return nil, err
	}
	return services, nil
}

func (s *state) WatchInstances(service string, cb func(value []*api.CatalogService)) ([]*api.CatalogService, error) {
	go func() {
		var lastIndex uint64
		for {
			services, meta, err := s.client.Catalog().Service(service, "", &api.QueryOptions{
				WaitIndex: lastIndex,
			})
			if err != nil {
				time.Sleep(watchTimeoutOnError)
				continue
			}
			if meta.LastIndex > lastIndex {
				cb(services)
				lastIndex = meta.LastIndex
			}
		}
	}()
	return s.GetInstances(service)
}

func (s *state) GetInstance(service string) (*api.CatalogService, error) {
	services, err := s.GetInstances(service)
	if len(services) == 0 {
		return nil, fmt.Errorf("service not found: %s", service)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch service: %w", err)
	}
	t := time.Now().UnixNano()
	ns := rand.NewSource(t)
	r := rand.New(ns)
	i := r.Intn(len(services))
	return services[i], nil
}
