package logger

import (
	"bytes"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
)

type ElasticsearchInterface interface {
	Write(p []byte) (int, error)
}

type Elasticsearch struct {
	client *elasticsearch.Client
	index  string
}

func NewElasticsearch(client *elasticsearch.Client, index string) ElasticsearchInterface {
	return &Elasticsearch{client, index}
}

func (e *Elasticsearch) Write(p []byte) (int, error) {
	reqBody := bytes.NewReader(p)
	res, err := e.client.Index(e.index, reqBody)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return 0, fmt.Errorf("error sending log to Elasticsearch: %s", res.String())
	}
	return len(p), nil
}
