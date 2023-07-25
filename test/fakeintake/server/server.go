// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package server implements a dummy http Datadog intake, meant to be used with integration and e2e tests.
// It runs an catch-all http server that stores submitted payloads into a dictionary of [api.Payloads], indexed by the route
// It implements 3 testing endpoints:
//   - /fakeintake/payloads/<payload_route> returns any received payloads on the specified route as [api.Payload]s
//   - /fakeintake/health returns current fakeintake server health
//   - /fakeintake/routestats returns stats for collected payloads, by route
//   - /fakeintake/flushPayloads returns all stored payloads and clear them up
//
// [api.Payloads]: https://pkg.go.dev/github.com/DataDog/datadog-agent@main/test/fakeintake/api#Payload
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/DataDog/datadog-agent/test/fakeintake/aggregator"
	"github.com/DataDog/datadog-agent/test/fakeintake/api"
	"github.com/benbjohnson/clock"
)

type Server struct {
	mu                 sync.RWMutex
	server             http.Server
	ready              chan bool
	clock              clock.Clock
	logAggregator      aggregator.LogAggregator
	metricAggregator   aggregator.MetricAggregator
	checkRunAggregator aggregator.CheckRunAggregator

	url string

	payloadStore     map[string][]api.Payload
	payloadJsonStore map[string][]api.ParsedPayload
}

// NewServer creates a new fake intake server and starts it on localhost:port
// options accept WithPort and WithReadyChan.
// Call Server.Start() to start the server in a separate go-routine
// If the port is 0, a port number is automatically chosen
func NewServer(options ...func(*Server)) *Server {
	fi := &Server{
		mu:                 sync.RWMutex{},
		payloadStore:       map[string][]api.Payload{},
		payloadJsonStore:   map[string][]api.ParsedPayload{},
		clock:              clock.New(),
		logAggregator:      aggregator.NewLogAggregator(),
		metricAggregator:   aggregator.NewMetricAggregator(),
		checkRunAggregator: aggregator.NewCheckRunAggregator(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", fi.handleDatadogRequest)
	mux.HandleFunc("/fakeintake/payloads/", fi.handleGetPayloads)
	mux.HandleFunc("/fakeintake/health/", fi.handleFakeHealth)
	mux.HandleFunc("/fakeintake/routestats/", fi.handleGetRouteStats)
	mux.HandleFunc("/fakeintake/flushPayloads/", fi.handleFlushPayloads)

	fi.server = http.Server{
		Handler: mux,
		Addr:    ":0",
	}

	for _, opt := range options {
		opt(fi)
	}

	return fi
}

// WithPort changes the server port.
// If the port is 0, a port number is automatically chosen
func WithPort(port int) func(*Server) {
	return func(fi *Server) {
		if fi.URL() != "" {
			log.Println("Fake intake is already running. Stop it and try again to change the port.")
			return
		}
		fi.server.Addr = fmt.Sprintf(":%d", port)
	}
}

// WithReadyChannel assign a boolean channel to get notified when the server is ready.
func WithReadyChannel(ready chan bool) func(*Server) {
	return func(fi *Server) {
		if fi.URL() != "" {
			log.Println("Fake intake is already running. Stop it and try again to change the ready channel.")
			return
		}
		fi.ready = ready
	}
}

func WithClock(clock clock.Clock) func(*Server) {
	return func(fi *Server) {
		if fi.URL() != "" {
			log.Println("Fake intake is already running. Stop it and try again to change the clock.")
			return
		}
		fi.clock = clock
	}
}

// Start Starts a fake intake server in a separate go-routine
// Notifies when ready to the ready channel
func (fi *Server) Start() {
	if fi.URL() != "" {
		log.Printf("Fake intake alredy running at %s", fi.URL())
		if fi.ready != nil {
			fi.ready <- true
		}
		return
	}
	go func() {
		// explicitly creating a listener to get the actual port
		// as http.Server.ListenAndServe hides this information
		// https://github.com/golang/go/blob/go1.19.6/src/net/http/server.go#L2987-L3000
		listener, err := net.Listen("tcp", fi.server.Addr)
		if err != nil {
			log.Printf("Error creating fake intake server at %s: %v", fi.server.Addr, err)

			if fi.ready != nil {
				fi.ready <- false
			}

			return
		}
		fi.url = "http://" + listener.Addr().String()
		// notify server is ready, if anybody is listening
		if fi.ready != nil {
			fi.ready <- true
		}
		// server.Serve blocks and listens to requests
		err = fi.server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("Error creating fake intake server at %s: %v", listener.Addr().String(), err)
			return
		}
	}()
}

func (fi *Server) URL() string {
	return fi.url
}

// Stop Gracefully stop the http server
func (fi *Server) Stop() error {
	if fi.URL() == "" {
		return fmt.Errorf("server not running")
	}
	err := fi.server.Shutdown(context.Background())
	if err != nil {
		return err
	}
	fi.url = ""
	return nil
}

type postPayloadResponse struct {
	Errors []string `json:"errors"`
}

func (fi *Server) handleDatadogRequest(w http.ResponseWriter, req *http.Request) {
	if req == nil {
		response := buildPostResponse(errors.New("invalid request, nil request"))
		writeHttpResponse(w, response)
		return
	}

	log.Printf("Handling Datadog %s request to %s, header %v", req.Method, req.URL.Path, req.Header)

	if req.Method == http.MethodGet {
		writeHttpResponse(w, httpResponse{
			statusCode: http.StatusOK,
		})
		return
	}

	// from now on accept only POST requests
	if req.Method != http.MethodPost {
		response := buildPostResponse(fmt.Errorf("invalid request with route %s and method %s", req.URL.Path, req.Method))
		writeHttpResponse(w, response)
		return
	}

	if req.Body == nil {
		response := buildPostResponse(errors.New("invalid request, nil body"))
		writeHttpResponse(w, response)
		return
	}
	payload, err := io.ReadAll(req.Body)
	if err != nil {
		response := buildPostResponse(err)
		writeHttpResponse(w, response)
		return
	}

	fi.safeAppendPayload(req.URL.Path, payload, req.Header.Get("Content-Encoding"))
	response := buildPostResponse(nil)
	writeHttpResponse(w, response)
}

func (fi *Server) handleFlushPayloads(w http.ResponseWriter, req *http.Request) {
	fi.safeFlushPayloads()

	// send response
	writeHttpResponse(w, httpResponse{
		statusCode: http.StatusOK,
	})
}

func buildPostResponse(responseError error) httpResponse {
	ret := httpResponse{}

	ret.contentType = "application/json"
	ret.statusCode = http.StatusAccepted

	resp := postPayloadResponse{}
	if responseError != nil {
		ret.statusCode = http.StatusBadRequest
		resp.Errors = []string{responseError.Error()}
	}
	body, err := json.Marshal(resp)

	if err != nil {
		return httpResponse{
			statusCode:  http.StatusInternalServerError,
			contentType: "text/plain",
			body:        []byte(err.Error()),
		}
	}

	ret.body = body

	return ret
}

func (fi *Server) handleGetPayloads(w http.ResponseWriter, req *http.Request) {
	routes := req.URL.Query()["endpoint"]
	if len(routes) == 0 {
		writeHttpResponse(w, httpResponse{
			contentType: "text/plain",
			statusCode:  http.StatusBadRequest,
			body:        []byte("missing endpoint query parameter"),
		})
		return
	}
	format := req.URL.Query().Get("format") // raw or json
	if format == "" {
		format = "raw"
	}

	// we could support multiple endpoints in the future
	route := routes[0]
	log.Printf("Handling GetPayload request for %s payloads in %s format.", route, format)
	var jsonResp []byte
	var err error
	if format == "raw" {
		payloads := fi.safeGetRawPayloads(route)

		// build response
		resp := api.APIFakeIntakePayloadsRawGETResponse{
			Payloads: payloads,
		}
		jsonResp, err = json.Marshal(resp)
	} else {
		payloads := fi.safeGetJsonPayloads(route)

		// build response
		resp := api.APIFakeIntakePayloadsJsonGETResponse{
			Payloads: payloads,
		}
		jsonResp, err = json.Marshal(resp)
	}

	if err != nil {
		writeHttpResponse(w, httpResponse{
			contentType: "text/plain",
			statusCode:  http.StatusInternalServerError,
			body:        []byte(err.Error()),
		})
		return
	}
	// send response
	writeHttpResponse(w, httpResponse{
		contentType: "application/json",
		statusCode:  http.StatusOK,
		body:        jsonResp,
	})
}

func (fi *Server) handleFakeHealth(w http.ResponseWriter, req *http.Request) {
	writeHttpResponse(w, httpResponse{
		statusCode: http.StatusOK,
	})
}

func (fi *Server) safeAppendPayload(route string, data []byte, encoding string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if _, found := fi.payloadStore[route]; !found {
		fi.payloadStore[route] = []api.Payload{}
	}
	newPayload := api.Payload{
		Timestamp: fi.clock.Now(),
		Data:      data,
		Encoding:  encoding,
	}
	parsedPayload := api.ParsedPayload{
		Timestamp: newPayload.Timestamp,
		Data:      "",
		Encoding:  encoding,
	}
	fi.payloadStore[route] = append(fi.payloadStore[route], newPayload)

	if route == "/api/v2/logs" {
		parsedPayload.Data = fi.getLogPayLoadData(newPayload)
	} else if route == "/api/v2/series" {
		parsedPayload.Data = fi.getMetricPayLoadData(newPayload)
	} else if route == "/api/v1/check_run" {
		parsedPayload.Data = fi.getCheckRunPayLoadData(newPayload)
	}
	fi.payloadJsonStore[route] = append(fi.payloadJsonStore[route], parsedPayload)
}

func (fi *Server) getLogPayLoadData(payload api.Payload) string {
	logs, err := aggregator.ParseLogPayload(payload)
	if err != nil {
		return "ERROR"
	}

	output, er := json.Marshal(logs)
	if er != nil {
		return "ERROR"
	}
	return string(output)
}

func (fi *Server) getMetricPayLoadData(payload api.Payload) string {
	MetricOutput, err := aggregator.ParseMetricSeries(payload)
	if err != nil {
		return "1- ERROR : " + err.Error()
	}

	output, er := json.Marshal(MetricOutput)
	if er != nil {
		return "2- ERROR : " + er.Error()
	}
	return string(output)
}

func (fi *Server) getCheckRunPayLoadData(payload api.Payload) string {
	MetricOutput, err := aggregator.ParseCheckRunPayload(payload)
	if err != nil {
		return "ERROR"
	}

	output, er := json.Marshal(MetricOutput)
	if er != nil {
		return "ERROR"
	}
	return string(output)
}

func (fi *Server) safeGetRawPayloads(route string) []api.Payload {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	payloads := make([]api.Payload, 0, len(fi.payloadStore[route]))
	payloads = append(payloads, fi.payloadStore[route]...)
	return payloads
}

func (fi *Server) safeGetJsonPayloads(route string) []api.ParsedPayload {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	payloads := make([]api.ParsedPayload, 0, len(fi.payloadJsonStore[route]))
	payloads = append(payloads, fi.payloadJsonStore[route]...)
	return payloads
}

func (fi *Server) safeFlushPayloads() {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.payloadStore = map[string][]api.Payload{}
}

func (fi *Server) handleGetRouteStats(w http.ResponseWriter, req *http.Request) {
	log.Print("Handling getRouteStats request")
	routes := fi.safeGetRouteStats()
	// build response
	resp := api.APIFakeIntakeRouteStatsGETResponse{
		Routes: map[string]api.RouteStat{},
	}
	for route, count := range routes {
		resp.Routes[route] = api.RouteStat{ID: route, Count: count}
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		writeHttpResponse(w, httpResponse{
			contentType: "text/plain",
			statusCode:  http.StatusInternalServerError,
			body:        []byte(err.Error()),
		})
		return
	}

	// send response
	writeHttpResponse(w, httpResponse{
		contentType: "application/json",
		statusCode:  http.StatusOK,
		body:        jsonResp,
	})
}

func (fi *Server) safeGetRouteStats() map[string]int {
	routes := map[string]int{}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	for route, payloads := range fi.payloadStore {
		routes[route] = len(payloads)
	}
	return routes
}
