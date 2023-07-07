// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"encoding/json"
	"net/http"
)

type httpResponse struct {
	contentType string
	statusCode  int
	body        []byte
}

func writeHttpResponse(w http.ResponseWriter, response httpResponse) {
	if response.contentType != "" {
		w.Header().Set("Content-Type", response.contentType)
	}
	w.WriteHeader(response.statusCode)
	if len(response.body) > 0 {
		w.Write(response.body)
	}
}

type errorResponse struct {
	Errors []string `json:"errors"`
}

// Same struct as in datadog-agent/comp/core/flare/helpers/send_flare.go
type flareResponse struct {
	CaseID int    `json:"case_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

func buildErrorResponse(responseError error) httpResponse {
	statusCode := http.StatusAccepted

	resp := errorResponse{}
	if responseError != nil {
		statusCode = http.StatusBadRequest
		resp.Errors = []string{responseError.Error()}
	}

	return buildResponse(resp, statusCode, "application/json")
}

func buildSuccessResponse(urlPath string) httpResponse {
	var body interface{}
	if urlPath == "/support/flare" {
		body = flareResponse{}
	} else {
		body = errorResponse{}
	}

	return buildResponse(body, http.StatusOK, "application/json")
}

func buildResponse(body interface{}, statusCode int, contentType string) httpResponse {
	resp := httpResponse{contentType: contentType, statusCode: statusCode}

	bodyJson, err := json.Marshal(body)

	if err != nil {
		return httpResponse{
			statusCode:  http.StatusInternalServerError,
			contentType: "text/plain",
			body:        []byte(err.Error()),
		}
	}

	resp.body = bodyJson
	return resp
}
