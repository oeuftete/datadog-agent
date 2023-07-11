// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build otlp

package status

import (
	"fmt"
	"io"
	"net/http"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/otlp"
)

// GetOTLPStatus parses the otlp pipeline and its collector info to be sent to the frontend
func GetOTLPStatus() map[string]interface{} {
	if !otlp.IsEnabled(config.Datadog) {
		return map[string]interface{}{
			"otlpStatus":          false,
			"otlpCollectorStatus": otlp.CollectorStatus{Status: "Not running"},
		}
	}

	var status, statuserr string
	resp, err := getHTTPClient().Get(fmt.Sprintf("http://localhost:%s", config.Datadog.GetInt(config.OTLPHealthPort)))
	if err != nil {
		statuserr = fmt.Sprintf("Can not retrieve status: %s", err)
	}
	io.ReadAll(resp.Body) //nolint:errcheck
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		status = "Ready"
	case http.StatusInternalServerError:
		status = "Unavailable"
	}
	return map[string]interface{}{
		"otlpStatus":             true,
		"otlpCollectorStatus":    status,
		"otlpCollectorStatusErr": statuserr,
	}
}
