// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package module

import (
	"github.com/DataDog/datadog-go/v5/statsd"
)

// TODO Split this
// Opts define module options
type Opts struct {
	StatsdClient       statsd.ClientInterface
	EventSender        EventSender
	DontDiscardRuntime bool
}
