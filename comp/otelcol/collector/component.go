// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package collector

import (
	"context"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/config"
	corelog "github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/otlp"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Component specifies the interface implemented by the collector module.
type Component interface{}

// Params specifies a set of parameters used for configuring this module.
type Params struct {
	// Stopped reports whether the Collector should be stopped. This is used
	// to prevent startup in systems where the Collector is disabled by
	// external config.
	Stopped bool
}

// Module specifies the Collector module bundle.
var Module = fxutil.Component(
	fx.Provide(newPipeline),
)

// dependencies specifies a list of dependencies required for the collector
// to be instantiated.
type dependencies struct {
	fx.In

	// Lc specifies the fx lifecycle settings, used for appending startup
	// and shutdown hooks.
	Lc fx.Lifecycle

	// Config specifies the Datadog Agent's configuration component.
	Config config.Component

	// Log specifies the logging component.
	Log corelog.Component

	// Serializer specifies the metrics serializer that is used to export metrics
	// to Datadog.
	Serializer serializer.MetricSerializer

	// Params specifies an additional set of user-specifies parameters.
	Params Params
}

// newPipeline creates a new Component for this module and returns any errors on failure.
func newPipeline(deps dependencies) (Component, error) {
	col, err := otlp.NewPipelineFromAgentConfig(deps.Config, deps.Serializer)
	if err != nil {
		return col, err
	}
	if deps.Params.Stopped {
		return col, nil
	}
	deps.Lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			// the context passed to this function has a startup deadline which
			// will shutdown the collector prematurely
			ctx := context.Background()
			go func() {
				if err := col.Run(ctx); err != nil {
					deps.Log.Errorf("Error running the OTLP pipeline: %w", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			col.Stop()
			return nil
		},
	})
	return col, nil
}
