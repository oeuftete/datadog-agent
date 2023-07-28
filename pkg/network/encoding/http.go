// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package encoding

import (
	"bytes"
	"github.com/gogo/protobuf/proto"
	"io"

	model "github.com/DataDog/agent-payload/v5/process"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/types"
)

type httpEncoder struct {
	builder      *model.HTTPAggregationsBuilder
	byConnection *USMConnectionIndex[http.Key, *http.RequestStats]
}

func newHTTPEncoder(payload *network.Connections) *httpEncoder {
	if len(payload.HTTP) == 0 {
		return nil
	}

	return &httpEncoder{
		builder: model.NewHTTPAggregationsBuilder(nil),
		byConnection: GroupByConnection("http", payload.HTTP, func(key http.Key) types.ConnectionKey {
			return key.ConnectionKey
		}),
	}
}

func (e *httpEncoder) GetHTTPAggregationsAndTags(c network.ConnectionStats, builder *model.ConnectionBuilder) (uint64, map[string]struct{}) {
	if e == nil {
		return 0, nil
	}

	connectionData := e.byConnection.Find(c)
	if connectionData == nil || len(connectionData.Data) == 0 || connectionData.IsPIDCollision(c) {
		return 0, nil
	}

	var (
		staticTags  uint64
		dynamicTags map[string]struct{}
	)

	builder.SetHttpAggregations(func(b *bytes.Buffer) {
		staticTags, dynamicTags = e.encodeData(connectionData, b)
	})
	return staticTags, dynamicTags
}

func (e *httpEncoder) encodeData(connectionData *USMConnectionData[http.Key, *http.RequestStats], w io.Writer) (uint64, map[string]struct{}) {
	var staticTags uint64
	dynamicTags := make(map[string]struct{})
	e.builder.Reset(w)

	for _, kvPair := range connectionData.Data {
		e.builder.AddEndpointAggregations(func(httpStatsBuilder *model.HTTPStatsBuilder) {
			key := kvPair.Key
			stats := kvPair.Value

			httpStatsBuilder.SetPath(key.Path.Content)
			httpStatsBuilder.SetFullPath(key.Path.FullPath)
			httpStatsBuilder.SetMethod(uint64(model.HTTPMethod(key.Method)))

			for code, stats := range stats.Data {
				httpStatsBuilder.AddStatsByStatusCode(func(w *model.HTTPStats_StatsByStatusCodeEntryBuilder) {

					if code != 0 {
						w.SetKey(int32(code))
					}
					w.SetValue(func(w *model.HTTPStats_DataBuilder) {
						w.SetCount(uint32(stats.Count))
						if latencies := stats.Latencies; latencies != nil {

							// TODO: can we get a streaming marshaller for latencies?
							blob, _ := proto.Marshal(latencies.ToProto())
							w.SetLatencies(func(b *bytes.Buffer) {
								b.Write(blob)
							})
						} else {
							w.SetFirstLatencySample(stats.FirstLatencySample)
						}
					})
				})

				staticTags |= stats.StaticTags
				for _, dynamicTag := range stats.DynamicTags {
					dynamicTags[dynamicTag] = struct{}{}
				}
			}
		})

	}
	return staticTags, dynamicTags
}

func (e *httpEncoder) Close() {
	if e == nil {
		return
	}

	e.byConnection.Close()
}
