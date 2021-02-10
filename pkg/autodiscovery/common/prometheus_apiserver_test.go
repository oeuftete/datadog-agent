// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build clusterchecks
// +build kubeapiserver

package common

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/providers/names"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestConfigsForService(t *testing.T) {
	tests := []struct {
		name  string
		check *PrometheusCheck
		svc   *corev1.Service
		want  []integration.Config
	}{
		{
			name:  "nominal case",
			check: DefaultPrometheusCheck,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					UID:         types.UID("foo-uid"),
					Name:        "svc-foo",
					Annotations: map[string]string{"prometheus.io/scrape": "true"},
				},
			},
			want: []integration.Config{
				{
					Name:          "openmetrics",
					InitConfig:    integration.Data("{}"),
					Instances:     []integration.Data{integration.Data(`{"prometheus_url":"http://%%host%%:%%port%%/metrics","namespace":"","metrics":["*"]}`)},
					ClusterCheck:  true,
					Provider:      names.PrometheusServices,
					Source:        "prometheus_services:kube_service_uid://foo-uid",
					ADIdentifiers: []string{"kube_service_uid://foo-uid"},
				},
			},
		},
		{
			name: "custom prometheus_url",
			check: &PrometheusCheck{
				Instances: []*OpenmetricsInstance{
					{
						URL:       "foo/bar",
						Metrics:   []string{"*"},
						Namespace: "",
					},
				},
			},
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					UID:         types.UID("foo-uid"),
					Name:        "svc-foo",
					Annotations: map[string]string{"prometheus.io/scrape": "true"},
				},
			},
			want: []integration.Config{
				{
					Name:          "openmetrics",
					InitConfig:    integration.Data("{}"),
					Instances:     []integration.Data{integration.Data(`{"prometheus_url":"foo/bar","namespace":"","metrics":["*"]}`)},
					ClusterCheck:  true,
					Provider:      names.PrometheusServices,
					Source:        "prometheus_services:kube_service_uid://foo-uid",
					ADIdentifiers: []string{"kube_service_uid://foo-uid"},
				},
			},
		},
		{
			name:  "excluded",
			check: DefaultPrometheusCheck,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					UID:         types.UID("foo-uid"),
					Name:        "svc-foo",
					Annotations: map[string]string{"prometheus.io/scrape": "false"},
				},
			},
			want: nil,
		},
		{
			name:  "no match",
			check: DefaultPrometheusCheck,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					UID:         types.UID("foo-uid"),
					Name:        "svc-foo",
					Annotations: map[string]string{"foo": "bar"},
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.check.Init())
			assert.ElementsMatch(t, tt.want, tt.check.ConfigsForService(tt.svc))
		})
	}
}
