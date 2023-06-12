// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package mutate

import (
	"encoding/base64"
	"errors"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/client-go/dynamic"

	"github.com/DataDog/datadog-agent/pkg/config"
)

const (
	cwsK8SUsername = "CWS_K8S_USERNAME"
	cwsK8SUID      = "CWS_K8S_UID"
	cwsK8SGroups   = "CWS_K8S_GROUPS"
)

var (
	cwsTargetNamespaces    = config.Datadog.GetStringSlice("admission_controller.cws_instrumentation.target.namespaces")
	cwsTargetAllNamespaces = config.Datadog.GetBool("admission_controller.cws_instrumentation.target.all_namespaces")
	allInjectedEnvs        = []string{cwsK8SUsername, cwsK8SUID, cwsK8SGroups}
)

// InjectCWSInstrumentation injects CWS instrumentation into exec or attach commands
func InjectCWSInstrumentation(rawPodExecOptions []byte, ns string, userInfo *authenticationv1.UserInfo, dc dynamic.Interface) ([]byte, error) {
	return mutatePodExecOptions(rawPodExecOptions, ns, userInfo, injectCWSInstrumentation, dc)
}

func injectCWSInstrumentation(exec *corev1.PodExecOptions, ns string, userInfo *authenticationv1.UserInfo, _ dynamic.Interface) error {
	if exec == nil {
		return errors.New("cannot inject CWS instrumentation into nil exec options")
	}

	// is the namespace targeted by the instrumentation ?
	if !isNsTargetedByCWSInstrumentation(ns) {
		return nil
	}

	// TODO check if the container has access to the cws instrumentation volume

	// A malicious user could try to prepend CWS env variables to the command in order to hide its identity, to prevent
	// this we always prepend the CWS env variables to the command.
	exec.Command = append([]string{
		"env",
		cwsK8SUsername + "=" + base64.RawStdEncoding.EncodeToString([]byte(userInfo.Username)),
		cwsK8SUID + "=" + base64.RawStdEncoding.EncodeToString([]byte(userInfo.UID)),
		cwsK8SGroups + "=" + base64.RawStdEncoding.EncodeToString([]byte(strings.Join(userInfo.Groups, ","))),
	}, exec.Command...)

	return nil
}

func isNsTargetedByCWSInstrumentation(ns string) bool {
	if cwsTargetAllNamespaces {
		return true
	}
	if len(cwsTargetNamespaces) == 0 {
		return false
	}
	for _, targetNs := range cwsTargetNamespaces {
		if ns == targetNs {
			return true
		}
	}
	return false
}
