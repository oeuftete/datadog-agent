package snmp

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/snmp/valuestore"
)

func fetchValues(session sessionAPI, config CheckConfig) (*valuestore.ResultValueStore, error) {
	// fetch scalar values
	scalarResults, err := fetchScalarOidsWithBatching(session, config.OidConfig.ScalarOids, config.oidBatchSize)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scalar oids with batching: %v", err)
	}

	// fetch column values
	oids := make(map[string]string, len(config.OidConfig.ColumnOids))
	for _, value := range config.OidConfig.ColumnOids {
		oids[value] = value
	}
	columnResults, err := fetchColumnOidsWithBatching(session, oids, config.oidBatchSize, config.bulkMaxRepetitions)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oids with batching: %v", err)
	}

	return &valuestore.ResultValueStore{ScalarValues: scalarResults, ColumnValues: columnResults}, nil
}
