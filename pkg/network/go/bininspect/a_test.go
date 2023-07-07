package bininspect

import (
	"debug/elf"
	"github.com/stretchr/testify/require"
	"testing"
)

var functionsConfig = map[string]FunctionConfiguration{
	WriteGoTLSFunc: {
		IncludeReturnLocations: true,
		ParamLookupFunction:    GetWriteParams,
	},
	ReadGoTLSFunc: {
		IncludeReturnLocations: true,
		ParamLookupFunction:    GetReadParams,
	},
	CloseGoTLSFunc: {
		IncludeReturnLocations: false,
		ParamLookupFunction:    GetCloseParams,
	},
}

func TestInspectNewProcessBinary(t *testing.T) {
	//elfFile, err := elf.Open("/proc/751528/exe")
	elfFile, err := elf.Open("/proc/1812240/exe")
	require.NoError(t, err)
	_, err = InspectNewProcessBinary(elfFile, functionsConfig, nil)
	require.NoError(t, err)
	_, err = InspectNewProcessBinary(elfFile, functionsConfig, nil)
	require.NoError(t, err)
}

func BenchmarkInspectNotSupported(b *testing.B) {
	elfFile, err := elf.Open("/proc/926589/exe")
	require.NoError(b, err)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := InspectNewProcessBinary(elfFile, functionsConfig, nil)
		require.Error(b, err)
	}
}
func BenchmarkInspectSupported(b *testing.B) {
	elfFile, err := elf.Open("/proc/799777/exe")
	require.NoError(b, err)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := InspectNewProcessBinary(elfFile, functionsConfig, nil)
		require.NoError(b, err)
	}
}

//func BenchmarkRegexMatch(b *testing.B) {
//	re := regexp.MustCompile(`thisismystring`)
//
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		re.MatchString("this is a long text with thisismystring inside the text.")
//	}
//}
//func BenchmarkRegexNotMatch(b *testing.B) {
//	re := regexp.MustCompile(`thisismystring`)
//
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		re.MatchString("this is a long text with this ismystring inside the text.")
//	}
//}
//
//func BenchmarkStringContainsMatch(b *testing.B) {
//	re := `thisismystring`
//
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		strings.Contains("this is a long text with thisismystring inside the text.", re)
//	}
//}
//func BenchmarkStringContainsNotMatch(b *testing.B) {
//	re := `thisismystring`
//
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		strings.Contains("this is a long text with this ismystring inside the text.", re)
//	}
//}
//
//func BenchmarkMApCreation(b *testing.B) {
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		_ = make(map[string]elf.Symbol, 0)
//	}
//}
