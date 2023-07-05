package bininspect

import (
	"debug/elf"
	"github.com/stretchr/testify/require"
	"testing"
)

var functionsConfig = map[string]FunctionConfiguration{
	WriteGoTLSFunc: {},
	ReadGoTLSFunc:  {},
	CloseGoTLSFunc: {},
}

func TestInspectNewProcessBinary(t *testing.T) {
	//elfFile, err := elf.Open("/proc/751528/exe")
	elfFile, err := elf.Open("/proc/782923/exe")
	require.NoError(t, err)
	_, err = InspectNewProcessBinary(elfFile, functionsConfig, nil)
	require.NoError(t, err)
}

//func BenchmarkInspectOldNotSupported(b *testing.B) {
//	elfFile, err := elf.Open("/proc/751528/exe")
//	require.NoError(b, err)
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		InspectNewProcessBinary(elfFile, nil, nil)
//	}
//}
//
//func BenchmarkInspectNewNotSupported(b *testing.B) {
//	elfFile, err := elf.Open("/proc/751528/exe")
//	require.NoError(b, err)
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		InspectNewProcessBinaryNew(elfFile, nil, nil)
//	}
//}
//
//func BenchmarkInspectOldSupported(b *testing.B) {
//	elfFile, err := elf.Open("/proc/782923/exe")
//	require.NoError(b, err)
//	b.ResetTimer()
//	b.ReportAllocs()
//
//	for i := 0; i < b.N; i++ {
//		InspectNewProcessBinary(elfFile, nil, nil)
//	}
//}

func BenchmarkInspectNewSupported(b *testing.B) {
	elfFile, err := elf.Open("/proc/782923/exe")
	require.NoError(b, err)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		InspectNewProcessBinary(elfFile, functionsConfig, nil)
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
