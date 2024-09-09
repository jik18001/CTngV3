package monitor

import (
	"fmt"
	"testing"

	def "github.com/jik18001/CTngV3/def"
)

func TestMonitorCryptoFunctionality(t *testing.T) {
	// Initialize a Monitor with 2 FSMCAs and 2 FSMLoggers
	m1 := NewMonitorEEA(def.CTngID("M1"), "../def/testconfig.json", "../def/testsettings.json")
	m2 := NewMonitorEEA(def.CTngID("M2"), "../def/testconfig.json", "../def/testsettings.json")
	m3 := NewMonitorEEA(def.CTngID("M3"), "../def/testconfig.json", "../def/testsettings.json")
	fmt.Println(m1.Settings.Ipmap[m1.CTngID])
	// Example test data
	testData := "test data"
	sigfrag1 := m1.ThresholdSign(testData)
	sigfrag2 := m2.ThresholdSign(testData)
	sigfrag3 := m3.ThresholdSign(testData)
	err := m1.FragmentVerify(testData, sigfrag1)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	siglist := []def.SigFragment{sigfrag1, sigfrag2, sigfrag3}
	sig := m1.Aggregate(siglist)
	err = m1.ThresholdVerify(testData, sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	testint, _ := def.MapIDtoInt(def.CTngID("M1"))
	fmt.Println(testint)
	testint, _ = def.MapIDtoInt(def.CTngID("L1"))
	fmt.Println(testint)
}
