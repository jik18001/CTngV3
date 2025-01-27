package deter

import (
	"flag"
	"fmt"
	"testing"

	def "github.com/jik18001/CTngV3/def"
)

func TestSimulationIO(t *testing.T) {
	num_monitors := 32
	Mal := 8
	num_loggers := 8
	num_cas := 8
	// Generate a new configuration using CTngKeyGen function with specified parameters.
	newconfig := def.CTngKeyGen(num_loggers, num_cas, num_monitors, Mal+1)

	// Encode the new configuration into a storable format.
	storedconfig := def.EncodeCrypto(newconfig)

	// Write the encoded configuration to a file and handle any errors.
	err := def.WriteData(storedconfig, "deterconfig.json")
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Define command-line flags for the number of CAs, Loggers, and Monitors.
	num_ca := flag.Int("num_ca", num_cas, "Number of CAs")
	num_logger := flag.Int("num_logger", num_loggers, "Number of Loggers")
	num_monitor := flag.Int("num_monitor", num_monitors, "Number of Monitors")
	mal := flag.Int("mal", Mal, "Number of faulty monitors allowed")

	//deter mask and offset

	ca_mask := flag.String("ca_mask", "172.30.0.", "CA IP mask")
	ca_offset := flag.Int("ca_offset", 11, "CA IP offset")
	logger_mask := flag.String("logger_mask", "172.30.0.", "Logger IP mask")
	logger_offset := flag.Int("logger_offset", 20, "Logger IP offset")
	monitor_mask := flag.String("monitor_mask", "172.30.0.", "Monitor IP mask")
	monitor_offset := flag.Int("monitor_offset", 28, "Monitor IP offset")

	// Define command-line flags for starting port number, wait time, and other settings.
	starting_port := flag.Int("starting_port", 8000, "Starting port number")
	update_wait_time := flag.Int("update_wait_time", 5, "Wait time in seconds")
	mature_wait_time := flag.Int("mature_wait_time", 0, "Wait time in seconds")
	response_wait_time := flag.Int("reponse_wait_time", 6, "Wait time in seconds")
	verification_wait_time := flag.Int("verification_wait_time", 10, "Wait time in seconds")
	mud := flag.Int("mud", 60, "Maximum Update Delay (some integer value) in seconds")
	//bmode := flag.String("bmode", def.MIN_WT, "Mode: Min bandwidth or Min wait time")
	bmode := flag.String("bmode", def.MIN_BC, "Mode: Min bandwidth or Min wait time")
	dmode := flag.String("dmode", def.DEFAULT, "Mode: default or EEA")
	//dmode := flag.String("dmode", def.EEA, "Mode: default or EEA")
	crvsize := flag.Int("CRV_size", 100000000, "CRV_size")
	revocation_ratio := flag.Float64("Revocation_ratio", 0.002, "Revocation_ratio (float)")
	certificate_size := flag.Int("Cerificate_size", 2000, "Size of dummy certificate, in Bytes")
	certificate_per_logger := flag.Int("Certificate_per_logger", 5000, "New certificates per period")

	// Parse the command-line flags.
	flag.Parse()

	// Generate the IP settings template using the parsed flag values.
	settings := def.Generate_IP_Json_template(
		*num_ca, *num_logger, *num_monitor, *mal,
		*ca_mask, *ca_offset,
		*logger_mask, *logger_offset,
		*monitor_mask, *monitor_offset,
		*starting_port, *update_wait_time, *mature_wait_time, *response_wait_time, *verification_wait_time,
		*mud, *dmode, *bmode, *crvsize, *revocation_ratio, *certificate_size, *certificate_per_logger,
	)

	// Write the generated settings to a file and handle any errors.
	err = def.WriteData(settings, "detersettings.json")
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
	fmt.Println(def.GetMonitorURL(*settings))
	fmt.Println(def.GetIDs('M', *settings))
	fmt.Println(def.MapIDtoInt(def.CTngID("C8")))
}
