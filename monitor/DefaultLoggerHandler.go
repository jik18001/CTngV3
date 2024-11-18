package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"time"

	def "github.com/jik18001/CTngV3/def"
	merkletree "github.com/txaty/go-merkletree"
	//rs "github.com/klauspost/reedsolomon"
)

func defaultLSMWakeup(m *MonitorEEA, lsm *FSMLoggerEEA, c def.Context) {

	switch c.Label {
	case def.WAKE_TC:
		// Placeholder for WAKE_TC event handling
		fmt.Println("WAKE_TC event triggered. Placeholder logic executed.")

	case def.WAKE_TM:
		fmt.Println("WAKE_TM event triggered.")
		if !reflect.DeepEqual(lsm.APoM, def.APoM{}) || !reflect.DeepEqual(lsm.CPoM, def.CPoM{}) {
			fmt.Println("PoM present")
			return
		}
		sth_fork := lsm.STH
		sth_fork.Signature = def.RSASig{}
		sthBytes, err := json.Marshal(sth_fork)
		if err != nil {
			log.Fatalf("Failed to serialize STH: %v", err)
		}
		fmt.Println("TBS: ", sth_fork)
		sigfrag := m.ThresholdSign(string(sthBytes))
		sigstring := sigfrag.String()
		monitor_signed_data := MonitorSignedData{
			Type:      "STH",
			CTngID:    def.CTngID(sth_fork.LID),
			Signature: sigstring,
		}
		msd_json, err := json.Marshal(monitor_signed_data)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		broadcastEEA(m, "/monitor/default_transparency_partial_signature", msd_json)
		fmt.Println("transparency_partial_signature broadcasted")

	case def.WAKE_TR:
		//Place holder for WAKE_TR event, it's already implemented in the default_transparency_notification_handler

	case def.WAKE_TU:
		// Placeholder for WAKE_TU event handling
		fmt.Println("WAKE_TU event triggered. Placeholder logic executed.")

	case def.WAKE_TV:
		// Placeholder for WAKE_TV event handling
		fmt.Println("WAKE_TV event triggered. Placeholder logic executed.")
	}
}

func check_and_send_valid_sth(m *MonitorEEA, fsmlogger *FSMLoggerEEA, sth def.STH) {
	STH_fork := sth
	STH_fork.Signature = def.RSASig{}
	sthBytes, err := json.Marshal(STH_fork)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}
	err = m.Crypto.Verify(sthBytes, sth.Signature)
	if err != nil {
		return
	}
	fsmlogger.SetField("State", def.PRECOMMIT)
	fsmlogger.SetField("STH", sth)
	fmt.Println("Transitioned to: ", fsmlogger.State)

	STH_only_update := def.Update_Logger{
		STH:  sth,
		File: [][]byte{},
	}
	sth_json, err := json.Marshal(STH_only_update)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/logger_update", sth_json)
	NewContext := def.Context{
		Label: def.WAKE_TM,
	}
	// Run this in a new goroutine
	go func() {
		time.AfterFunc(time.Duration(m.Settings.Verification_Wait_time)*time.Second, func() {
			value, _ := fsmlogger.GetField("DataCheck")
			dataCheckValue, _ := value.(bool)
			fmt.Println(m.Settings.Verification_Wait_time, dataCheckValue)
			if dataCheckValue {
				defaultLSMWakeup(m, fsmlogger, NewContext)
			} else {
				fmt.Println("Place holder for accusation.")
			}
		})
	}()

}

func check_and_send_conflict_sth(m *MonitorEEA, fsmlogger *FSMLoggerEEA, sth def.STH) bool {
	sth2, _ := fsmlogger.GetField("STH")
	// if we already have an existing STH
	if !reflect.DeepEqual(sth2, def.STH{}) {
		// we compare the sth against the existing record and broadcast a cPoM when needed
		sthsigbytes, _ := json.Marshal(sth)
		sthsigbytes2, _ := json.Marshal(sth2)
		if !reflect.DeepEqual(sthsigbytes, sthsigbytes2) {
			cPoM := &def.CPoM{
				Entity_Convicted: def.CTngID(sth.LID),
				MetaData1:        sth,
				MetaData2:        sth2,
			}
			err := fsmlogger.AddCPoM(*cPoM)
			//This means the cPoM is the first to be added
			if err == nil {
				fsmlogger.SetField("State", def.POM)
				fmt.Println("Switched to PoM State")
				STH_only_update := def.Update_Logger{
					STH:  sth,
					File: [][]byte{},
				}
				sth_json, err := json.Marshal(STH_only_update)
				if err != nil {
					log.Fatalf("Failed to marshal update: %v", err)
				}
				broadcastEEA(m, "/monitor/logger_update", sth_json)
			}

			/*
				cPoM_json, err := json.Marshal(cPoM)
				if err != nil {
					log.Fatalf("Failed to marshal update: %v", err)
				}
				broadcastEEA(m, "/monitor/PoM", cPoM_json)
			*/
			return true
		}
	}
	return false
}

func check_and_send_notifcation(m *MonitorEEA, fsmlogger *FSMLoggerEEA, update def.Update_Logger) {
	certs, _ := fsmlogger.GetField("Data")
	if !reflect.DeepEqual(certs, [][]byte{}) {
		return
	}
	STH_fork := update.STH
	STH_fork.Signature = def.RSASig{}
	sthBytes, err := json.Marshal(STH_fork)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}
	err = m.Crypto.Verify(sthBytes, update.STH.Signature)
	if err != nil {
		fmt.Println("Failed to verify the STH")
		return
	}

	//PoI verification
	data := update.File
	var dataBlocks []merkletree.DataBlock
	for i := range data[:(m.Settings.Num_Monitors - m.Settings.Mal)] {
		for j := 0; j < len(data[i]); j += m.Settings.Certificate_size {
			end := j + m.Settings.Certificate_size
			if end > len(data[i]) {
				end = len(data[i])
			}
			dataBlocks = append(dataBlocks, &def.LeafBlock{Content: data[i][j:end]})
		}
	}
	// Generate Merkle Tree
	tree, err := def.GenerateMerkleTree(dataBlocks)
	def.HandleError(err, "MT Generation")
	rootHash := def.GenerateRootHash(tree)
	if !reflect.DeepEqual(rootHash, update.STH.Head) {
		fmt.Println("PoI verification Failed!")
		return
	}
	fsmlogger.SetField("Data", update.File)
	fsmlogger.SetField("DataCheck", true)
	new_note := def.Notification{
		Type:       def.TUEEA,
		Originator: def.CTngID(update.STH.LID),
		//Monitor:    update.MonitorID,
		Sender: m.Self_ip_port,
	}
	//fmt.Println(new_note)
	new_note_json, err := json.Marshal(new_note)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/default_transparency_notification", new_note_json)
}

func process_logger_update(m *MonitorEEA, update def.Update_Logger) {
	// retrieve te state machine first
	index, _ := def.MapIDtoInt(def.CTngID(update.STH.LID))
	var fsmlogger *FSMLoggerEEA
	fsmlogger = m.FSMLoggerEEAs[index]
	current_state, _ := fsmlogger.GetField("State")

	if current_state == def.INIT {
		check_and_send_valid_sth(m, fsmlogger, update.STH)

	} else {
		if check_and_send_conflict_sth(m, fsmlogger, update.STH) {
			fmt.Println("Conflict Found.")
			return
		}
	}
	if update.File != nil && len(update.File) > 0 {
		check_and_send_notifcation(m, fsmlogger, update)
	}

}

func logger_update_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	// Create a counter to track the number of bytes read
	var byteCounter int64

	// Create a TeeReader to count bytes while reading from r.Body
	counterReader := io.TeeReader(r.Body, &countWriter{count: &byteCounter})

	// Parse the update
	var update def.Update_Logger
	if err := json.NewDecoder(counterReader).Decode(&update); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}

	// Retrieve the FSMLogger corresponding to the STH LID in the update
	index, _ := def.MapIDtoInt(def.CTngID(update.STH.LID))
	fsmlogger := m.FSMLoggerEEAs[index]

	// Retrieve the current traffic count and ensure type assertion
	trafficcountInterface, _ := fsmlogger.GetField("TrafficCount")
	trafficcount := trafficcountInterface.(int) // Assert as int

	// Update the traffic count by adding the size of the request body
	newcount := trafficcount + int(byteCounter)
	fsmlogger.SetField("TrafficCount", newcount)

	// Retrieve the current traffic count and ensure type assertion
	if update.File != nil && len(update.File) > 0 {
		fmt.Println("New Update received with size", byteCounter)
		updatecountInterface, _ := fsmlogger.GetField("UpdateCount")
		updatecount := updatecountInterface.(int) // Assert as int
		// Update the traffic count by adding the size of the request body
		newucount := updatecount + 1
		fsmlogger.SetField("UpdateCount", newucount)
	}

	// Process the logger update
	process_logger_update(m, update)
}

func default_transparency_request_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var new_note def.Notification
	if err := json.NewDecoder(r.Body).Decode(&new_note); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	loggerindex, _ := def.MapIDtoInt(new_note.Originator)
	//fmt.Println(new_note.Originator, loggerindex)
	fsmlogger := m.FSMLoggerEEAs[loggerindex]
	//fmt.Println(fsmlogger.State)

	//update, err := fsmlogger.GetUpdate(def.CTngID(new_note.Monitor))
	data, err := fsmlogger.GetField("Data")
	if err != nil {
		return
	}

	// Assert that data is of type [][]byte
	dataBytes, ok := data.([][]byte)
	if !ok {
		// Handle the case where the type assertion fails
		return //fmt.Errorf("failed to assert type of Data")
	}

	sth, err := fsmlogger.GetField("STH")
	if err != nil {
		return
	}

	// Assert that sth is of type def.STH
	sthStruct, ok := sth.(def.STH)
	if !ok {
		// Handle the case where the type assertion fails
		return //fmt.Errorf("failed to assert type of STH")
	}
	//fmt.Println(update.MonitorID)
	update := def.Update_Logger{
		STH:  sthStruct,
		File: dataBytes,
	}
	update_json, err := json.Marshal(update)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	url := "http://" + new_note.Sender + "/monitor/logger_update_EEA"
	_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(update_json))
	if err != nil {
		//fmt.Println("Failed to send update: ", err)
	}
}
func default_transparency_notification_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var new_note def.Notification
	if err := json.NewDecoder(r.Body).Decode(&new_note); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	//fmt.Println(new_note)
	new_note_fork := new_note
	new_note_fork.Sender = m.Self_ip_port
	// locate the corresponding FSMLoggerEEA
	loggerindex, _ := def.MapIDtoInt(new_note.Originator)
	fsmlogger := m.FSMLoggerEEAs[loggerindex]
	if m.Settings.Broadcasting_Mode == def.MIN_WT {
		//existing_update, _ := fsmlogger.GetUpdate(new_note.Monitor)
		//return if we already have the update
		//if !reflect.DeepEqual(existing_update, def.Update_Logger_EEA{}) {
		//	return
		//}
		data, err := fsmlogger.GetField("Data")
		if err != nil {
			return
		}
		if !reflect.DeepEqual(data, [][]byte{}) {
			return
		}
		url := "http://" + new_note.Sender + "/monitor/transparency_request"
		new_note_json, err := json.Marshal(new_note_fork)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
		if err != nil {
			//fmt.Println("Failed to send update: ", err)
		}
	}
	if m.Settings.Broadcasting_Mode == def.MIN_BC {
		// locate the corresponding FSMLoggerEEA
		// loggerindex, _ := def.MapIDtoInt(new_note.Originator)
		// fsmlogger := m.FSMLoggerEEAs[loggerindex]
		if fsmlogger.GetFirstNotification() == nil {
			url := "http://" + new_note.Sender + "/monitor/transparency_request"
			new_note_json, err := json.Marshal(new_note_fork)
			if err != nil {
				log.Fatalf("Failed to marshal update: %v", err)
			}
			_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
			if err != nil {
				fmt.Println("Failed to send update: ", err)
			}
			NewContext := def.Context{
				Label:   def.WAKE_TR,
				Content: new_note,
			}
			time.AfterFunc(time.Duration(m.Settings.Response_Wait_time)*time.Second, func() {
				LSMWakeup(m, fsmlogger, NewContext)

				//monitorindex, _ := def.MapIDtoInt(def.CTngID(new_note.Monitor))
				//_, err := fsmlogger.GetDataFragment(monitorindex)
				value, _ := fsmlogger.GetField("DataCheck")
				dataCheckValue, _ := value.(bool)
				if dataCheckValue == false {
					notifications := fsmlogger.GetNotifications()
					for _, notification := range notifications {
						url := "http://" + notification.Sender + "/monitor/transparency_request"
						_, err := m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
						if err != nil {
							//fmt.Println("Failed to send update: ", err)
						}
					}
				}

			})
		}
		fsmlogger.AddNotification(new_note)
	}

}

func default_transparency_partial_signature_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	//fmt.Println("MSD received")
	var msd MonitorSignedData
	if err := json.NewDecoder(r.Body).Decode(&msd); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	index, _ := def.MapIDtoInt(def.CTngID(msd.CTngID))
	fsmlogger := m.FSMLoggerEEAs[index]

	sth, err := fsmlogger.GetField("STH")
	if err != nil {
		fmt.Println("Error retrieving STH field:", err)
		return
	}
	sth_fork, ok := sth.(def.STH)
	if !ok {
		// Handle the case where the assertion fails
		fmt.Println("sth_fork is not of type STH")
		return
	}
	sth_fork.Signature = def.RSASig{}
	sthBytes, err := json.Marshal(sth_fork)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}
	//fmt.Println("TBV: ", sth_fork)
	sigfrag, _ := def.SigFragmentFromString(msd.Signature)
	err = m.FragmentVerify(string(sthBytes), sigfrag)
	if err != nil {
		fmt.Println("partial Signature verification failed: ", err)
		return
	}

	if fsmlogger.IsSignatureFragmentPresent(sigfrag) {
		//fmt.Println("partial Signature duplicates.")
		return
	}
	if fsmlogger.IsSignaturePresent() || fsmlogger.GetSignatureListLength() >= m.Settings.Mal+1 {
		//fmt.Println("Threshold Signature already exists.")
		return
	}
	fsmlogger.AddSignatureFragment(sigfrag)
	fmt.Println("number of partial Signatures: ", fsmlogger.GetSignatureListLength())
	//fmt.Println("number of partial Signatures: ", fsmlogger.Signaturelist)
	if fsmlogger.GetSignatureListLength() == m.Settings.Mal+1 {
		sig := m.Aggregate(fsmlogger.Signaturelist)
		fsmlogger.SetField("Signature", sig)
		//fsmlogger.Signature = sig
		// Retrieve the start time
		startTime := fsmlogger.GetStartTime()
		// Calculate the elapsed time
		elapsedTime := time.Since(startTime)
		fsmlogger.SetField("Convergetime", elapsedTime)
		//fsmlogger.ConvergeTime = elapsedTime
		// Print or log the elapsed time
		fmt.Println("Time elapsed since start:", elapsedTime)
	}
	msd_json, err := json.Marshal(msd)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/default_transparency_partial_signature", msd_json)
}
