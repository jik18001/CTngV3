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
	rs "github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

func LSMWakeup(m *MonitorEEA, lsm *FSMLoggerEEA, c def.Context) {

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
		broadcastEEA(m, "/monitor/transparency_partial_signature", msd_json)
		fmt.Println("transparency_partial_signature broadcasted")
		/*
			case def.WAKE_TR:

				if content, ok := c.Content.(def.Notification); ok {
					monitorIndex, err := def.MapIDtoInt(def.CTngID(content.Monitor))
					if err != nil {
						log.Printf("Failed to map monitor ID to int: %v", err)
						return
					}
					fsmlogger := m.FSMLoggerEEAs[monitorIndex]
					// Retrieve the data fragment
					dataFragment, err := fsmlogger.GetDataFragment(monitorIndex)
					if err != nil {
						log.Printf("Failed to get data fragment for monitor index %d: %v", monitorIndex, err)
						return
					}

					// If the data fragment is empty, initiate a request to retrieve it
					if len(dataFragment) == 0 {
						log.Println("Data fragment is empty. Initiating requests to retrieve it.")
						notifications := fsmlogger.GetNotifications()
						new_note_fork := content
						new_note_fork.Sender = m.Self_ip_port
						new_note_json, err := json.Marshal(new_note_fork)
						if err != nil {
							log.Fatalf("Failed to marshal update: %v", err)
						}
						for _, notification := range notifications {
							url := "http://" + notification.Sender + "/monitor/transparency_request"

							// Assume new_note_json is defined and contains the correct JSON data
							response, err := m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
							if err != nil {
								log.Printf("Failed to send transparency request to %s: %v", notification.Sender, err)
								continue
							}

							// Close the response body immediately after processing it
							if response.Body != nil {
								response.Body.Close()
							}

							log.Printf("Transparency request successfully sent to %s", notification.Sender)
						}
					} else {
						log.Println("Data fragment already available. No need to initiate requests.")
					}
				} else {
					log.Println("Failed to assert c.Content to the expected type")
				}*/

	case def.WAKE_TU:
		// Placeholder for WAKE_TU event handling
		fmt.Println("WAKE_TU event triggered. Placeholder logic executed.")

	case def.WAKE_TV:
		// Placeholder for WAKE_TV event handling
		fmt.Println("WAKE_TV event triggered. Placeholder logic executed.")
	}
}

func process_logger_update_EEA(m *MonitorEEA, sth def.STH, update def.Update_Logger_EEA) {
	//All cases we check STH first
	//Signature Verification, remove the signature from the data structure, then serialize it to get the message, then verifiy it against the signature
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
	//fmt.Println("Signature Verification Passed")
	// proceed only if we pass the verification
	// retrieve existing STH
	index, _ := def.MapIDtoInt(def.CTngID(sth.LID))
	var fsmlogger *FSMLoggerEEA
	fsmlogger = m.FSMLoggerEEAs[index]
	sth2, _ := fsmlogger.GetField("STH")
	// if we already have an existing STH
	if !reflect.DeepEqual(sth2, def.STH{}) {
		// we compare the sth against the existing record and broadcast a cPoM when needed
		sthsigbytes, _ := json.Marshal(sth)
		sthsigbytes2, _ := json.Marshal(sth2)
		if !reflect.DeepEqual(sthsigbytes, sthsigbytes2) {
			cPoM := &def.CPoM{
				Entity_Convicted: def.CTngID(STH_fork.LID),
				MetaData1:        sth,
				MetaData2:        sth2,
			}
			cPoM_json, err := json.Marshal(cPoM)
			if err != nil {
				log.Fatalf("Failed to marshal update: %v", err)
			}
			broadcastEEA(m, "/monitor/PoM", cPoM_json)
			return
		}
	}
	//fmt.Println("Conflicts Verification Passed")
	//check duplicate
	update2, _ := fsmlogger.GetUpdate(update.MonitorID)
	if reflect.DeepEqual(update, update2) {
		return
	}
	//validate data fragment
	//--------------------------------------need to switch to another libaray because the parallel procoessing does not work ----------------------------------------------------

	//m.Hashlock.Lock()
	ok, _ := def.VerifyPOI2(update.Head_rs, update.PoI.Proof, update.FileShare)
	//m.Hashlock.Unlock()
	if !ok {
		fmt.Println("Data Fragment Verification Failed")
		return
	}
	//fmt.Println("PoI Verification Passed")
	// Store the Update
	fmt.Println(update.MonitorID)
	fsmlogger.StoreUpdate(update.MonitorID, update)
	monitorindex, _ := def.MapIDtoInt(def.CTngID(update.MonitorID))
	frag, _ := fsmlogger.GetDataFragment(monitorindex)
	if reflect.DeepEqual(frag, update.FileShare) {
		return
	}
	fsmlogger.AddDataFragment(monitorindex, update.FileShare)
	counter := fsmlogger.GetDataFragmentCounter()
	if counter == m.Settings.Num_Monitors-m.Settings.Mal {

		dec, err := rs.New(counter, m.Settings.Mal)
		if err != nil {
			log.Fatalf("Error initializing Reed-Solomon decoder: %v", err)
		}
		fileShares := fsmlogger.GetDataFragments()
		err = dec.Reconstruct(fileShares)
		if err != nil {
			log.Fatalf("Error during Reed-Solomon decoding: %v", err)
		}
		fmt.Println(len(fileShares[0]))
		fmt.Println(len(fileShares[1]))
		fmt.Println(len(fileShares[2]))
		fmt.Println(len(fileShares[3]))
		//fmt.Println(fileShares[0])
		//fmt.Println(fileShares[1])
		//fmt.Println(fileShares[2])
		//fmt.Println(fileShares[3])
		var dataBlocks []merkletree.DataBlock
		for i := range fileShares[:(counter)] {
			for j := 0; j < len(fileShares[i]); j += m.Settings.Certificate_size {
				end := j + m.Settings.Certificate_size
				if end > len(fileShares[i]) {
					end = len(fileShares[i])
				}
				dataBlocks = append(dataBlocks, &def.LeafBlock{Content: fileShares[i][j:end]})
			}
		}
		// Generate Merkle Tree
		tree, err := def.GenerateMerkleTree(dataBlocks)
		def.HandleError(err, "MT Generation")
		rootHash := def.GenerateRootHash(tree)
		isRootHashValid := reflect.DeepEqual(rootHash, update.Head_cert)
		//fmt.Println(rootHash)
		//fmt.Println(update.Head_cert)
		//fmt.Println("RootHash comparison result:", isRootHashValid)
		if isRootHashValid {
			fsmlogger.SetField("DataCheck", true)
		}
		//value, _ := fsmlogger.GetField("DataCheck")
		//dataCheckValue, _ := value.(bool)
		//fmt.Println(dataCheckValue)
	}
	//fmt.Println(len(fsmlogger.DataFragments[0]))
	//fmt.Println(len(fsmlogger.DataFragments[1]))
	//fmt.Println(len(fsmlogger.DataFragments[2]))
	//fmt.Println(len(fsmlogger.DataFragments[3]))
	// now create a notification
	new_note := def.Notification{
		Type:       def.TUEEA,
		Originator: def.CTngID(update.STH.LID),
		Monitor:    update.MonitorID,
		Sender:     m.Self_ip_port,
	}
	//fmt.Println(new_note)
	new_note_json, err := json.Marshal(new_note)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/transparency_notification", new_note_json)
	//fmt.Printf("Notification broadcasted with logger %s and og monitor %s\n", update.STH.LID, update.MonitorID)
	//if this is the first STH
	if reflect.DeepEqual(sth2, def.STH{}) {
		//fmt.Println(sth2)
		//fmt.Println(sth)
		fsmlogger.SetField("STH", sth)
		fsmlogger.SetField("State", def.PRECOMMIT)
		fmt.Println("Transitioned to: ", fsmlogger.State)
		sth_json, err := json.Marshal(sth)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		broadcastEEA(m, "/monitor/STH", sth_json)
		NewContext := def.Context{
			Label: def.WAKE_TM,
		}
		time.AfterFunc(time.Duration(m.Settings.Mature_Wait_time+m.Settings.Verification_Wait_time)*time.Second, func() {

			value, _ := fsmlogger.GetField("DataCheck")
			dataCheckValue, _ := value.(bool)
			//fmt.Println(dataCheckValue)
			if dataCheckValue {
				LSMWakeup(m, fsmlogger, NewContext)
			} else {
				fmt.Println("Place holder for accusation.")
			}
		})
		return
	}

}

func logger_sth_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var sth def.STH

	// Create a counter to track the number of bytes read
	var byteCounter int64

	// Create a TeeReader to count bytes while reading from r.Body
	counterReader := io.TeeReader(r.Body, &countWriter{count: &byteCounter})

	// Decode the STH from the request body
	if err := json.NewDecoder(counterReader).Decode(&sth); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}

	// Retrieve the FSMLogger corresponding to the STH LID
	//index, _ := def.MapIDtoInt(def.CTngID(sth.LID))
	//fsmlogger := m.FSMLoggerEEAs[index]

	// Retrieve the current traffic count and ensure type assertion
	// trafficcountInterface, _ := fsmlogger.GetField("TrafficCount")
	// trafficcount := trafficcountInterface.(int) // Assert as int

	// Update the traffic count by adding the size of the request body
	// newcount := trafficcount + int(byteCounter)
	// fsmlogger.SetField("TrafficCount", newcount)

	// Process the logger update
	process_logger_update_EEA(m, sth, def.Update_Logger_EEA{})
}

// this function handles the update (Erasure Encoding Version) from the logger
/*func logger_update_EEA_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	//parse the update
	var update def.Update_Logger_EEA
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	//fmt.Println(update.STH)
	//if no conflicts
	//fmt.Println("Update received")
	process_logger_update_EEA(m, update.STH, update)

}*/

func logger_update_EEA_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	// Create a counter to track the number of bytes read
	var byteCounter int64

	// Create a TeeReader to count bytes while reading from r.Body
	counterReader := io.TeeReader(r.Body, &countWriter{count: &byteCounter})

	// Parse the update
	var update def.Update_Logger_EEA
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
	updatecountInterface, _ := fsmlogger.GetField("UpdateCount")
	updatecount := updatecountInterface.(int) // Assert as int
	// Update the traffic count by adding the size of the request body
	newucount := updatecount + 1
	fsmlogger.SetField("UpdateCount", newucount)

	// Process the logger update
	process_logger_update_EEA(m, update.STH, update)
}

func transparency_request_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var new_note def.Notification
	if err := json.NewDecoder(r.Body).Decode(&new_note); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	loggerindex, _ := def.MapIDtoInt(new_note.Originator)
	//fmt.Println(new_note.Originator, loggerindex)
	fsmlogger := m.FSMLoggerEEAs[loggerindex]
	//fmt.Println(fsmlogger.State)

	update, err := fsmlogger.GetUpdate(def.CTngID(new_note.Monitor))
	if err != nil {
		return
	}
	//fmt.Println(update.MonitorID)
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
func transparency_notification_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
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
		existing_update, _ := fsmlogger.GetUpdate(new_note.Monitor)
		//return if we already have the update
		if !reflect.DeepEqual(existing_update, def.Update_Logger_EEA{}) {
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
				//fmt.Println("Failed to send update: ", err)
			}
			NewContext := def.Context{
				Label:   def.WAKE_TR,
				Content: new_note,
			}
			time.AfterFunc(time.Duration(m.Settings.Update_Wait_time)*time.Second, func() {
				LSMWakeup(m, fsmlogger, NewContext)
				/*
					monitorindex, _ := def.MapIDtoInt(def.CTngID(new_note.Monitor))
					_, err := fsmlogger.GetDataFragment(monitorindex)
					if err == nil {
						notifications := fsmlogger.GetNotifications()
						for _, notification := range notifications {
							url := "http://" + notification.Sender + "/monitor/transparency_request"
							_, err := m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
							if err != nil {
								//fmt.Println("Failed to send update: ", err)
							}
						}
					}
				*/
			})
		}
		fsmlogger.AddNotification(new_note)
	}

}

func transparency_partial_signature_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	fmt.Println("MSD received")
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
	fmt.Println("TBV: ", sth_fork)
	sigfrag, _ := def.SigFragmentFromString(msd.Signature)
	err = m.FragmentVerify(string(sthBytes), sigfrag)
	if err != nil {
		fmt.Println("partial Signature verification failed: ", err)
		return
	}

	if fsmlogger.IsSignatureFragmentPresent(sigfrag) {
		fmt.Println("partial Signature duplicates.")
		return
	}
	if fsmlogger.IsSignaturePresent() || fsmlogger.GetSignatureListLength() >= m.Settings.Mal+1 {
		fmt.Println("Threshold Signature already exists.")
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
	broadcastEEA(m, "/monitor/transparency_partial_signature", msd_json)
}
