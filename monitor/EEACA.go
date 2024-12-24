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
)

func CSMWakeup(m *MonitorEEA, fsmca *FSMCAEEA, c def.Context) {
	switch c.Label {
	case def.WAKE_TC:
		fmt.Println("WAKE_TC event triggered. Placeholder logic executed.")

	case def.WAKE_TM:
		fmt.Println("WAKE_TM event triggered.")
		if !reflect.DeepEqual(fsmca.APoM, def.APoM{}) || !reflect.DeepEqual(fsmca.CPoM, def.CPoM{}) {
			fmt.Println("PoM present")
			return
		}
		srh_fork := fsmca.SRH
		srh_fork.Signature = def.RSASig{}
		srhBytes, err := json.Marshal(srh_fork)
		if err != nil {
			log.Fatalf("Failed to serialize SRH: %v", err)
		}
		sigfrag := m.ThresholdSign(string(srhBytes))
		sigstring := sigfrag.String()
		monitor_signed_data := MonitorSignedData{
			Type:      "SRH",
			CTngID:    def.CTngID(srh_fork.CAID),
			Signature: sigstring,
		}
		msd_json, err := json.Marshal(monitor_signed_data)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		broadcastEEA(m, "/monitor/revocation_partial_signature", msd_json)
		fmt.Println("revocation_partial_signature broadcasted")

	case def.WAKE_TU:
		fmt.Println("WAKE_TU event triggered. Placeholder logic executed.")

	case def.WAKE_TV:
		fmt.Println("WAKE_TV event triggered. Placeholder logic executed.")

	case def.WAKE_TR:
		fmt.Println("WAKE_TR event triggered.")
		// Attempt to retrieve missing data fragments as done in logger code
		if content, ok := c.Content.(def.Notification); ok {
			// Map Originator (CA ID) to index
			caindex, err := def.MapIDtoInt(content.Originator)
			if err != nil {
				log.Printf("Failed to map Originator ID to int: %v", err)
				return
			}
			fsmca := m.FSMCAEEAs[caindex]

			// Determine the data fragment index from the Monitor ID
			dataFragmentIndex, err := def.MapIDtoInt(def.CTngID(content.Monitor))
			if err != nil {
				log.Printf("Failed to map Monitor ID to int: %v", err)
				return
			}

			// Retrieve the data fragment
			dataFragment, err := fsmca.GetDataFragment(dataFragmentIndex)
			if err != nil {
				log.Printf("Failed to get data fragment for index %d: %v", dataFragmentIndex, err)
				return
			}

			// If the data fragment is empty, attempt to re-fetch it
			if len(dataFragment) == 0 {
				log.Println("Data fragment is empty. Initiating requests to retrieve it.")

				new_note_fork := content
				new_note_fork.Sender = m.Self_ip_port
				new_note_json, err := json.Marshal(new_note_fork)
				if err != nil {
					log.Fatalf("Failed to marshal notification: %v", err)
				}

				// Since we don't have fragment-specific notifications or Bmodes,
				// we will try contacting all known notification senders.
				notifications := fsmca.GetNotifications()
				for _, notification := range notifications {
					url := "http://" + notification.Sender + "/monitor/revocation_request"
					response, err := m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
					if err != nil {
						log.Printf("Failed to send revocation request to %s: %v", notification.Sender, err)
						continue
					}
					if response.Body != nil {
						response.Body.Close()
					}
				}
			} else {
				// Data fragment already available, no action needed
			}
		} else {
			log.Println("Failed to assert c.Content to type def.Notification")
		}
	}
}

func process_ca_update_EEA(m *MonitorEEA, srh def.SRH, update def.Update_CA_EEA) {
	SRH_fork := srh
	SRH_fork.Signature = def.RSASig{}
	srhBytes, err := json.Marshal(SRH_fork)
	if err != nil {
		log.Fatalf("Failed to serialize SRH: %v", err)
	}

	err = m.Crypto.Verify(srhBytes, srh.Signature)
	if err != nil {
		fmt.Println("Signature Verification Failed")
		return
	}

	index, _ := def.MapIDtoInt(def.CTngID(srh.CAID))
	fsmca := m.FSMCAEEAs[index]
	srh2, _ := fsmca.GetField("SRH")

	// Check for conflicting SRH (PoM)
	if !reflect.DeepEqual(srh2, def.SRH{}) {
		srhsigbytes, _ := json.Marshal(srh)
		srhsigbytes2, _ := json.Marshal(srh2)
		if !reflect.DeepEqual(srhsigbytes, srhsigbytes2) {
			cPoM := &def.CPoM{
				Entity_Convicted: def.CTngID(SRH_fork.CAID),
				MetaData1:        srh,
				MetaData2:        srh2,
			}

			// Attempt to add the CPoM to the FSMCAEEA instance
			err := fsmca.AddCPoM(*cPoM)
			// If this is the first CPoM, change the state and broadcast a minimal update
			if err == nil {
				fsmca.SetField("State", def.POM)
				fmt.Println("Switched to PoM State")

				// Create a minimal CA update with just the SRH and no file shares
				SRH_only_update := def.Update_CA_EEA{
					SRH:       srh,
					FileShare: []byte{},
					Head_rs:   []byte{},
					PoI:       def.PoI{},
				}
				srh_json, err := json.Marshal(SRH_only_update)
				if err != nil {
					log.Fatalf("Failed to marshal update: %v", err)
				}

				// Broadcast the minimal CA update to inform all monitors
				broadcastEEA(m, "/monitor/ca_update_EEA", srh_json)
			}
			return
		}
	}

	// Check for duplicate update
	update2, _ := fsmca.GetUpdate(update.MonitorID)
	if reflect.DeepEqual(update, update2) {
		return
	}

	// Verify PoI for the fragment
	ok, _ := def.VerifyPOI2(update.Head_rs, update.PoI.Proof, update.FileShare)
	if !ok {
		fmt.Println("Data Fragment Verification Failed")
		return
	}

	// Store the update and add the data fragment
	fsmca.StoreUpdate(update.MonitorID, update)
	monitorindex, _ := def.MapIDtoInt(def.CTngID(update.MonitorID))
	frag, _ := fsmca.GetDataFragment(monitorindex)
	if reflect.DeepEqual(frag, update.FileShare) {
		return
	}
	fsmca.AddDataFragment(monitorindex, update.FileShare)

	// Check if we have enough fragments to reconstruct
	counter := fsmca.GetDataFragmentCounter()
	fmt.Println("Number of data fragments collected:", counter)
	required := m.Settings.Num_Monitors - m.Settings.Mal
	if counter == required {
		dec, err := rs.New(required, m.Settings.Mal)
		if err != nil {
			log.Fatalf("Error initializing Reed-Solomon decoder: %v", err)
		}
		fileShares := fsmca.GetDataFragments()

		// Reconstruct the data
		err = dec.Reconstruct(fileShares)
		if err != nil {
			log.Fatalf("Error during Reed-Solomon decoding: %v", err)
		}

		// Concatenate the first 'required' shards to get the compressed DCRV (just like the CA used dcrv)
		concatenatedData := []byte{}
		for _, shard := range fileShares[:required] {
			concatenatedData = append(concatenatedData, shard...)
		}

		// After reconstructing and concatenating the shards:
		concatenatedData = concatenatedData[:update.OriginalLen]

		// Compute hcrv and hdcrv as CA did by hashing the exact original dcrv
		hcrv, _ := def.GenerateSHA256(concatenatedData)
		hdcrv, _ := def.GenerateSHA256(concatenatedData)

		// Recreate SRH.Head as the CA did: hcrv || hdcrv || update.Head_rs
		recreatedHead := append(hcrv, hdcrv...)
		recreatedHead = append(recreatedHead, update.Head_rs...)

		// Compare recreatedHead with srh.Head from the CA
		if !reflect.DeepEqual(recreatedHead, srh.Head) {
			fmt.Println("SRH.Head mismatch! Data verification failed.")
		} else {
			// If verification passes
			fsmca.SetField("DataCheck", true)
			fmt.Println("Data reconstruction and verification succeeded. DataCheck set to true.")
		}

	}

	// Send a notification after handling the update
	new_note := def.Notification{
		Type:       def.TUEEA,
		Originator: def.CTngID(update.SRH.CAID),
		Monitor:    update.MonitorID,
		Sender:     m.Self_ip_port,
	}
	new_note_json, err := json.Marshal(new_note)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/revocation_notification", new_note_json)

	// If this is the first SRH
	if reflect.DeepEqual(srh2, def.SRH{}) {
		fsmca.SetField("SRH", srh)
		fsmca.SetField("State", def.PRECOMMIT)
		fmt.Println("Transitioned to:", fsmca.State)
		srh_json, err := json.Marshal(srh)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		broadcastEEA(m, "/monitor/SRH", srh_json)

		NewContext := def.Context{
			Label: def.WAKE_TM,
		}
		go func() {
			time.AfterFunc(time.Duration(m.Settings.Mature_Wait_time+m.Settings.Verification_Wait_time)*time.Second, func() {
				value, _ := fsmca.GetField("DataCheck")
				dataCheckValue, _ := value.(bool)
				if dataCheckValue {
					CSMWakeup(m, fsmca, NewContext)
				} else {
					fmt.Println("Place holder for accusation.")
				}
			})
		}()
	}
}

func ca_srh_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var srh def.SRH
	var byteCounter int64
	counterReader := io.TeeReader(r.Body, &countWriter{count: &byteCounter})

	if err := json.NewDecoder(counterReader).Decode(&srh); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}

	process_ca_update_EEA(m, srh, def.Update_CA_EEA{})
}

func ca_update_EEA_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var byteCounter int64
	counterReader := io.TeeReader(r.Body, &countWriter{count: &byteCounter})

	var update def.Update_CA_EEA
	if err := json.NewDecoder(counterReader).Decode(&update); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}

	index, _ := def.MapIDtoInt(def.CTngID(update.SRH.CAID))
	fsmca := m.FSMCAEEAs[index]
	// Print the Logger ID (LID) and Monitor ID (MID)
	fmt.Printf("Processing update from CA ID (CAID): %s, Monitor ID (MID): %s\n", update.SRH.CAID, update.MonitorID)
	trafficcountInterface, _ := fsmca.GetField("TrafficCount")
	trafficcount := trafficcountInterface.(int)

	newcount := trafficcount + int(byteCounter)
	fsmca.SetField("TrafficCount", newcount)

	updatecountInterface, _ := fsmca.GetField("UpdateCount")
	updatecount := updatecountInterface.(int)
	newucount := updatecount + 1
	fsmca.SetField("UpdateCount", newucount)
	fmt.Println("Update received, originally assigned to: ", update.MonitorID)
	process_ca_update_EEA(m, update.SRH, update)
}

func revocation_request_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	fmt.Println("request received")
	var new_note def.Notification
	if err := json.NewDecoder(r.Body).Decode(&new_note); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	caindex, _ := def.MapIDtoInt(new_note.Originator)
	fsmca := m.FSMCAEEAs[caindex]

	update, err := fsmca.GetUpdate(def.CTngID(new_note.Monitor))
	if err != nil {
		fmt.Println("Failed to fetch update.", err)
		return
	}
	update_json, err := json.Marshal(update)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	url := "http://" + new_note.Sender + "/monitor/ca_update_EEA"
	_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(update_json))
	if err != nil {
		fmt.Println("Failed to send update: ", err)
	}
}

func revocation_notification_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	var new_note def.Notification
	if err := json.NewDecoder(r.Body).Decode(&new_note); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	fmt.Println("Notification received, originally assigned to: ", new_note.Monitor, " with CAID = ", new_note.Originator)

	// Create a copy of the notification to modify the Sender
	new_note_fork := new_note
	new_note_fork.Sender = m.Self_ip_port

	// Map Originator ID (CA ID) to CA index
	caindex, err := def.MapIDtoInt(new_note.Originator)
	if err != nil {
		http.Error(w, "Failed to map Originator ID to CA index", http.StatusBadRequest)
		return
	}

	// Retrieve the corresponding FSMCAEEA
	fsmca := m.FSMCAEEAs[caindex]

	// Map Monitor ID to data fragment index
	dataFragmentIndex, err := def.MapIDtoInt(new_note.Monitor)

	if err != nil {
		http.Error(w, "Failed to map Monitor ID to data fragment index", http.StatusBadRequest)
		return
	}

	// Retrieve the Bmode for this fragment
	bmode, err := fsmca.GetBmodeForFragment(dataFragmentIndex)
	if err != nil {
		// If no Bmode for this fragment, handle gracefully or set a default
		fmt.Println("Failed to get Bmode for fragment:", err)
		return
	}
	// Check if we already have the update
	existing_update, _ := fsmca.GetUpdate(new_note.Monitor)
	if !reflect.DeepEqual(existing_update, def.Update_CA_EEA{}) {
		// We already have this update, so no need to request it again
		//fmt.Println("dup update")
		return
	}

	// Logic depends on the current broadcasting mode
	if bmode == def.MIN_WT {
		// If Bmode is MIN_WT, we send a revocation request immediately
		url := "http://" + new_note.Sender + "/monitor/revocation_request"
		new_note_json, err := json.Marshal(new_note_fork)
		if err != nil {
			log.Fatalf("Failed to marshal notification: %v", err)
		}

		_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
		if err != nil {
			fmt.Println("Failed to send revocation request:", err)
		}
	}
	fmt.Println("CA index mapped from CAID =", caindex, "datafragmentindex mapped from MID = ", dataFragmentIndex, "with Bmode: ", bmode)
	if bmode == def.MIN_BC {
		// Check if there's already a first notification for this fragment
		firstNotification, err := fsmca.GetFirstNotificationForFragment(dataFragmentIndex)
		if err != nil {
			log.Fatalf("Failed to get first notification: %v", err)
		}
		fmt.Println("CA index mapped from CAID =", caindex, "datafragmentindex mapped from MID = ", dataFragmentIndex, "with Bmode: ", bmode)
		if firstNotification == nil {
			// If no first notification, send a revocation request and schedule WAKE_TR
			fmt.Println("request sent, TR started")
			url := "http://" + new_note.Sender + "/monitor/revocation_request"
			new_note_json, err := json.Marshal(new_note_fork)
			if err != nil {
				log.Fatalf("Failed to marshal notification: %v", err)
			}

			_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
			if err != nil {
				fmt.Println("Failed to send revocation request:", err)
			}

			// Schedule a WAKE_TR event after Update_Wait_time
			NewContext := def.Context{
				Label:   def.WAKE_TR,
				Content: new_note,
			}
			time.AfterFunc(time.Duration(m.Settings.Update_Wait_time)*time.Second, func() {
				CSMWakeup(m, fsmca, NewContext)
			})
		}

		// Add this notification to the fragment-specific notifications
		err = fsmca.AddNotificationToFragment(dataFragmentIndex, new_note)
		if err != nil {
			log.Fatalf("Failed to add notification to fragment: %v", err)
		}
	}
}

func revocation_partial_signature_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	//fmt.Println("MSD received")
	var msd MonitorSignedData
	if err := json.NewDecoder(r.Body).Decode(&msd); err != nil {
		http.Error(w, "Failed to decode update", http.StatusBadRequest)
		return
	}
	index, _ := def.MapIDtoInt(def.CTngID(msd.CTngID))
	fsmca := m.FSMCAEEAs[index]

	srh, err := fsmca.GetField("SRH")
	if err != nil {
		fmt.Println("Error retrieving SRH field:", err)
		return
	}
	srh_fork, ok := srh.(def.SRH)
	if !ok {
		fmt.Println("srh_fork is not of type SRH")
		return
	}
	srh_fork.Signature = def.RSASig{}
	srhBytes, err := json.Marshal(srh_fork)
	if err != nil {
		log.Fatalf("Failed to serialize SRH: %v", err)
	}
	sigfrag, _ := def.SigFragmentFromString(msd.Signature)
	err = m.FragmentVerify(string(srhBytes), sigfrag)
	if err != nil {
		fmt.Println("partial Signature verification failed: ", err)
		return
	}

	if fsmca.IsSignatureFragmentPresent(sigfrag) {
		return
	}
	if fsmca.IsSignaturePresent() || fsmca.GetSignatureListLength() >= m.Settings.Mal+1 {
		return
	}
	fsmca.AddSignatureFragment(sigfrag)
	fmt.Println("number of partial Signatures: ", fsmca.GetSignatureListLength())
	if fsmca.GetSignatureListLength() == m.Settings.Mal+1 {
		sig := m.Aggregate(fsmca.Signaturelist)
		fsmca.SetField("Signature", sig)

		startTime := fsmca.GetStartTime()
		elapsedTime := time.Since(startTime)
		// Use SetField for concurrency safety
		fsmca.SetField("Convergetime", elapsedTime)

		fmt.Println("Time elapsed since start:", elapsedTime)
	}
	msd_json, err := json.Marshal(msd)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/revocation_partial_signature", msd_json)
}
