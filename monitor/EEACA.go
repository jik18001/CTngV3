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
		//fmt.Println("TBS: ", srh_fork)
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
	}
}

func process_ca_update_EEA(m *MonitorEEA, srh def.SRH, update def.Update_CA_EEA) {
	// Work with a fork of SRH
	SRH_fork := srh
	SRH_fork.Signature = def.RSASig{}
	srhBytes, err := json.Marshal(SRH_fork)
	if err != nil {
		log.Fatalf("Failed to serialize SRH: %v", err)
	}
	//fmt.Println(SRH_fork, srh.Signature)
	err = m.Crypto.Verify(srhBytes, srh.Signature)
	if err != nil {
		fmt.Println("Signature Verification Failed")
		return
	}

	// Retrieve FSMCAEEA
	index, _ := def.MapIDtoInt(def.CTngID(srh.CAID))
	fsmca := m.FSMCAEEAs[index]
	srh2, _ := fsmca.GetField("SRH")

	// If we already have an existing SRH, compare with the incoming one
	if !reflect.DeepEqual(srh2, def.SRH{}) {
		srhsigbytes, _ := json.Marshal(srh)
		srhsigbytes2, _ := json.Marshal(srh2)
		if !reflect.DeepEqual(srhsigbytes, srhsigbytes2) {
			cPoM := &def.CPoM{
				Entity_Convicted: def.CTngID(SRH_fork.CAID),
				MetaData1:        srh,
				MetaData2:        srh2,
			}
			cPoM_json, err := json.Marshal(cPoM)
			if err != nil {
				log.Fatalf("Failed to marshal update: %v", err)
			}
			broadcastEEA(m, "/monitor/PoM", cPoM_json)
			return
		}
	}

	// Check for duplicates
	update2, _ := fsmca.GetUpdate(update.MonitorID)
	if reflect.DeepEqual(update, update2) {
		return
	}

	// Validate the data fragment
	ok, _ := def.VerifyPOI2(update.Head_rs, update.PoI.Proof, update.FileShare)
	if !ok {
		fmt.Println("Data Fragment Verification Failed")
		return
	}

	// Store the Update
	fsmca.StoreUpdate(update.MonitorID, update)
	monitorindex, _ := def.MapIDtoInt(def.CTngID(update.MonitorID))
	frag, _ := fsmca.GetDataFragment(monitorindex)
	if reflect.DeepEqual(frag, update.FileShare) {
		return
	}
	fsmca.AddDataFragment(monitorindex, update.FileShare)
	counter := fsmca.GetDataFragmentCounter()
	fmt.Println(counter)
	if counter == m.Settings.Num_Monitors-m.Settings.Mal {
		dec, err := rs.New(counter, m.Settings.Mal)
		if err != nil {
			log.Fatalf("Error initializing Reed-Solomon decoder: %v", err)
		}
		fileShares := fsmca.GetDataFragments()
		err = dec.Reconstruct(fileShares)
		if err != nil {
			log.Fatalf("Error during Reed-Solomon decoding: %v", err)
		}
		fsmca.SetField("DataCheck", true)
	}

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
		fmt.Println("Transitioned to: ", fsmca.State)
		srh_json, err := json.Marshal(srh)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		broadcastEEA(m, "/monitor/SRH", srh_json)
		NewContext := def.Context{
			Label: def.WAKE_TM,
		}
		time.AfterFunc(time.Duration(m.Settings.Mature_Wait_time+m.Settings.Verification_Wait_time)*time.Second, func() {

			value, _ := fsmca.GetField("DataCheck")
			dataCheckValue, _ := value.(bool)
			if dataCheckValue {
				CSMWakeup(m, fsmca, NewContext)
			} else {
				fmt.Println("Place holder for accusation.")
			}
		})
		return
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
	fmt.Println("Notification received, originally assigned to: ", new_note.Monitor)
	new_note_fork := new_note
	new_note_fork.Sender = m.Self_ip_port

	caindex, _ := def.MapIDtoInt(new_note.Originator)
	fsmca := m.FSMCAEEAs[caindex]
	if m.Settings.Broadcasting_Mode == def.MIN_WT {
		existing_update, _ := fsmca.GetUpdate(new_note.Monitor)
		if !reflect.DeepEqual(existing_update, def.Update_CA_EEA{}) {
			return
		}
		url := "http://" + new_note.Sender + "/monitor/revocation_request"
		new_note_json, err := json.Marshal(new_note_fork)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		_, err = m.Client.Post(url, "application/json", bytes.NewBuffer(new_note_json))
		if err != nil {
			fmt.Println("Failed to send update: ", err)
		}
	}
	if m.Settings.Broadcasting_Mode == def.MIN_BC {
		if fsmca.GetFirstNotification() == nil {
			url := "http://" + new_note.Sender + "/monitor/revocation_request"
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
			time.AfterFunc(time.Duration(m.Settings.Update_Wait_time)*time.Second, func() {
				CSMWakeup(m, fsmca, NewContext)
			})
		}
		fsmca.AddNotification(new_note)
	}
}

func revocation_partial_signature_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {
	fmt.Println("MSD received")
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
	fmt.Println("TBV: ", srh_fork)
	sigfrag, _ := def.SigFragmentFromString(msd.Signature)
	err = m.FragmentVerify(string(srhBytes), sigfrag)
	if err != nil {
		fmt.Println("partial Signature verification failed: ", err)
		return
	}

	if fsmca.IsSignatureFragmentPresent(sigfrag) {
		fmt.Println("partial Signature duplicates.")
		return
	}
	if fsmca.IsSignaturePresent() || fsmca.GetSignatureListLength() >= m.Settings.Mal+1 {
		fmt.Println("Threshold Signature already exists.")
		return
	}
	fsmca.AddSignatureFragment(sigfrag)
	fmt.Println("number of partial Signatures: ", fsmca.GetSignatureListLength())
	if fsmca.GetSignatureListLength() == m.Settings.Mal+1 {
		sig := m.Aggregate(fsmca.Signaturelist)
		//fsmca.Signature = sig
		fsmca.SetField("Signature", sig)
		startTime := fsmca.GetStartTime()
		elapsedTime := time.Since(startTime)
		fsmca.ConvergeTime = elapsedTime
		fmt.Println("Time elapsed since start:", elapsedTime)
	}
	msd_json, err := json.Marshal(msd)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}
	broadcastEEA(m, "/monitor/revocation_partial_signature", msd_json)
}
