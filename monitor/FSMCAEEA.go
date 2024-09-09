package monitor

import (
	"errors"
	"reflect"
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type FSMCAEEA struct {
	CTngID               def.CTngID                       // CTngID
	State                string                           // Current state
	lock                 sync.RWMutex                     // Concurrency control
	Period               int                              // Current period of operation
	SRH                  def.SRH                          // Valid SRH received for the period
	Updates              map[def.CTngID]def.Update_CA_EEA // All the updates for this CA, indexed by Monitor ID
	Notifications        []def.Notification               // Notifications cache for data collection
	DataFragments        [][]byte                         // The certificate shares in this case
	DataFragment_Counter int                              // Count of Data Fragments
	DataCheck            bool                             // Compare against the head_cert
	Signaturelist        []def.SigFragment                // Precommit and Post Commit State, sign over the SRH
	Signature            def.ThresholdSig                 // Done state (Serialized signature)
	APoM                 def.APoM                         // APoM record against this CA, if any
	CPoM                 def.CPoM                         // CPoM record against this CA, if any
	TrafficCount         int                              // Count of traffic
	UpdateCount          int                              // Count of update received
	StartTime            time.Time                        // Time when the FSMCAEEA was started
	ConvergeTime         time.Duration                    // Time it takes to generate Threshold Signature
}

// Method to retrieve the start time
func (ca *FSMCAEEA) GetStartTime() time.Time {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.StartTime
}

// General method to set a field of the FSMCAEEA
func (ca *FSMCAEEA) SetField(field string, value interface{}) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	switch field {
	case "SRH":
		if v, ok := value.(def.SRH); ok {
			ca.SRH = v
		} else {
			return errors.New("invalid type for SRH")
		}
	case "State":
		if v, ok := value.(string); ok {
			ca.State = v
		} else {
			return errors.New("invalid type for State")
		}
	case "Signature":
		if v, ok := value.(def.ThresholdSig); ok {
			ca.Signature = v
		} else {
			return errors.New("invalid type for Signature")
		}
	case "CPoM":
		if v, ok := value.(def.CPoM); ok {
			ca.CPoM = v
		} else {
			return errors.New("invalid type for CPoM")
		}
	case "APoM":
		if v, ok := value.(def.APoM); ok {
			ca.APoM = v
		} else {
			return errors.New("invalid type for APoM")
		}
	case "TrafficCount":
		if v, ok := value.(int); ok {
			ca.TrafficCount = v
		} else {
			return errors.New("invalid type for TrafficCount")
		}
	case "UpdateCount":
		if v, ok := value.(int); ok {
			ca.UpdateCount = v
		} else {
			return errors.New("invalid type for UpdateCount")
		}
	case "DataCheck":
		if v, ok := value.(bool); ok {
			ca.DataCheck = v
		} else {
			return errors.New("invalid type for DataCheck")
		}
	default:
		return errors.New("unknown field")
	}
	return nil
}

// General method to get a field of the FSMCAEEA
func (ca *FSMCAEEA) GetField(field string) (interface{}, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	switch field {
	case "SRH":
		return ca.SRH, nil
	case "State":
		return ca.State, nil
	case "Signature":
		return ca.Signature, nil
	case "CPoM":
		return ca.CPoM, nil
	case "APoM":
		return ca.APoM, nil
	case "DataCheck":
		return ca.DataCheck, nil
	case "TrafficCount":
		return ca.TrafficCount, nil
	case "UpdateCount":
		return ca.UpdateCount, nil
	default:
		return nil, errors.New("unknown field")
	}
}

// Method to retrieve the current value of DataFragment_Counter
func (ca *FSMCAEEA) GetDataFragmentCounter() int {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.DataFragment_Counter
}

// Method to add a data fragment to the FSMCAEEA
func (ca *FSMCAEEA) AddDataFragment(index int, dataFragment []byte) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	// Check if index is within the valid range
	if index < 0 || index >= len(ca.DataFragments) {
		return errors.New("index out of range")
	}

	// Only increment the counter if the fragment is non-empty and hasn't been set before
	if len(dataFragment) > 0 && len(ca.DataFragments[index]) == 0 {
		ca.DataFragment_Counter++
	}

	// Set the data fragment at the specified index
	ca.DataFragments[index] = dataFragment
	return nil
}

// Method to get a data fragment from the FSMCAEEA
func (ca *FSMCAEEA) GetDataFragment(index int) ([]byte, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	if index < 0 || index >= len(ca.DataFragments) {
		return nil, errors.New("index out of range")
	}
	return ca.DataFragments[index], nil
}

// Method to retrieve all data fragments from the FSMCAEEA
func (ca *FSMCAEEA) GetDataFragments() [][]byte {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	dataFragmentsCopy := make([][]byte, len(ca.DataFragments))
	copy(dataFragmentsCopy, ca.DataFragments)
	return dataFragmentsCopy
}

// Method to store an update for the FSMCAEEA
func (ca *FSMCAEEA) StoreUpdate(monitorID def.CTngID, update def.Update_CA_EEA) {
	ca.lock.Lock()
	defer ca.lock.Unlock()
	ca.Updates[monitorID] = update
}

// Method to get an update from the FSMCAEEA
func (ca *FSMCAEEA) GetUpdate(monitorID def.CTngID) (def.Update_CA_EEA, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	update, exists := ca.Updates[monitorID]
	if !exists {
		return def.Update_CA_EEA{}, errors.New("update not found")
	}
	return update, nil
}

func (ca *FSMCAEEA) AddNotification(notification def.Notification) {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	for _, existingNotification := range ca.Notifications {
		if existingNotification == notification {
			return // Duplicate found, do not add
		}
	}

	ca.Notifications = append(ca.Notifications, notification)
}

// Method to retrieve all notifications from the FSMCAEEA
func (ca *FSMCAEEA) GetNotifications() []def.Notification {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	// Return a copy of the notifications to avoid data race issues
	notificationsCopy := make([]def.Notification, len(ca.Notifications))
	copy(notificationsCopy, ca.Notifications)
	return notificationsCopy
}

// Method to retrieve the first notification from the FSMCAEEA
func (ca *FSMCAEEA) GetFirstNotification() *def.Notification {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if len(ca.Notifications) == 0 {
		return nil
	}
	return &ca.Notifications[0]
}

// Method to add a signature fragment to the Signaturelist
func (ca *FSMCAEEA) AddSignatureFragment(signatureFragment def.SigFragment) {
	ca.lock.Lock()
	defer ca.lock.Unlock()
	for _, existingFragment := range ca.Signaturelist {
		if reflect.DeepEqual(existingFragment, signatureFragment) {
			return
		}
	}
	ca.Signaturelist = append(ca.Signaturelist, signatureFragment)
}

// Method to check if a signature fragment is already present in the Signaturelist
func (ca *FSMCAEEA) IsSignatureFragmentPresent(signatureFragment def.SigFragment) bool {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	for _, existingFragment := range ca.Signaturelist {
		if reflect.DeepEqual(existingFragment, signatureFragment) {
			return true
		}
	}
	return false
}

func (ca *FSMCAEEA) GetSignatureListLength() int {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return len(ca.Signaturelist)
}

func (ca *FSMCAEEA) IsSignaturePresent() bool {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	if (reflect.DeepEqual(ca.Signature, def.ThresholdSig{})) {
		return false
	}
	return true
}
