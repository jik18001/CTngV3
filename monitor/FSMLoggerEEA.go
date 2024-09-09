package monitor

import (
	"errors"
	"reflect"
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type FSMLoggerEEA struct {
	CTngID               def.CTngID                           // CTngID
	State                string                               // Current state
	lock                 sync.RWMutex                         // Concurrency control
	Period               int                                  // Current period of operation
	STH                  def.STH                              // Valid STH received for the period
	Updates              map[def.CTngID]def.Update_Logger_EEA // All the updates for this Logger, indexed by Monitor ID
	Notifications        []def.Notification                   // Notifications cache for data collection
	DataFragments        [][]byte                             // The certificates shares in this case
	DataFragment_Counter int                                  // count of Data Fragments
	DataCheck            bool                                 // compare agains the head_cert
	Signaturelist        []def.SigFragment                    // Precommit and Post Commit State, sign over the STH
	Signature            def.ThresholdSig                     // Done state (Serialized signature)
	APoM                 def.APoM                             // APoM record against this Logger, if any
	CPoM                 def.CPoM                             // CPoM record against this Logger, if any
	TrafficCount         int                                  // Count of  traffic
	UpdateCount          int                                  // Count of update received
	StartTime            time.Time                            // Time when the FSMLoggerEEA was started
	ConvergeTime         time.Duration                        // Time it takes to generate Threshold Signature
}

// Method to retrieve the start time
func (l *FSMLoggerEEA) GetStartTime() time.Time {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.StartTime
}

// General method to set a field of the FSMLoggerEEA
func (l *FSMLoggerEEA) SetField(field string, value interface{}) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	switch field {
	case "STH":
		if v, ok := value.(def.STH); ok {
			l.STH = v
		} else {
			return errors.New("invalid type for STH")
		}
	case "State":
		if v, ok := value.(string); ok {
			l.State = v
		} else {
			return errors.New("invalid type for State")
		}
	case "Signature":
		if v, ok := value.(def.ThresholdSig); ok {
			l.Signature = v
		} else {
			return errors.New("invalid type for Signature")
		}
	case "CPoM":
		if v, ok := value.(def.CPoM); ok {
			l.CPoM = v
		} else {
			return errors.New("invalid type for CPoM")
		}
	case "APoM":
		if v, ok := value.(def.APoM); ok {
			l.APoM = v
		} else {
			return errors.New("invalid type for APoM")
		}
	case "TrafficCount":
		if v, ok := value.(int); ok {
			l.TrafficCount = v
		} else {
			return errors.New("invalid type for TrafficCount")
		}
	case "UpdateCount":
		if v, ok := value.(int); ok {
			l.UpdateCount = v
		} else {
			return errors.New("invalid type for UpdateCount")
		}
	case "DataCheck":
		if v, ok := value.(bool); ok {
			l.DataCheck = v
		} else {
			return errors.New("invalid type for DataCheck")
		}
	default:
		return errors.New("unknown field")
	}
	return nil
}

// General method to get a field of the FSMLoggerEEA
func (l *FSMLoggerEEA) GetField(field string) (interface{}, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	switch field {
	case "STH":
		return l.STH, nil
	case "State":
		return l.State, nil
	case "Signature":
		return l.Signature, nil
	case "CPoM":
		return l.CPoM, nil
	case "APoM":
		return l.APoM, nil
	case "DataCheck":
		return l.DataCheck, nil
	case "TrafficCount":
		return l.TrafficCount, nil
	case "UpdateCount":
		return l.UpdateCount, nil
	default:
		return nil, errors.New("unknown field")
	}
}

// Method to retrieve the current value of DataFragment_Counter
func (l *FSMLoggerEEA) GetDataFragmentCounter() int {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.DataFragment_Counter
}

// Method to add a data fragment to the FSMLoggerEEA
func (l *FSMLoggerEEA) AddDataFragment(index int, dataFragment []byte) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	// Check if index is within the valid range
	if index < 0 || index >= len(l.DataFragments) {
		return errors.New("index out of range")
	}

	// Only increment the counter if the fragment is non-empty and hasn't been set before
	if len(dataFragment) > 0 && len(l.DataFragments[index]) == 0 {
		l.DataFragment_Counter++
	}

	// Set the data fragment at the specified index
	l.DataFragments[index] = dataFragment
	return nil
}

// Method to get a data fragment from the FSMLoggerEEA
func (l *FSMLoggerEEA) GetDataFragment(index int) ([]byte, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if index < 0 || index >= len(l.DataFragments) {
		return nil, errors.New("index out of range")
	}
	return l.DataFragments[index], nil
}

// Method to retrieve all data fragments from the FSMLoggerEEA
func (l *FSMLoggerEEA) GetDataFragments() [][]byte {
	l.lock.RLock()
	defer l.lock.RUnlock()
	dataFragmentsCopy := make([][]byte, len(l.DataFragments))
	copy(dataFragmentsCopy, l.DataFragments)
	return dataFragmentsCopy
}

// Method to store an update for the FSMLoggerEEA
func (l *FSMLoggerEEA) StoreUpdate(monitorID def.CTngID, update def.Update_Logger_EEA) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.Updates[monitorID] = update
}

// Method to get an update from the FSMLoggerEEA
func (l *FSMLoggerEEA) GetUpdate(monitorID def.CTngID) (def.Update_Logger_EEA, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	update, exists := l.Updates[monitorID]
	if !exists {
		return def.Update_Logger_EEA{}, errors.New("update not found")
	}
	return update, nil
}

func (l *FSMLoggerEEA) AddNotification(notification def.Notification) {
	l.lock.Lock()
	defer l.lock.Unlock()

	for _, existingNotification := range l.Notifications {
		if existingNotification == notification {
			return // Duplicate found, do not add
		}
	}

	l.Notifications = append(l.Notifications, notification)
}

// Method to retrieve all notifications from the FSMLoggerEEA
func (l *FSMLoggerEEA) GetNotifications() []def.Notification {
	l.lock.RLock()
	defer l.lock.RUnlock()
	// Return a copy of the notifications to avoid data race issues
	notificationsCopy := make([]def.Notification, len(l.Notifications))
	copy(notificationsCopy, l.Notifications)
	return notificationsCopy
}

// Method to retrieve the first notification from the FSMLoggerEEA
func (l *FSMLoggerEEA) GetFirstNotification() *def.Notification {
	l.lock.RLock()
	defer l.lock.RUnlock()

	if len(l.Notifications) == 0 {
		return nil
	}
	return &l.Notifications[0]
}

// Method to add a signature fragment to the Signaturelist
func (l *FSMLoggerEEA) AddSignatureFragment(signatureFragment def.SigFragment) {
	l.lock.Lock()
	defer l.lock.Unlock()
	for _, existingFragment := range l.Signaturelist {
		if reflect.DeepEqual(existingFragment, signatureFragment) {
			return
		}
	}
	l.Signaturelist = append(l.Signaturelist, signatureFragment)
}

// Method to check if a signature fragment is already present in the Signaturelist
func (l *FSMLoggerEEA) IsSignatureFragmentPresent(signatureFragment def.SigFragment) bool {
	l.lock.RLock()
	defer l.lock.RUnlock()

	for _, existingFragment := range l.Signaturelist {
		if reflect.DeepEqual(existingFragment, signatureFragment) {
			return true
		}
	}
	return false
}

func (l *FSMLoggerEEA) GetSignatureListLength() int {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return len(l.Signaturelist)
}

func (l *FSMLoggerEEA) IsSignaturePresent() bool {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if (reflect.DeepEqual(l.Signature, def.ThresholdSig{})) {
		return false
	}
	return true
}
