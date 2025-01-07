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
	DataFragments        [][]byte                             // The certificate shares
	Bmodes               []string                             // Broadcasting modes for each data fragment
	EEA_Notifications    [][]def.Notification                 // Notifications for each data fragment
	DataFragment_Counter int                                  // Count of Data Fragments
	Data                 [][]byte                             // The entire certificate file
	DataCheck            bool                                 // Compare against the head_cert
	TimeCheck            bool
	Signaturelist        []def.SigFragment  // Precommit and Post Commit State, sign over the STH
	Signature            def.ThresholdSig   // Done state (Serialized signature)
	APoM                 def.APoM           // APoM record against this Logger, if any
	CPoM                 def.CPoM           // CPoM record against this Logger, if any
	TrafficCount         int                // Count of traffic
	UpdateCount          int                // Count of updates received
	StartTime            time.Time          // Time when the FSMLoggerEEA was started
	ConvergeTime         time.Duration      // Time it takes to generate Threshold Signature
	Bmode                string             // Only used in the base version (Non-EEA)
	Notifications        []def.Notification // Only used in the base version (Non-EEA)

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
	case "TimeCheck":
		if v, ok := value.(bool); ok {
			l.TimeCheck = v
		} else {
			return errors.New("invalid type for TimeCheck")
		}

	case "Convergetime":
		if v, ok := value.(time.Duration); ok {
			l.ConvergeTime = v
		} else {
			return errors.New("invalid type for DataCheck")
		}
	case "Data":
		if v, ok := value.([][]byte); ok {
			l.Data = v
		} else {
			return errors.New("invalid type for Data")
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
	case "TimeCheck":
		return l.TimeCheck, nil
	case "TrafficCount":
		return l.TrafficCount, nil
	case "UpdateCount":
		return l.UpdateCount, nil
	case "Data":
		return l.Data, nil
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

// Method to securely add APoM to the FSMLoggerEEA
func (l *FSMLoggerEEA) AddAPoM(apom def.APoM) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	// Ensure that APoM is not overwritten if already present
	if !reflect.DeepEqual(l.APoM, def.APoM{}) {
		return errors.New("APoM already present")
	}

	l.APoM = apom
	return nil
}

// Method to securely add CPoM to the FSMLoggerEEA
func (l *FSMLoggerEEA) AddCPoM(cpom def.CPoM) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	// Ensure that CPoM is not overwritten if already present
	if !reflect.DeepEqual(l.CPoM, def.CPoM{}) {
		return errors.New("CPoM already present")
	}

	l.CPoM = cpom
	return nil
}

func (l *FSMLoggerEEA) SetBmodeForFragment(index int, bmode string) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	if index < 0 {
		return errors.New("index cannot be negative")
	}

	// Ensure the Bmodes slice is large enough
	if index >= len(l.Bmodes) {
		newSize := index + 1

		// Resize Bmodes
		newBmodes := make([]string, newSize)
		copy(newBmodes, l.Bmodes)
		l.Bmodes = newBmodes

		// Also resize DataFragments and EEA_Notifications to keep all slices in sync
		newDataFragments := make([][]byte, newSize)
		copy(newDataFragments, l.DataFragments)
		l.DataFragments = newDataFragments

		newEEA_Notifications := make([][]def.Notification, newSize)
		copy(newEEA_Notifications, l.EEA_Notifications)
		l.EEA_Notifications = newEEA_Notifications
	}

	l.Bmodes[index] = bmode
	return nil
}

// Method to get the Bmode for a specific data fragment
func (l *FSMLoggerEEA) GetBmodeForFragment(index int) (string, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	if index < 0 || index >= len(l.Bmodes) {
		return "", errors.New("index out of range")
	}

	return l.Bmodes[index], nil
}

// Method to add a notification to a specific data fragment
func (l *FSMLoggerEEA) AddNotificationToFragment(index int, notification def.Notification) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	if index < 0 {
		return errors.New("index cannot be negative")
	}

	// Ensure the EEA_Notifications slice is large enough
	if index >= len(l.EEA_Notifications) {
		newSize := index + 1
		newEEA_Notifications := make([][]def.Notification, newSize)
		copy(newEEA_Notifications, l.EEA_Notifications)
		l.EEA_Notifications = newEEA_Notifications

		// Also resize DataFragments and Bmodes to keep all slices in sync
		newDataFragments := make([][]byte, newSize)
		copy(newDataFragments, l.DataFragments)
		l.DataFragments = newDataFragments

		newBmodes := make([]string, newSize)
		copy(newBmodes, l.Bmodes)
		l.Bmodes = newBmodes
	}

	notifications := &l.EEA_Notifications[index]

	// Check for duplicates
	for _, existingNotification := range *notifications {
		if reflect.DeepEqual(existingNotification, notification) {
			return nil // Duplicate found, do not add
		}
	}

	*notifications = append(*notifications, notification)
	return nil
}

// Method to retrieve all notifications from a specific data fragment
func (l *FSMLoggerEEA) GetNotificationsForFragment(index int) ([]def.Notification, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	if index < 0 || index >= len(l.EEA_Notifications) {
		return nil, errors.New("index out of range")
	}

	notifications := l.EEA_Notifications[index]

	// Return a copy to prevent external modification
	notificationsCopy := make([]def.Notification, len(notifications))
	copy(notificationsCopy, notifications)
	return notificationsCopy, nil
}

// Method to retrieve the first notification from a specific data fragment
func (l *FSMLoggerEEA) GetFirstNotificationForFragment(index int) (*def.Notification, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	if index < 0 || index >= len(l.EEA_Notifications) {
		return nil, errors.New("index out of range")
	}

	notifications := l.EEA_Notifications[index]

	if len(notifications) == 0 {
		return nil, nil // No notifications for this fragment
	}

	// Return a copy to prevent external modifications
	notificationCopy := notifications[0]
	return &notificationCopy, nil
}
