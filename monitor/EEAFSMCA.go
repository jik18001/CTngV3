package monitor

import (
	"errors"
	"reflect"
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type FSMCAEEA struct {
	CTngID               def.CTngID
	State                string
	lock                 sync.RWMutex
	Period               int
	SRH                  def.SRH
	Updates              map[def.CTngID]def.Update_CA_EEA
	Notifications        []def.Notification
	DataFragments        [][]byte
	DataFragment_Counter int
	DataCheck            bool
	TimeCheck            bool
	Signaturelist        []def.SigFragment
	Signature            def.ThresholdSig
	APoM                 def.APoM
	CPoM                 def.CPoM
	TrafficCount         int
	UpdateCount          int
	StartTime            time.Time
	ConvergeTime         time.Duration
	Bmode                string
	Bmodes               []string
	EEA_Notifications    [][]def.Notification
}

// NewFSMCAEEA creates a new instance of FSMCAEEA with initialized maps and slices
func NewFSMCAEEA(ctngID def.CTngID, initialState string, initialPeriod int, numFragments int) *FSMCAEEA {
	return &FSMCAEEA{
		CTngID:            ctngID,
		State:             initialState,
		Period:            initialPeriod,
		Updates:           make(map[def.CTngID]def.Update_CA_EEA),
		Notifications:     make([]def.Notification, 0),
		DataFragments:     make([][]byte, 0),
		Signaturelist:     make([]def.SigFragment, 0),
		StartTime:         time.Now(),
		Bmodes:            make([]string, numFragments),
		EEA_Notifications: make([][]def.Notification, numFragments),
	}
}

func (ca *FSMCAEEA) GetStartTime() time.Time {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.StartTime
}

// SetField sets a field of the FSMCAEEA by name
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
	case "TimeCheck":
		if v, ok := value.(bool); ok {
			ca.TimeCheck = v
		} else {
			return errors.New("invalid type for TimeCheck")
		}
	case "Period":
		if v, ok := value.(int); ok {
			ca.Period = v
		} else {
			return errors.New("invalid type for Period")
		}
	case "Convergetime":
		if v, ok := value.(time.Duration); ok {
			ca.ConvergeTime = v
		} else {
			return errors.New("invalid type for Convergetime")
		}
	case "Bmode":
		if v, ok := value.(string); ok {
			ca.Bmode = v
		} else {
			return errors.New("invalid type for Bmode")
		}
	default:
		return errors.New("unknown field")
	}
	return nil
}

// GetField retrieves a field of the FSMCAEEA by name
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
	case "TimeCheck":
		return ca.TimeCheck, nil
	case "TrafficCount":
		return ca.TrafficCount, nil
	case "UpdateCount":
		return ca.UpdateCount, nil
	case "Period":
		return ca.Period, nil
	case "Convergetime":
		return ca.ConvergeTime, nil
	case "Bmode":
		return ca.Bmode, nil
	default:
		return nil, errors.New("unknown field")
	}
}

func (ca *FSMCAEEA) GetDataFragmentCounter() int {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.DataFragment_Counter
}

func (ca *FSMCAEEA) AddDataFragment(index int, dataFragment []byte) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	if index < 0 {
		return errors.New("index cannot be negative")
	}
	if index >= len(ca.DataFragments) {
		newSize := index + 1
		newDataFragments := make([][]byte, newSize)
		copy(newDataFragments, ca.DataFragments)
		ca.DataFragments = newDataFragments
	}

	if len(dataFragment) > 0 && len(ca.DataFragments[index]) == 0 {
		ca.DataFragment_Counter++
	}

	ca.DataFragments[index] = dataFragment
	return nil
}

func (ca *FSMCAEEA) GetDataFragment(index int) ([]byte, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if index < 0 || index >= len(ca.DataFragments) {
		return nil, errors.New("index out of range")
	}
	return ca.DataFragments[index], nil
}

func (ca *FSMCAEEA) GetDataFragments() [][]byte {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	dataFragmentsCopy := make([][]byte, len(ca.DataFragments))
	copy(dataFragmentsCopy, ca.DataFragments)
	return dataFragmentsCopy
}

func (ca *FSMCAEEA) StoreUpdate(monitorID def.CTngID, update def.Update_CA_EEA) {
	ca.lock.Lock()
	defer ca.lock.Unlock()
	if ca.Updates == nil {
		ca.Updates = make(map[def.CTngID]def.Update_CA_EEA)
	}
	ca.Updates[monitorID] = update
}

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
		if reflect.DeepEqual(existingNotification, notification) {
			return // Duplicate found
		}
	}

	ca.Notifications = append(ca.Notifications, notification)
}

func (ca *FSMCAEEA) GetNotifications() []def.Notification {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	notificationsCopy := make([]def.Notification, len(ca.Notifications))
	copy(notificationsCopy, ca.Notifications)
	return notificationsCopy
}

func (ca *FSMCAEEA) GetFirstNotification() *def.Notification {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if len(ca.Notifications) == 0 {
		return nil
	}
	return &ca.Notifications[0]
}

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
	return !reflect.DeepEqual(ca.Signature, def.ThresholdSig{})
}

func (ca *FSMCAEEA) GetBmodeForFragment(index int) (string, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if index < 0 || index >= len(ca.Bmodes) {
		return "", errors.New("index out of range")
	}

	return ca.Bmodes[index], nil
}

func (ca *FSMCAEEA) SetBmodeForFragment(index int, bmode string) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	if index < 0 {
		return errors.New("index cannot be negative")
	}

	if index >= len(ca.Bmodes) {
		newSize := index + 1
		newBmodes := make([]string, newSize)
		copy(newBmodes, ca.Bmodes)
		ca.Bmodes = newBmodes

		newNotifications := make([][]def.Notification, newSize)
		copy(newNotifications, ca.EEA_Notifications)
		ca.EEA_Notifications = newNotifications
	}

	ca.Bmodes[index] = bmode
	return nil
}

func (ca *FSMCAEEA) AddNotificationToFragment(index int, notification def.Notification) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	if index < 0 {
		return errors.New("index cannot be negative")
	}

	if index >= len(ca.EEA_Notifications) {
		newSize := index + 1
		newEEA := make([][]def.Notification, newSize)
		copy(newEEA, ca.EEA_Notifications)
		ca.EEA_Notifications = newEEA

		newBmodes := make([]string, newSize)
		copy(newBmodes, ca.Bmodes)
		ca.Bmodes = newBmodes
	}

	notifications := &ca.EEA_Notifications[index]

	for _, existingNotification := range *notifications {
		if reflect.DeepEqual(existingNotification, notification) {
			return nil // Duplicate found
		}
	}

	*notifications = append(*notifications, notification)
	return nil
}

func (ca *FSMCAEEA) GetNotificationsForFragment(index int) ([]def.Notification, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if index < 0 || index >= len(ca.EEA_Notifications) {
		return nil, errors.New("index out of range")
	}

	notifications := ca.EEA_Notifications[index]
	notificationsCopy := make([]def.Notification, len(notifications))
	copy(notificationsCopy, notifications)
	return notificationsCopy, nil
}

func (ca *FSMCAEEA) GetFirstNotificationForFragment(index int) (*def.Notification, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	if index < 0 || index >= len(ca.EEA_Notifications) {
		return nil, errors.New("index out of range")
	}

	notifications := ca.EEA_Notifications[index]
	if len(notifications) == 0 {
		return nil, nil
	}

	notificationCopy := notifications[0]
	return &notificationCopy, nil
}

func (ca *FSMCAEEA) AddCPoM(cpom def.CPoM) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	if !reflect.DeepEqual(ca.CPoM, def.CPoM{}) {
		return errors.New("CPoM already present")
	}

	ca.CPoM = cpom
	return nil
}

func (ca *FSMCAEEA) AddAPoM(apom def.APoM) error {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	if !reflect.DeepEqual(ca.APoM, def.APoM{}) {
		return errors.New("APoM already present")
	}

	ca.APoM = apom
	return nil
}
