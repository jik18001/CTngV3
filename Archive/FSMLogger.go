package monitor

import (
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type FSMLogger struct {
	CTngID        def.CTngID
	Starttime     time.Time
	Period        int
	Notification  []def.Notification
	MetaData      def.STH
	DataFragments [][]byte
	Data          []byte
	State         string
	lock          sync.RWMutex
}

// Method to add a notification to the FSMLogger
func (l *FSMLogger) AddNotification(notification def.Notification) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.Notification = append(l.Notification, notification)
}

// Method to retrieve all notifications from the FSMLogger
func (l *FSMLogger) GetNotification() []def.Notification {
	l.lock.RLock()
	defer l.lock.RUnlock()

	// Return a copy of the notifications to avoid data race issues
	notificationsCopy := make([]def.Notification, len(l.Notification))
	copy(notificationsCopy, l.Notification)
	return notificationsCopy
}

// Method to set the metadata of the FSMLogger
func (l *FSMLogger) SetMetaData(metaData def.STH) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.MetaData = metaData
}

// Method to get the metadata of the FSMLogger
func (l *FSMLogger) GetMetaData() def.STH {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.MetaData
}

// Method to add a data fragment to the FSMLogger
func (l *FSMLogger) AddDataFragment(index int, dataFragment []byte) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.DataFragments[index] = dataFragment
}

// Method to get a data fragment to the FSMLogger
func (l *FSMLogger) GetDataFragment(index int, dataFragment []byte) []byte {
	l.lock.Lock()
	defer l.lock.Unlock()
	return l.DataFragments[index]
}

// Method to retrieve all data fragments from the FSMLogger
func (l *FSMLogger) GetDataFragments() [][]byte {
	l.lock.RLock()
	defer l.lock.RUnlock()

	// Return a copy of the data fragments to avoid data race issues
	dataFragmentsCopy := make([][]byte, len(l.DataFragments))
	copy(dataFragmentsCopy, l.DataFragments)
	return dataFragmentsCopy
}

// Method to set the main data of the FSMLogger
func (l *FSMLogger) SetData(data []byte) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.Data = data
}

// Method to get the main data of the FSMLogger
func (l *FSMLogger) GetData() []byte {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.Data
}

// Method to set the state of the FSMLogger
func (l *FSMLogger) SetState(newState string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.State = newState
}

// Method to get the state of the FSMLogger
func (l *FSMLogger) GetState() string {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.State
}
