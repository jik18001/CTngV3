package monitor

import (
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type FSMCA struct {
	CTngID        def.CTngID
	Starttime     time.Time
	Period        int
	Notification  []def.Notification
	MetaData      def.SRH
	DataFragments [][]byte
	Data          []byte
	State         string
	lock          sync.RWMutex
}

// Method to add a notification to the FSMCA
func (c *FSMCA) AddNotification(notification def.Notification) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Notification = append(c.Notification, notification)
}

// Method to retrieve all notifications from the FSMCA
func (c *FSMCA) GetNotification() []def.Notification {
	c.lock.RLock()
	defer c.lock.RUnlock()

	// Return a copy of the notifications to avoid data race issues
	notificationsCopy := make([]def.Notification, len(c.Notification))
	copy(notificationsCopy, c.Notification)
	return notificationsCopy
}

// Method to set the metadata of the FSMCA
func (c *FSMCA) SetMetaData(metaData def.SRH) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.MetaData = metaData
}

// Method to get the metadata of the FSMCA
func (c *FSMCA) GetMetaData() def.SRH {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.MetaData
}

// Method to add a data fragment to the FSMCA
func (c *FSMCA) AddDataFragment(index int, dataFragment []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.DataFragments[index] = dataFragment
}

// Method to retrieve all data fragments from the FSMCA
func (c *FSMCA) GetDataFragments() [][]byte {
	c.lock.RLock()
	defer c.lock.RUnlock()

	// Return a copy of the data fragments to avoid data race issues
	dataFragmentsCopy := make([][]byte, len(c.DataFragments))
	copy(dataFragmentsCopy, c.DataFragments)
	return dataFragmentsCopy
}

// Method to set the main data of the FSMCA
func (c *FSMCA) SetData(data []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.Data = data
}

// Method to get the main data of the FSMCA
func (c *FSMCA) GetData() []byte {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.Data
}

// Method to set the state of the FSMCA
func (c *FSMCA) SetState(newState string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.State = newState
}

// Method to get the state of the FSMCA
func (c *FSMCA) GetState() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.State
}
