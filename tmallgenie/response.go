package tmallgenie

import ()

type TMallGenieResponseDevice struct {
	DeviceId   string            `json:"deviceId"`
	DeviceName string            `json:"deviceName"`
	DeviceType string            `json:"deviceType"`
	Brand      string            `json:"brand"`
	Model      string            `json:"model"`
	Zone       string            `json:"zone"`
	Icon       string            `json:"icon"`
	Properties map[string]string `json:"properties"`
	Actions    []string          `json:"actions"`
	Extensions map[string]string `json:"extensions"`
}

func (this *TMallGenieResponseDevice) SetZone(zone string) {
	this.Zone = zone
}

func (this *TMallGenieResponseDevice) SetIcon(icon string) {
	this.Icon = icon
}

func (this *TMallGenieResponseDevice) AddProperties(key, value string) {
	this.Properties[key] = value
}

func (this *TMallGenieResponseDevice) AddAction(action string) {
	this.Actions = append(this.Actions, action)
}

func (this *TMallGenieResponseDevice) AddExtensions(key, value string) {
	this.Extensions[key] = value
}

type TMallGenieResponseDiscovery struct {
	Devices []*TMallGenieResponseDevice `json:"devices"`
}

type TMallGenieResponseError struct {
	DeviceId  string `json:"deviceId"`
	ErrorCode string `json:"errorCode"`
	Message   string `json:"message"`
}

type TMallGenieResponse struct {
	Header  *TMallGenieHeader `json:"header"`
	Payload interface{}       `json:"payload"`
}

func NewTMallGenieResponseDevice(devid, name, type_, brand, model string) *TMallGenieResponseDevice {
	return &TMallGenieResponseDevice{
		DeviceId:   devid,
		DeviceName: name,
		DeviceType: type_,
		Brand:      brand,
		Model:      model,
		Zone:       "门口",
		Icon:       "https://gss2.bdstatic.com/9fo3dSag_xI4khGkpoWK1HF6hhy/baike/c0%3Dbaike150%2C5%2C5%2C150%2C50/sign=0edeabc20be93901420f856c1a853f82/ca1349540923dd542449b48adb09b3de9c82481d.jpg",
		Properties: make(map[string]string),
		Extensions: make(map[string]string),
	}
}
