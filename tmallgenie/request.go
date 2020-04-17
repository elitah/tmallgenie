package tmallgenie

import (
	"encoding/json"
)

type TMallGenieAccessToken interface {
	GetAccessToken() string
}

type TMallGenieRequestDiscovery struct {
	AccessToken string `json:"accessToken"`
}

func (this *TMallGenieRequestDiscovery) GetAccessToken() string {
	return this.AccessToken
}

type TMallGenieRequestControl struct {
	AccessToken string `json:"accessToken"`
}

func (this *TMallGenieRequestControl) GetAccessToken() string {
	return this.AccessToken
}

type TMallGenieRequestQuery struct {
	AccessToken string `json:"accessToken"`
}

func (this *TMallGenieRequestQuery) GetAccessToken() string {
	return this.AccessToken
}

type TMallGenieRequest struct {
	Header  TMallGenieHeader `json:"header"`
	Payload json.RawMessage  `json:"payload"`

	_payload TMallGenieAccessToken
}

func (this *TMallGenieRequest) GetPayload() TMallGenieAccessToken {
	if nil == this._payload {
		switch this.Header.Namespace {
		case "AliGenie.Iot.Device.Discovery":
			switch this.Header.Name {
			case "DiscoveryDevices":
				payload := &TMallGenieRequestDiscovery{}
				//
				if err := json.Unmarshal(this.Payload, payload); nil == err {
					this._payload = payload
				}
			}
		case "AliGenie.Iot.Device.Control":
			switch this.Header.Name {
			case "TurnOn":
			}
		case "AliGenie.Iot.Device.Query":
			switch this.Header.Name {
			case "TurnOn":
			}
		}
	}
	return this._payload
}

func (this *TMallGenieRequest) GetAccessToken() string {
	return this.GetPayload().GetAccessToken()
}
