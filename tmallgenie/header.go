package tmallgenie

import ()

type TMallGenieHeader struct {
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	MessageId      string `json:"messageId"`
	PayLoadVersion int    `json:"payLoadVersion"`
}
