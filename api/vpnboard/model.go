package vpnboard

import "encoding/json"

type NodeInfoResponse struct {
	Name              string `json:"name"`
	Remarks           string `json:"remarks"`
	Address           string `json:"address"`
	Port              int64  `json:"port"`
	NodeOrder         int64  `json:"node_order"`
	NodeSpeedLimit    int64  `json:"node_speed_limit"`
	NodeType          string `json:"node_type"`
	EnableTLS         bool   `json:"enable_tls"`
	Path              string `json:"path"`
	TransportProtocol string `json:"transport_protocol"`
	Host              string `json:"host"`
	ServiceName       string `json:"service_name"`
	EnableVless       bool   `json:"enable_vless"`
	Method            string `json:"method"`
	ServerKey         string `json:"server_key"`
}

type UserListResponse struct {
	List []UserListResponseItem `json:"list"`
}

type UserListResponseItem struct {
	UID         int    `json:"uid"`
	UUID        string `json:"uuid"`
	UserName    string `json:"user_name"`
	SpeedLimit  uint64 `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

// Response is the common response
type Response struct {
	Code int64           `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}
