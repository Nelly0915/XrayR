package vpnboard

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"os"
	"reflect"
	"regexp"
	"sync"
	"time"
)

// APIClient create a api client to the panel.
type APIClient struct {
	client              *resty.Client
	APIHost             string
	NodeID              int
	Key                 string
	NodeType            string
	EnableVless         bool
	VlessFlow           string
	SpeedLimit          float64
	DeviceLimit         int
	DisableCustomConfig bool
	LocalRuleList       []api.DetectRule
	LastReportOnline    map[int]int
	access              sync.Mutex
	version             string
	eTags               map[string]string
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()

	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})

	client.SetBaseURL(apiConfig.APIHost)

	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	return &APIClient{
		client:              client,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		APIHost:             apiConfig.APIHost,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		VlessFlow:           apiConfig.VlessFlow,
		SpeedLimit:          apiConfig.SpeedLimit,
		DeviceLimit:         apiConfig.DeviceLimit,
		LocalRuleList:       localRuleList,
		DisableCustomConfig: apiConfig.DisableCustomConfig,
		LastReportOnline:    make(map[int]int),
		eTags:               make(map[string]string),
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("Error when closing file: %s", err)
			}
		}(file)
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := "/api/public/xrayr/node/info"
	res, err := c.client.R().
		SetBody(map[string]uint{"node_id": uint(c.NodeID)}).
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return nil, err
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	nodeInfo, err = c.parseNodeInfo(nodeInfoResponse)

	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	path := "/api/public/xrayr/user/list"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	res, err := c.client.R().
		SetBody(map[string]uint{"node_id": uint(c.NodeID)}).
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags["users"]).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return nil, err
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new(UserListResponse)

	if err := json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}

	users := userListResponse.List
	userList := make([]api.UserInfo, len(users))

	for i := 0; i < len(users); i++ {
		u := api.UserInfo{
			UID:  users[i].UID,
			UUID: users[i].UUID,
		}

		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = users[i].SpeedLimit * 1000000 / 8
		}

		if c.DeviceLimit > 0 {
			u.DeviceLimit = c.DeviceLimit
		} else {
			u.DeviceLimit = users[i].DeviceLimit
		}

		if isEmailFormat(users[i].UserName) {
			u.Email = users[i].UserName
		} else {
			u.Email = users[i].UserName + "@vpnboard.user"
		}

		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}

	fmt.Println(userList)

	return &userList, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUser *[]api.OnlineUser) (err error) {
	return nil
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) (err error) {
	return nil
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

func (c *APIClient) GetNodeRule() (ruleList *[]api.DetectRule, err error) {
	return &c.LocalRuleList, nil
}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}

func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Code != 0 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("ret %s invalid", string(res))
	}
	return response, nil
}

func (c *APIClient) parseNodeInfo(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var speedLimit uint64
	if c.SpeedLimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((nodeInfoResponse.NodeSpeedLimit * 1000000) / 8)
	}
	nodeInfo := &api.NodeInfo{
		NodeType:          nodeInfoResponse.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(nodeInfoResponse.Port),
		SpeedLimit:        speedLimit,
		TransportProtocol: nodeInfoResponse.TransportProtocol,
		Host:              nodeInfoResponse.Host,
		Path:              nodeInfoResponse.Path,
		EnableTLS:         nodeInfoResponse.EnableTLS,
		EnableVless:       nodeInfoResponse.EnableVless,
		VlessFlow:         c.VlessFlow,
		ServiceName:       nodeInfoResponse.ServiceName,
		CypherMethod:      nodeInfoResponse.Method,
		ServerKey:         nodeInfoResponse.ServerKey,
	}
	return nodeInfo, nil
}

func isEmailFormat(email string) bool {
	const emailPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailPattern)
	return re.MatchString(email)
}
