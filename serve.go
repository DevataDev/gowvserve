package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/devatadev/gowvserve/wv"
	wvgo "github.com/devatadev/gowvserve/wv/proto"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
)

type config struct {
	Serve   serve           `yaml:"serve"`
	Users   map[string]user `yaml:"users"`
	Devices []string        `yaml:"devices"`
}

type user struct {
	Devices []string `yaml:"devices"`
	Name    string   `yaml:"name"`
}

type serve struct {
	Port             int64  `yaml:"port"`
	Host             string `yaml:"host"`
	Mode             string `yaml:"mode"`
	ForcePrivacyMode bool   `yaml:"force_privacy_mode"`
}

type KeyResponseItem struct {
	KeyId string `json:"key_id"`
	Key   string `json:"key"`
}

func readConfig() *config {
	yamlFile, err := ioutil.ReadFile("./serve.yaml")

	if err != nil {
		panic(err)
	}

	var config config

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		panic(err)
	}
	return &config
}

func main() {
	config := readConfig()
	mode := config.Serve.Mode
	if mode == "" {
		mode = "release"
	} else if (mode == "prod") || (mode == "production") {
		mode = "release"
	} else {
		mode = "debug"
	}
	var router *gin.Engine
	if mode == "release" {
		gin.SetMode(gin.ReleaseMode)
		// access log file
		gin.DefaultWriter = ioutil.Discard
		router = gin.New()
	} else {
		router = gin.Default()
	}
	opened_cdm := make(map[string]*wv.CDM)
	// middleware check for secret key
	router.Use(func(c *gin.Context) {
		secret_key := c.Request.Header["X-Secret-Key"]
		if secret_key == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		user := config.Users[secret_key[0]]
		if user.Name == "" {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		c.Next()
	})
	// set response headers
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		c.Header("Content-Type", "application/json")
		c.Header("X-Request-Via", "GoWVServe")
		c.Header("Server", "https://github.com/devine-dl/pywidevine serve v1.8.0")
		c.Next()
	})

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "GoServe is running!",
		})
	})

	router.HEAD("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "GoServe is running!",
		})
	})

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "pong",
		})
	})
	router.GET("/:device/open", func(c *gin.Context) {
		secret_key := c.Request.Header["X-Secret-Key"]
		device_name := c.Param("device")
		if secret_key == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		if config.Users[secret_key[0]].Devices[0] != device_name {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		selected_device := config.Devices[0]
		for _, device := range config.Devices {
			// if device contains device_name
			if strings.Contains(device, device_name) {
				selected_device = device
			}
		}

		wvd_file, err := ioutil.ReadFile(selected_device)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read WVD file",
			})
			c.Abort()
			return
		}

		device, err := wv.NewDevice(wv.FromWVD(bytes.NewReader(wvd_file)))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to create device",
			})
			c.Abort()
			return
		}
		var cdm *wv.CDM
		cdmKey := secret_key[0] + device_name
		// check if device is already opened
		if opened_cdm[cdmKey] != nil {
			cdm = opened_cdm[cdmKey]
		} else {
			cdm = wv.NewCDM(device)
			opened_cdm[cdmKey] = cdm
		}
		session, err := cdm.OpenSession()
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to open session",
			})
			c.Abort()
			return
		}
		sessionIdHex := hex.EncodeToString(session.Id)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Session opened",
			"data": gin.H{
				"session_id": sessionIdHex,
				"system_id":  cdm.GetSystemId(),
			},
		})
		return
	})

	router.GET("/:device/close/:session_id", func(c *gin.Context) {
		secret_key := c.Request.Header["X-Secret-Key"]
		device_name := c.Param("device")
		session_id := c.Param("session_id")
		if secret_key == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if config.Users[secret_key[0]].Devices[0] != device_name {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secret_key[0] + device_name
		cdm := opened_cdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}

		sessionId, err := hex.DecodeString(session_id)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}

		err = cdm.CloseSession(sessionId)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to close session",
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Session closed",
		})
		return
	})

	router.POST("/:device/set_service_certificate", func(c *gin.Context) {
		secretKey := c.Request.Header["X-Secret-Key"]
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := ioutil.ReadAll(requestBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read request body",
			})
			c.Abort()
			return
		}

		jsonBody := make(map[string]interface{})
		err = json.Unmarshal(body, &jsonBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to parse request body",
			})
			c.Abort()
			return
		}

		// check if session_id and init_data are present on request body
		if jsonBody["session_id"] == nil || jsonBody["certificate"] == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Session id or certificate not found",
			})
			c.Abort()
			return
		}

		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if config.Users[secretKey[0]].Devices[0] != deviceName {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey[0] + deviceName
		cdm := opened_cdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}

		sessionId, err := hex.DecodeString(jsonBody["session_id"].(string))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}

		base64Certificate := jsonBody["certificate"].(string)
		certificateDecoded, err := base64.StdEncoding.DecodeString(base64Certificate)

		_, err = cdm.SetServiceCertificate(sessionId, certificateDecoded)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to set service certificate : " + err.Error(),
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Service certificate set",
		})
		return
	})

	router.POST("/:device/get_license_challenge/:license_type", func(c *gin.Context) {
		secretKey := c.Request.Header["X-Secret-Key"]
		deviceName := c.Param("device")
		licenseType := c.Param("license_type")
		requestBody := c.Request.Body
		body, err := ioutil.ReadAll(requestBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read request body",
			})
			c.Abort()
			return
		}

		jsonBody := make(map[string]interface{})
		err = json.Unmarshal(body, &jsonBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to parse request body",
			})
			c.Abort()
			return
		}

		// check if session_id and init_data are present on request body
		if jsonBody["session_id"] == nil || jsonBody["init_data"] == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Session id or init_data not found",
			})
			c.Abort()
			return
		}

		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if config.Users[secretKey[0]].Devices[0] != deviceName {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey[0] + deviceName
		cdm := opened_cdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}
		sessionId, err := hex.DecodeString(jsonBody["session_id"].(string))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}
		base64Pssh := jsonBody["init_data"].(string)
		psshDecoded, err := base64.StdEncoding.DecodeString(base64Pssh)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode pssh",
			})
			c.Abort()
			return
		}
		pssh, err := wv.NewPSSH(psshDecoded)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to create pssh : " + err.Error(),
			})
			c.Abort()
			return
		}
		mappedLicenseType := wvgo.LicenseType_value[strings.ToUpper(licenseType)]
		if mappedLicenseType == 0 {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to map license type",
			})
			c.Abort()
			return
		}

		typeLicense := wvgo.LicenseType(mappedLicenseType)

		challenge, err := cdm.GetLicenseChallenge(sessionId, pssh, typeLicense, config.Serve.ForcePrivacyMode)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to get license challenge : " + err.Error(),
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Success",
			"data": gin.H{
				"challenge_b64": base64.StdEncoding.EncodeToString(challenge),
			},
		})
		return
	})

	router.POST("/:device/parse_license", func(c *gin.Context) {
		secretKey := c.Request.Header["X-Secret-Key"]
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := ioutil.ReadAll(requestBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read request body",
			})
			c.Abort()
			return
		}

		jsonBody := make(map[string]interface{})
		err = json.Unmarshal(body, &jsonBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to parse request body",
			})
			c.Abort()
			return
		}
		// check if session_id and init_data are present on request body
		if jsonBody["session_id"] == nil || jsonBody["license"] == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Session id or license not found",
			})
			c.Abort()
			return
		}

		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if config.Users[secretKey[0]].Devices[0] != deviceName {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey[0] + deviceName
		cdm := opened_cdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}
		sessionId, err := hex.DecodeString(jsonBody["session_id"].(string))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}

		base64License := jsonBody["license"].(string)
		licenseDecoded, err := base64.StdEncoding.DecodeString(base64License)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode license",
			})
			c.Abort()
			return
		}
		err = cdm.ParseLicense(sessionId, licenseDecoded)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to parse license : " + err.Error(),
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Success",
		})
		return
	})

	router.POST("/:device/get_keys/:key_type", func(c *gin.Context) {
		secretKey := c.Request.Header["X-Secret-Key"]
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := ioutil.ReadAll(requestBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read request body",
			})
			c.Abort()
			return
		}

		jsonBody := make(map[string]interface{})
		err = json.Unmarshal(body, &jsonBody)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to parse request body",
			})
			c.Abort()
			return
		}

		// check if session_id and init_data are present on request body
		if jsonBody["session_id"] == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Session id or license not found",
			})
			c.Abort()
			return
		}

		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if config.Users[secretKey[0]].Devices[0] != deviceName {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey[0] + deviceName
		cdm := opened_cdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}
		sessionId, err := hex.DecodeString(jsonBody["session_id"].(string))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}

		mappedKeyType := wvgo.License_KeyContainer_KeyType_value[strings.ToUpper(c.Param("key_type"))]
		if mappedKeyType == 0 {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to map key type",
			})
			c.Abort()
			return
		}

		keyType := wv.KeyType(mappedKeyType)
		keys, err := cdm.GetKeys(sessionId, keyType)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to get keys : " + err.Error(),
			})
			c.Abort()
			return
		}

		mappedKeyResponses := make([]*KeyResponseItem, 0)
		for _, key := range keys {
			mappedKeyResponses = append(mappedKeyResponses, &KeyResponseItem{
				KeyId: hex.EncodeToString(key.ID),
				Key:   hex.EncodeToString(key.Key),
			})
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Success",
			"data": gin.H{
				"keys": mappedKeyResponses,
			},
		})
		return
	})

	host := config.Serve.Host
	port := config.Serve.Port
	address := host + ":" + strconv.FormatInt(port, 10)

	err := router.Run(address)
	if err != nil {
		return
	}
	log.Print("Server started on " + address + "! - using mode " + mode + ", press Ctrl+C to exit.")
}
