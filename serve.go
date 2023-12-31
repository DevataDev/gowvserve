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
	"io"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
)

type Config struct {
	Serve   Serve           `yaml:"serve"`
	Users   map[string]User `yaml:"users"`
	Devices []string        `yaml:"devices"`
}

type User struct {
	Devices []string `yaml:"devices"`
	Name    string   `yaml:"name"`
}

type Serve struct {
	Port             int64  `yaml:"port"`
	Host             string `yaml:"host"`
	Mode             string `yaml:"mode"`
	ForcePrivacyMode bool   `yaml:"force_privacy_mode"`
}

type KeyResponseItem struct {
	KeyId string `json:"key_id"`
	Key   string `json:"key"`
}

func readConfig() *Config {
	yamlFile, err := os.ReadFile("./serve.yaml")

	if err != nil {
		panic(err)
	}

	var config Config

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
		gin.DefaultWriter = io.Discard
		router = gin.New()
	} else {
		router = gin.Default()
	}
	openedCdm := make(map[string]*wv.CDM)
	// middleware check for secret key
	router.Use(func(c *gin.Context) {
		secretKey := c.Request.Header["X-Secret-Key"]
		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		user := config.Users[secretKey[0]]
		if user.Name == "" {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		// set secret key to context
		c.Set("secret_key", secretKey[0])
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
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		selectedDevice := config.Devices[0]
		for _, device := range config.Devices {
			deviceFilename := strings.Split(device, "/")
			deviceFilename = strings.Split(deviceFilename[len(deviceFilename)-1], ".")
			if deviceFilename[0] == deviceName {
				selectedDevice = device
			}
		}

		wvdFile, err := os.ReadFile(selectedDevice)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to read WVD file",
			})
			c.Abort()
			return
		}

		device, err := wv.NewDevice(wv.FromWVD(bytes.NewReader(wvdFile)))
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to create device",
			})
			c.Abort()
			return
		}
		var cdm *wv.CDM
		cdmKey := secretKey.(string) + deviceName
		// check if device is already opened
		if openedCdm[cdmKey] != nil {
			cdm = openedCdm[cdmKey]
		} else {
			cdm = wv.NewCDM(device)
			openedCdm[cdmKey] = cdm
		}
		session, err := cdm.OpenSession()
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to open session : " + err.Error(),
			})
			c.Abort()
			return
		}
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Success",
			"data": gin.H{
				"session_id": session.HexId(),
				"system_id":  cdm.GetSystemId(),
			},
		})
		return
	})

	router.GET("/:device/close/:session_id", func(c *gin.Context) {
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		sessionId := c.Param("session_id")
		if secretKey == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey.(string) + deviceName
		cdm := openedCdm[cdmKey]
		if cdm == nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Opened session not found",
			})
			c.Abort()
			return
		}

		decodedSessionId, err := hex.DecodeString(sessionId)
		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Failed to decode session id",
			})
			c.Abort()
			return
		}

		err = cdm.CloseSession(decodedSessionId)
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
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := io.ReadAll(requestBody)
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

		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey.(string) + deviceName
		cdm := openedCdm[cdmKey]
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
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		licenseType := c.Param("license_type")
		requestBody := c.Request.Body
		body, err := io.ReadAll(requestBody)
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

		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey.(string) + deviceName
		cdm := openedCdm[cdmKey]
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
		base64PSSH := jsonBody["init_data"].(string)
		psshDecoded, err := base64.StdEncoding.DecodeString(base64PSSH)
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
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := io.ReadAll(requestBody)
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

		// check if devices contains deviceName
		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey.(string) + deviceName
		cdm := openedCdm[cdmKey]
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
		secretKey, _ := c.Get("secret_key")
		deviceName := c.Param("device")
		requestBody := c.Request.Body
		body, err := io.ReadAll(requestBody)
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

		if !slices.Contains(config.Users[secretKey.(string)].Devices, deviceName) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		cdmKey := secretKey.(string) + deviceName
		cdm := openedCdm[cdmKey]
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
				KeyId: key.KeyIdHex(),
				Key:   key.KeyHex(),
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
