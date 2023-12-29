package main

import (
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"strconv"
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
	router := gin.Default()
	config := readConfig()
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
		c.Header("Server", "GoServe v1.0.0")
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
		log.Printf("Device : %v", c.Param("device"))
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

	})
	host := config.Serve.Host
	port := config.Serve.Port
	address := host + ":" + strconv.FormatInt(port, 10)
	log.Printf("Config : %v", config)

	err := router.Run(address)
	if err != nil {
		return
	}
	log.Print("Server started on " + address + "!")
}
