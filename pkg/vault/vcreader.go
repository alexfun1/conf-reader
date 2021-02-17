package vcreader

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Vault - vault api calls
// Expects VAULT_ADDR, VAULT_INSECURE, VAULT_TOKEN to be set in env variables
type Vault struct {
	Storage string
	Config  *api.Config
	Client  *api.Client
}

func (v *Vault) setConfig() bool {
	v.Config.Address = os.Getenv("VAULT_ADDR")
	flag, _ := strconv.ParseBool((os.Getenv("VAULT_INSECURE")))
	if flag {
		err := v.Config.ConfigureTLS(&api.TLSConfig{Insecure: flag})
		if err != nil {
			log.Println("Vault SSL verification disabled")
			return false
		}
	}
	return true
}

func (v *Vault) setClient() bool {
	var err error
	v.Client, err = api.NewClient(v.Config)
	if err != nil {
		log.Println("Error connecting to Vault: ", err)
		return false
	}
	v.Client.SetToken(os.Getenv("VAULT_TOKEN"))
	return true
}

//Init - initialize vault object - creates connection and empty key structure
func (v *Vault) Init() error {
	v.Config = new(api.Config)
	v.Client = new(api.Client)
	v.Storage = os.Getenv("VAULT_STORAGE")

	if len(v.Storage) < 1 {
		v.Storage = "secret/"
	}

	if !strings.HasSuffix(v.Storage, "/") {
		v.Storage = v.Storage + "/"
	}

	if !v.setConfig() {
		return fmt.Errorf("Cannot initiate vault connection: address - %s", os.Getenv("VAULT_ADDR"))
	}
	if !v.setClient() {
		return fmt.Errorf("Cannot initiate vault connection: address - %s", os.Getenv("VAULT_ADDR"))
	}
	return nil
}

func (v *Vault) getData(key string) (map[string]interface{}, error) {
	secret, err := v.Client.Logical().Read(v.Storage + key)
	if err != nil {
		log.Printf("Error reading secret:%s ", err.Error())
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("Key %s does not exist", key)
	}

	return secret.Data, nil
}

func (v *Vault) GetPlainData(key string) (map[string]interface{}, error) {
	result, err := v.getData(key)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (v *Vault) GetJSON(key string) ([]byte, error) {
	data, err := v.getData(key)
	if err != nil {

		return nil, err
	}

	result, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling secret:%s ", err.Error())
		return nil, err
	}

	return result, nil
}

//Backward compatibility

func (v *Vault) GetConfig(key string) (map[string][]byte, error) {
	result := map[string][]byte{}
	secret, err := v.Client.Logical().Read(v.Storage + key)
	if err != nil {
		log.Printf("Error reading secret:%s ", err.Error())
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("Key %s does not exist", key)
	}

	//Converting values to byte
	for i, s := range secret.Data {
		result[i] = []byte(fmt.Sprintf("%v", s))
	}

	return result, nil
}

func (v *Vault) GetPlainConfig(key string) (map[string]interface{}, error) {
	secret, err := v.Client.Logical().Read(v.Storage + key)
	if err != nil {
		log.Printf("Error reading secret:%s ", err.Error())
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("Key %s does not exist", key)
	}

	return secret.Data, nil
}

func (v *Vault) List(key string) (map[string]interface{}, error) {
	secret, err := v.Client.Logical().List(v.Storage + key)
	if err != nil {
		log.Printf("Error reading secret:%s ", err.Error())
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("Key %s does not exist", key)
	}
	return secret.Data, nil

}
