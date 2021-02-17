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
	Storage  string
	Address  string
	Insecure bool
	Config   *api.Config
	Client   *api.Client
}

func (v *Vault) setAddress() {
	v.Address = os.Getenv("VAULT_ADDR")
	if len(v.Address) < 1 {
		v.Address = "127.0.0.1"
	}
}

func (v *Vault) setInsecure() {
	var err error
	v.Insecure, err = strconv.ParseBool((os.Getenv("VAULT_INSECURE")))
	if err != nil {
		log.Println("Error getting VAULT_INSECURE value: %s, setting to false ", err)
		v.Insecure = false
	}
}

func (v *Vault) setStorage() {

	v.Storage = os.Getenv("VAULT_STORAGE")

	if len(v.Storage) < 1 {
		v.Storage = "secret/"
	}

	if !strings.HasSuffix(v.Storage, "/") {
		v.Storage = v.Storage + "/"
	}
}

//Init - initialize vault object - creates connection and empty key structure
func (v *Vault) Init() error {
	v.setAddress()
	v.setInsecure()
	v.setStorage()
	v.Config = new(api.Config)
	v.Client = new(api.Client)

	v.Config.Address = v.Address
	v.Config.ConfigureTLS(&api.TLSConfig{Insecure: v.Insecure})

	var err error

	v.Client, err = api.NewClient(v.Config)
	if err != nil {
		log.Println("Error connecting to Vault: ", err)
		return err
	}
	v.Client.SetToken(os.Getenv("VAULT_TOKEN"))
	
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
