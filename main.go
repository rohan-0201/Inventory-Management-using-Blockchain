package main

import (
	"fmt"

	"encoding/json"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/bcrypt"
)

/*
1. While loop implementation possibly????
2. Storing all user regs in a file maybe?????
*/

/*
Using bcrypt hashing for passwords because apparently its one of the safest and go itself provides some additional security bs bs
i didnt go thru it much so dw you want then most welcome go reasearch
*/

// Creating a user structure, for all the usrer
type User struct {
	Username string
	Password string
}

// creates a structure for managing authentication
type auth struct {
	users map[string]string
	file  string
}

// init "auth" struct
func (am *auth) Initialize(filePath string) {
	am.users = make(map[string]string)
	am.file = filePath
	am.loadUsers()
}

// here register users
func (am *auth) RegUser(username, password string) error {
	if _, exists := am.users[username]; exists {
		return fmt.Errorf("user already exists")
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) //Hashing user passwords
	if err != nil {
		return fmt.Errorf("hashing failed: %v", err)
	}

	am.users[username] = string(pwHash) //Store pw

	if err := am.SaveUsers(); err != nil {
		return fmt.Errorf("failed to save users : %v", err)
	}
	return nil
}

// auth process happens by comparing pw with database
func (am *auth) Authentication(username, password string) bool {
	pwHash, exists := am.users[username]
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password))
	return err == nil
}

func (am *auth) loadUsers() {
	data, err := ioutil.ReadFile(am.file)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Println("Failed to load users from file : ", err)
		return
	}

	if err := json.Unmarshal(data, &am.users); err != nil {
		fmt.Println("Failed to parse user data from file : ", err)
	}
}

func (am *auth) SaveUsers() error {
	data, err := json.Marshal(am.users)
	if err != nil {
		return fmt.Errorf("failed to serialize users to JSON : %v", err)
	}
	if err := ioutil.WriteFile(am.file, data, 0600); err != nil {
		return fmt.Errorf("failed to write users : %v", err)
	}
	return nil
}

func main() {
	filePath := "/Users/rohan/Documents/Programming/GO-mini-proj/user_list.json"

	//init auth
	auth := &auth{}
	auth.Initialize(filePath)

	//Registeration

	/*username := "user1"
	password := "password"*/

	fmt.Print("Enter username for registration:")
	var username string
	fmt.Scanln(&username)

	fmt.Print("Enter password for registration:")
	var password string
	fmt.Scanln(&password)
	err := auth.RegUser(username, password)
	if err != nil {
		fmt.Println("Failed : ", err)
		return
	}
	fmt.Println("Successfully Registered macha!")

	//authentication
	fmt.Print("Enter username for authentications:")
	fmt.Scanln(&username)
	fmt.Print("Enter password for authentications:")
	fmt.Scanln(&password)

	/*authenticate := auth.Authentication(username, password)
	if authenticate {
		fmt.Println("Authenticated successfully")
	} else {
		fmt.Println("Failed.")
	}*/

	if auth.Authentication(username, password) {
		fmt.Println("Successful boss")
	} else {
		fmt.Println("Failed")
	}
}
