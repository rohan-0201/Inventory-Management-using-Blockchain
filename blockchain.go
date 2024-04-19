package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Password string
}

type auth struct {
	users map[string]string
	file  string
}

func (am *auth) Initialize() error {
	am.users = make(map[string]string)
	am.file = "user_list.json"

	_, err := os.Stat(am.file)
	if os.IsNotExist(err) {
		emptyJSON := []byte("{}")
		err := os.WriteFile(am.file, emptyJSON, 0644)
		if err != nil {
			return fmt.Errorf("failed to create user list file: %v", err)
		}
	}

	err = am.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %v", err)
	}

	return nil
}

func (am *auth) RegUser(username, password string) error {
	if _, exists := am.users[username]; exists {
		return fmt.Errorf("user already exists")
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing failed: %v", err)
	}

	am.users[username] = string(pwHash)

	if err := am.SaveUsers(); err != nil {
		return fmt.Errorf("failed to save users : %v", err)
	}
	return nil
}

func (am *auth) Authentication(username, password string) bool {
	pwHash, exists := am.users[username]
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password))
	return err == nil
}

func (am *auth) loadUsers() error {
	data, err := os.ReadFile(am.file)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &am.users); err != nil {
		return err
	}
	return nil
}

func (am *auth) SaveUsers() error {
	data, err := json.Marshal(am.users)
	if err != nil {
		return fmt.Errorf("failed to serialize users to JSON : %v", err)
	}
	if err := os.WriteFile(am.file, data, 0600); err != nil {
		return fmt.Errorf("failed to write users : %v", err)
	}
	return nil
}

type Block struct {
	Index                 int
	Timestamp             int64
	PrevHash              string
	Data                  string
	Nonce                 int
	Difficulty            int
	Hash                  string
	InventoryTransactions []InventoryItem
}

type Blockchain struct {
	Chain            []Block
	UserInventories  map[string][]InventoryItem // Map of user inventories
	UserTransactions map[string][]Transaction   // Map of user transaction history
}

type InventoryItem struct {
	ID       int
	Name     string
	Quantity int
}

type Transaction struct {
	Username  string
	Timestamp int64
	Action    string
	Item      InventoryItem
}

var (
	mutex sync.Mutex
)

func calculateHash(b Block) string {
	record := strconv.Itoa(b.Index) +
		strconv.FormatInt(b.Timestamp, 10) +
		b.PrevHash +
		b.Data +
		strconv.Itoa(b.Nonce)

	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

func createGenesisBlock(difficulty int) Block {
	genesisBlock := Block{
		Index:      0,
		Timestamp:  time.Now().Unix(),
		PrevHash:   "0",
		Data:       "Genesis Block",
		Nonce:      0,
		Difficulty: difficulty,
	}

	genesisBlock.Hash = calculateHash(genesisBlock)
	return genesisBlock
}

func createNewBlock(previousBlock Block, data string, difficulty int, inventoryTransactions []InventoryItem) Block {
	newBlock := Block{
		Index:                 previousBlock.Index + 1,
		Timestamp:             time.Now().Unix(),
		PrevHash:              previousBlock.Hash,
		Data:                  data,
		Nonce:                 0,
		Difficulty:            difficulty,
		InventoryTransactions: inventoryTransactions,
	}

	newBlock.Hash = calculateHash(newBlock)

	return newBlock
}

func (bc *Blockchain) Initialize() {
	bc.UserInventories = make(map[string][]InventoryItem)
	bc.UserTransactions = make(map[string][]Transaction)
}

func addInventoryItem(blockchain *Blockchain, username, name string, quantity int) {
	mutex.Lock()
	defer mutex.Unlock()

	if blockchain.UserInventories == nil {
		blockchain.UserInventories = make(map[string][]InventoryItem)
	}

	userInventory := blockchain.UserInventories[username]
	if userInventory == nil {
		userInventory = []InventoryItem{}
	}

	newItem := InventoryItem{
		ID:       len(userInventory) + 1,
		Name:     name,
		Quantity: quantity,
	}
	blockchain.UserInventories[username] = append(userInventory, newItem)

	if blockchain.UserTransactions == nil {
		blockchain.UserTransactions = make(map[string][]Transaction)
	}

	userTransactions := blockchain.UserTransactions[username]
	if userTransactions == nil {
		userTransactions = []Transaction{}
	}

	transaction := Transaction{
		Username:  username,
		Timestamp: time.Now().Unix(),
		Action:    "add",
		Item:      newItem,
	}

	blockchain.UserTransactions[username] = append(userTransactions, transaction)

	transactionTime := time.Unix(transaction.Timestamp, 0).Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s added to inventory: %s (Quantity: %d)\n", transactionTime, username, newItem.Name, newItem.Quantity)

	saveUserTransactions(username, blockchain.UserTransactions[username])
}

func removeInventoryItem(blockchain *Blockchain, username string, id, quantity int) {
	mutex.Lock()
	defer mutex.Unlock()

	if blockchain.UserInventories == nil {
		blockchain.UserInventories = make(map[string][]InventoryItem)
	}

	userInventory, exists := blockchain.UserInventories[username]
	if !exists {
		fmt.Println("User inventory not found.")
		return
	}

	var foundItem *InventoryItem
	for i, item := range userInventory {
		if item.ID == id {
			foundItem = &userInventory[i]
			break
		}
	}

	if foundItem == nil {
		fmt.Println("Item not found in user inventory.")
		return
	}

	if quantity > foundItem.Quantity {
		fmt.Println("Cannot remove more quantity than available.")
		return
	}

	foundItem.Quantity -= quantity

	prevBlock := blockchain.Chain[len(blockchain.Chain)-1]
	prevBlock.InventoryTransactions = append(prevBlock.InventoryTransactions, *foundItem)

	newBlock := createNewBlock(prevBlock, "Inventory updated", prevBlock.Difficulty, prevBlock.InventoryTransactions)
	blockchain.Chain = append(blockchain.Chain, newBlock)

	transaction := Transaction{
		Username:  username,
		Timestamp: time.Now().Unix(),
		Action:    "remove",
		Item:      *foundItem,
	}
	blockchain.UserTransactions[username] = append(blockchain.UserTransactions[username], transaction)

	saveUserTransactions(username, blockchain.UserTransactions[username])

	transactionTime := time.Unix(transaction.Timestamp, 0).Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s removed from inventory: %s (Quantity: %d)\n", transactionTime, username, foundItem.Name, quantity)
}

func viewInventory(blockchain *Blockchain, username string) {
	fmt.Printf("\n-------------------\nCurrent Inventory:")
	userInventory := blockchain.UserInventories[username]
	for _, item := range userInventory {
		fmt.Printf("ID: %d, Name: %s, Quantity: %d\n", item.ID, item.Name, item.Quantity)
	}

	fmt.Println("-------------------")

}

func viewBlockchain(blockchain *Blockchain, username string) {
	fmt.Println("-------------------")
	userInventory := blockchain.UserInventories[username]
	fmt.Println("Blockchain:")
	if len(blockchain.Chain) > 0 {
		lastBlock := blockchain.Chain[len(blockchain.Chain)-1]
		fmt.Printf("Timestamp: %d\n", lastBlock.Timestamp)
		fmt.Printf("PrevHash: %s\n", lastBlock.PrevHash)
		fmt.Printf("Data: %s\n", lastBlock.Data)
		fmt.Printf("Hash: %s\n", lastBlock.Hash)
		fmt.Println("Inventory Transactions:")
		for _, item := range lastBlock.InventoryTransactions {
			if itemExistsInUserInventory(userInventory, item) {
				fmt.Printf("ID: %d, Name: %s, Quantity: %d\n", item.ID, item.Name, item.Quantity)
			}
		}
		fmt.Println("-------------------")
	} else {
		fmt.Println("Blockchain is empty.")
	}
}

func itemExistsInUserInventory(userInventory []InventoryItem, item InventoryItem) bool {
	for _, invItem := range userInventory {
		if invItem.ID == item.ID && invItem.Name == item.Name {
			return true
		}
	}
	return false
}

func auditBlockchain(blockchain *Blockchain) {
	fmt.Println("Auditing blockchain...")

	for i := 1; i < len(blockchain.Chain); i++ {
		prevBlock := blockchain.Chain[i-1]
		currBlock := blockchain.Chain[i]

		if currBlock.PrevHash != calculateHash(prevBlock) {
			fmt.Printf("Block %d is corrupted!\n", currBlock.Index)
			return
		}

		if currBlock.Hash != calculateHash(currBlock) {
			fmt.Printf("Block %d is corrupted!\n", currBlock.Index)
			return
		}
	}

	fmt.Println("Blockchain audit passed successfully!")
}

func logTransactions(blockchain *Blockchain, username string) {
	fmt.Println("Transaction History:")
	userTransactions := blockchain.UserTransactions[username]

	currentQuantities := make(map[string]int)

	for _, transaction := range userTransactions {
		quantityChange := 0

		switch transaction.Action {
		case "add":
			quantityChange = transaction.Item.Quantity
			currentQuantities[transaction.Item.Name] += transaction.Item.Quantity
		case "remove":
			quantityChange = transaction.Item.Quantity
			currentQuantities[transaction.Item.Name] -= transaction.Item.Quantity
		}

		transactionTime := time.Unix(transaction.Timestamp, 0).Format("2006-01-02 15:04:05")
		fmt.Printf("[%s] [%s] %s %d %s (Current Quantity: %d)\n", transactionTime, username, transaction.Action, currentQuantities[transaction.Item.Name], transaction.Item.Name, quantityChange)
	}
}

func saveBlockchain(blockchain *Blockchain) {
	mutex.Lock()
	defer mutex.Unlock()

	data, err := json.Marshal(blockchain)
	if err != nil {
		fmt.Println("Error marshalling blockchain:", err)
		return
	}
	err = os.WriteFile("blockchain.json", data, 0644)
	if err != nil {
		fmt.Println("Error writing blockchain to file:", err)
		return
	}
	fmt.Println("Blockchain saved to file.")
}

func loadBlockchain() Blockchain {
	var blockchain Blockchain
	data, err := os.ReadFile("blockchain.json")
	if err != nil {
		fmt.Println("Error reading blockchain file:", err)
		return blockchain
	}
	err = json.Unmarshal(data, &blockchain)
	if err != nil {
		fmt.Println("Error unmarshalling blockchain:", err)
		return blockchain
	}
	fmt.Println("Blockchain loaded from file.")
	return blockchain
}

func updateListener(blockchain *Blockchain, username, itemName string) {
	for {
		time.Sleep(1 * time.Minute)

		mutex.Lock()
		latestBlock := blockchain.Chain[len(blockchain.Chain)-1]
		mutex.Unlock()

		userUpdates := make(map[string]int)

		for _, item := range latestBlock.InventoryTransactions {
			if item.Name == itemName {
				userUpdates[item.Name] = item.Quantity
			}
		}

		mutex.Lock()
		userInventory := blockchain.UserInventories[username]
		mutex.Unlock()

		fmt.Printf("\n-------------------\nReal-Time Inventory Updates for User %s - Item %s:\n", username, itemName)

		for _, invItem := range userInventory {
			if invItem.Name == itemName {
				fmt.Printf("%s: %d\n", itemName, invItem.Quantity)
				break
			}
		}

		fmt.Println("-------------------")
	}
}

// Load user transaction history from a JSON file
func loadUserTransactions(username string) []Transaction {
	filename := username + "_transactions.json"
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading user transaction file:", err)
		return nil
	}
	var transactions []Transaction
	err = json.Unmarshal(data, &transactions)
	if err != nil {
		fmt.Println("Error unmarshalling user transactions:", err)
		return nil
	}
	return transactions
}

// Save user transaction history to a JSON file
func saveUserTransactions(username string, transactions []Transaction) {
	filename := username + "_transactions.json"
	data, err := json.Marshal(transactions)
	if err != nil {
		fmt.Println("Error marshalling user transactions:", err)
		return
	}
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("Error writing user transactions to file:", err)
		return
	}
}

func main() {
	auth := &auth{}
	err := auth.Initialize()
	if err != nil {
		fmt.Println("Error initializing authentication:", err)
		return
	}

	var username, password string

	for {
		var userChoice string
		fmt.Println("1. Login")
		fmt.Println("2. Signup")
		fmt.Println("3. Exit")
		fmt.Print("Enter your choice: ")
		fmt.Scanln(&userChoice)

		switch userChoice {
		case "1":
			fmt.Print("Enter username: ")
			fmt.Scanln(&username)
			fmt.Print("Enter password: ")
			fmt.Scanln(&password)

			if !auth.Authentication(username, password) {
				fmt.Println("Authentication failed. Access denied.")
				continue
			}

			fmt.Println("Login successful!")
			mainMenu(&auth, &username)

		case "2":
			fmt.Print("Enter username for registration: ")
			fmt.Scanln(&username)
			fmt.Print("Enter password for registration: ")
			fmt.Scanln(&password)

			err := auth.RegUser(username, password)
			if err != nil {
				fmt.Println("Failed to register:", err)
				continue
			}

			fmt.Println("Registration successful!")

		case "3":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func mainMenu(auth **auth, username *string) {
	difficulty := 3
	var blockchain Blockchain
	blockchain.Initialize()
	if _, err := os.Stat("blockchain.json"); os.IsNotExist(err) {
		blockchain = Blockchain{
			Chain:            []Block{createGenesisBlock(difficulty)},
			UserInventories:  make(map[string][]InventoryItem),
			UserTransactions: make(map[string][]Transaction),
		}
	} else {
		blockchain = loadBlockchain()
	}

	userInventory := blockchain.UserInventories[*username]
	for _, item := range userInventory {
		go updateListener(&blockchain, *username, item.Name)
	}

	for {
		var choice int
		fmt.Println("1.Add item to inventory")
		fmt.Println("2.Remove item from inventory")
		fmt.Println("3.View inventory")
		fmt.Println("4.Audit blockchain")
		fmt.Println("5.View transaction history")
		fmt.Println("6.View Blockchain")
		fmt.Println("7.Logout")
		fmt.Print("Enter your choice: ")
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			var name string
			var quantity int
			fmt.Print("Enter item name: ")
			fmt.Scanln(&name)
			fmt.Print("Enter item quantity: ")
			fmt.Scanln(&quantity)
			addInventoryItem(&blockchain, *username, name, quantity)
			saveBlockchain(&blockchain)
			fmt.Println("Item added to inventory.")

		case 2:
			var id int
			var quantityToRemove int
			fmt.Print("Enter item ID to remove: ")
			fmt.Scanln(&id)
			fmt.Print("Enter quantity to remove: ")
			fmt.Scanln(&quantityToRemove)
			removeInventoryItem(&blockchain, *username, id, quantityToRemove)
			saveBlockchain(&blockchain)
			fmt.Println("Item quantity updated in inventory.")

		case 3:
			viewInventory(&blockchain, *username)

		case 4:
			auditBlockchain(&blockchain)

		case 5:
			logTransactions(&blockchain, *username)

		case 6:
			viewBlockchain(&blockchain, *username)

		case 7:
			fmt.Println("Logging out...")
			return // Exit the main menu loop and return to login/signup

		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
