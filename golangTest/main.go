package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const userFile = "users.json"

type Users map[string]string

func loadUsers() Users {
	file, err := os.Open(userFile)
	if err != nil {
		return Users{}
	}
	defer file.Close()

	users := Users{}
	json.NewDecoder(file).Decode(&users)
	return users
}

func saveUsers(users Users) {
	file, err := os.Create(userFile)
	if err != nil {
		fmt.Println("Error saving users:", err)
		return
	}
	defer file.Close()
	json.NewEncoder(file).Encode(users)
}

func hashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func register(username, password string) string {
	users := loadUsers()
	if _, exists := users[username]; exists {
		return "User already exists."
	}
	users[username] = hashPassword(password)
	saveUsers(users)
	return fmt.Sprintf("User '%s' registered successfully!", username)
}

func login(username, password string) string {
	users := loadUsers()
	hashed := hashPassword(password)
	if stored, exists := users[username]; !exists {
		return "User not found."
	} else if stored != hashed {
		return "Invalid password."
	}
	return fmt.Sprintf("Welcome back, %s!", username)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Go GitHub Collaboration Auth Demo ===")

	for {
		fmt.Print("\nOptions: register | login | quit\n> ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "quit" {
			break
		}

		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)

		fmt.Print("Password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		switch choice {
		case "register":
			fmt.Println(register(username, password))
		case "login":
			fmt.Println(login(username, password))
		default:
			fmt.Println("Invalid option.")
		}
	}
}
