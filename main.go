package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/tidwall/gjson"
)

// SavedFile - Custom file struct
type SavedFile struct {
	OriginalName string `json:"originalName"` // Original name of the file (including the extension)
	StrippedPath string `json:"strippedPath"` // Decrypted file name, why decrypted? good question, We shell never know
	FileID       string `json:"fileID"`       // FileID
}

// User - Custom user struct
type User struct {
	ID      string      `json:"id"`      // ID
	Name    string      `json:"name"`    // username, can be duplicated
	Created string      `json:"created"` // creation date object to string, used as enc/dec key
	Files   []SavedFile `json:"files"`   // Files that the user has
}

// Users - List of Users that are connected (our amazing database)
var Users []User

// Checks if the user cookie is found in the header
func hasUserCookie(r *http.Request) bool {
	userCookie := r.Header.Get("user")

	return userCookie != ""
}

// Retriving the user cookie (can be combined with hasUserCookie in some cases)
func retrieveUserCookie(r *http.Request) string {
	return r.Header.Get("user")
}

// finds the user by the given id (can be combined with hasUserCookie in some cases)
func findUserByID(id string) (User, int) {
	loggedUserIndex := -1
	var selectedUser User

	// Looping the users array to match ids
	if len(Users) != 0 {
		for index, user := range Users {
			if user.ID == id {
				loggedUserIndex = index
				selectedUser = user
			}
		}
	}

	return selectedUser, loggedUserIndex
}

// FindDuplicateFile - Find any files that has the same ORIGINAL NAME, this triggers when trying to insert a file into the a user's database
func FindDuplicateFile(slice []SavedFile, val string) (int, bool) {
	// Looping a SavedFiles array to match original names
	for i, item := range slice {
		if item.OriginalName == val {
			return i, true
		}
	}
	return -1, false
}

// Creating the hash from the user date creation object
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Typical aes encryption
func encrypt(data []byte, passphrase string) []byte {
	// Creates chiper block (AES) with the passphrase (currectly the created time object of user) as key, after hashing
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))

	// GCM operation mode (works well since its a symmetric key cryptographic system)
	// GCM throughput rates for state-of-the-art, high-speed communication channels can be achieved with inexpensive hardware resources
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// nonce array (practically an IV)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// chipering the original data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// Typical aes decryption
func decrypt(data []byte, passphrase string) []byte {
	// Creates AES key from the user created time object (after hasing)
	key := []byte(createHash(passphrase))

	// Creates chiper block (AES) with the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// GCM operation mode (works well since its a symmetric key cryptographic system)
	// GCM throughput rates for state-of-the-art, high-speed communication channels can be achieved with inexpensive hardware resources
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// nonce array (practically an IV)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// decrypting the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func addFileToDatabase(user User, userIndex int, fileName string, file io.Reader) (SavedFile, bool, error) {
	var newFile SavedFile

	// Create a Storage dir incase there is non
	if _, err := os.Stat("storage"); os.IsNotExist(err) {
		os.Mkdir("./storage", os.ModeDir)
	}

	// Create a Storage/userID dir incase there is non
	if _, err := os.Stat("storage/" + user.ID); os.IsNotExist(err) {
		os.Mkdir("./storage/"+user.ID, os.ModeDir)
	}

	// Search if the new file is not a duplication of a currently existing file (name wise)
	_, found := FindDuplicateFile(user.Files, fileName)
	if found {
		// In reality I would just ask the user if he wants to overrride the file.
		fmt.Println("there is already a file with the same name in the database, Sorry pleb, Gonna skip the headache and just disable you from overriding it, sadly delete is the only option")
		return newFile, true, nil
	}

	fmt.Printf("uploading file to user - %v\n", user)

	// Creating a file that will contain the encrypted data
	tempFile, err := ioutil.TempFile("storage/"+user.ID, uuid.NewString())
	if err != nil {
		fmt.Println(err)
		return newFile, false, err
	}
	defer tempFile.Close()

	// Get the files data (bytes wise)
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return newFile, false, err
	}

	fmt.Println(fileBytes)

	// Write the encrypted data into the file we created above
	tempFile.Write(encrypt(fileBytes, user.Created))

	newFile.OriginalName = fileName
	newFile.StrippedPath = tempFile.Name()
	newFile.FileID = filepath.Base(tempFile.Name())

	// Append the file we created above to the list of files the user has
	Users[userIndex].Files = append(user.Files, newFile)

	return newFile, false, err
}

// Upload file function {SHOULD EXPLAIN HERE ALOT ALOT MORE}
func uploadFile(w http.ResponseWriter, r *http.Request) {
	// Check if the usercookies are present
	if hasUserCookie(r) {
		// Find user by id
		loggedUser, loggedUserIndex := findUserByID(retrieveUserCookie(r))
		// Check if user id exists
		if loggedUserIndex == -1 {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, "error finding user with matching id")
			return
		}

		// Read the file from the multipart request
		file, handler, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `error retrieving the file, {Rest only issue: Please make sure the file key in the form-data is actually "file"}`)
			return
		}
		defer file.Close()

		// Add the file to the database (of the passed user)
		newFile, duplicated, err := addFileToDatabase(loggedUser, loggedUserIndex, handler.Filename, file)
		if duplicated {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, `error uploading file, such file already exists, please delete it first`)
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, `error uploading the file`)
			return
		}

		// Return the custom file object that we created (Not sure what file object you meant, but if there
		// is a need to return the golang file struct it can be done)
		json.NewEncoder(w).Encode(newFile)
	} else {
		// Incase there is no user cookie
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "user header missing")
	}
}

// Get user files function, Self expanitory
func getUserFiles(w http.ResponseWriter, r *http.Request) {
	// Check if the usercookies are present
	if hasUserCookie(r) {
		// Find user by id
		loggedUser, loggedUserIndex := findUserByID(retrieveUserCookie(r))
		// Check if user id exists
		if loggedUserIndex == -1 {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, "error finding user with matching id")
			return
		}

		returnedFiles := []SavedFile{}

		// Get the user files if they exists
		// KEEP IN MIND THAT THIS IS A HORRIBLE WAY TO DO THAT, IN PRODUCTION YOU SHOULD ALWAYS LOOP THROUGH THE REAL
		// FILES AND NOT READ FROM A STATIC ARRAY, (incase one file got deleted and the array wont show it, unless the array updates itself on OS modification)
		if len(loggedUser.Files) != 0 {
			returnedFiles = loggedUser.Files
		}

		json.NewEncoder(w).Encode(returnedFiles)
	} else {
		// Incase there is no user cookie
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "user header missing")
	}
}

// Get a specific user file by FileID, Makes sure to decrypt the data before returnning to user
func getUserFile(w http.ResponseWriter, r *http.Request) {
	// Check if the usercookies are present
	if hasUserCookie(r) {
		// Find user by id
		loggedUser, loggedUserIndex := findUserByID(retrieveUserCookie(r))
		// Check if user id exists
		if loggedUserIndex == -1 {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, "error finding user with matching id")
			return
		}

		// Get the id from the router that we are currently using (MUX)
		vars := mux.Vars(r)
		id := vars["id"]

		// loop throught the users files and match id (HUGE WARNNING PLEASE READ LINE 260)
		for _, file := range loggedUser.Files {
			if file.FileID == id {
				data, _ := ioutil.ReadFile(file.StrippedPath)

				// Decrypt the file and return to user
				fmt.Fprintf(w, string(decrypt(data, loggedUser.Created)))
				return
			}
		}

		// Incase the program didnt return in the loop, "something aint right"
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "the logged in user does not have a file with such id")
	} else {
		// Incase there is no user cookie
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "user header missing")
	}
}

// Delete file by FileID
func deleteUserFile(w http.ResponseWriter, r *http.Request) {
	// Check if the usercookies are present
	if hasUserCookie(r) {
		// Find user by id
		loggedUser, loggedUserIndex := findUserByID(retrieveUserCookie(r))
		// Check if user id exists
		if loggedUserIndex == -1 {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, "error finding user with matching id")
			return
		}

		// Get the id from the router that we are currently using (MUX)
		vars := mux.Vars(r)
		id := vars["id"]

		// Loop through the users files array and match by id
		for index, file := range loggedUser.Files {
			if file.FileID == id {
				// Remove the file with the wanted id
				Users[loggedUserIndex].Files = append(Users[loggedUserIndex].Files[:index], Users[loggedUserIndex].Files[index+1:]...)

				// Remove the actual file
				os.Remove(file.StrippedPath)
				fmt.Println("file deleted successfully")
				return
			}
		}

		// Incase the program didnt return in the loop, "something aint right"
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "the logged in user does not have a file with such id")
	} else {
		// Incase there is no user cookie
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "user header missing")
	}
}

// Copy a file to another user (Not sure if that was the main idea of the question, But I'm rolling with it)
func shareFileWithUser(w http.ResponseWriter, r *http.Request) {
	// Check if the usercookies are present
	if hasUserCookie(r) {
		// Convert the user request to a bytes array
		reqBody, _ := ioutil.ReadAll(r.Body)

		// May god forsake this language for not incluing a easier way to get a json key,value
		sharedUserID := gjson.Get(string(reqBody), "user").String()
		sharedFileID := gjson.Get(string(reqBody), "file").String()

		// Sanity check
		if sharedUserID == "" || sharedFileID == "" {
			w.WriteHeader(http.StatusNotAcceptable)
			fmt.Fprintf(w, `"user" key or "file" key are either missing or empty`)
			return
		}

		// Get user by id (our user cookie id)
		loggedUser, loggedUserIndex := findUserByID(retrieveUserCookie(r))
		if loggedUserIndex == -1 {
			w.WriteHeader(http.StatusExpectationFailed)
			fmt.Fprintf(w, "error finding user with matching id")
			return
		}

		var sharedFileObject SavedFile
		var sharedUserObject User
		var sharedUserindex int

		// Get the user that we want to share the file with
		for index, user := range Users {
			if sharedUserID == user.ID {
				sharedUserObject = user
				sharedUserindex = index
			}
		}

		// Get the file that we want to share the user with
		for _, file := range loggedUser.Files {
			if file.FileID == sharedFileID {
				sharedFileObject = file
			}
		}

		// Check if the reciving user dosent have a file with the same name
		_, found := FindDuplicateFile(sharedUserObject.Files, sharedFileObject.OriginalName)
		if found {
			// In reality I would just ask the user if he wants to overrride the file.
			fmt.Println("there is already a file with the same name in the database, Sorry pleb, Gonna skip the headache and just disable you from overriding it, sadly delete is the only option")
			fmt.Fprintf(w, "there is already a file with the same name in the database, Please delete it first")
			return
		}

		// Sanity check
		if sharedUserID == loggedUser.ID {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "cant share a file with yourself")
			return
		}

		if sharedFileObject != (SavedFile{}) && sharedUserObject.ID != "" {
			// Get the encrypted data form the file
			data, _ := ioutil.ReadFile(sharedFileObject.StrippedPath)

			// Decrypt the data that we want to share
			fileData := string(decrypt(data, loggedUser.Created))

			// Create a file with the encrypted data (temp middleman  file)
			tempDecryptedFile, err := ioutil.TempFile("./storage/"+loggedUser.ID, "*")
			if err != nil {
				w.WriteHeader(http.StatusExpectationFailed)
				fmt.Fprintf(w, `error reading file`)
				return
			}
			defer tempDecryptedFile.Close()

			// Write the decrypted data to the temp file
			tempDecryptedFile.Write([]byte(fileData))

			// Open the file with the new decrypted data
			tempFile, err := os.Open(tempDecryptedFile.Name())
			if err != nil {
				w.WriteHeader(http.StatusExpectationFailed)
				fmt.Fprintf(w, `error openning file`)
				return
			}
			defer tempFile.Close()

			// Encrpyt the data with the reciving user passphrase (just like uploadFile function)
			_, duplicated, err := addFileToDatabase(sharedUserObject, sharedUserindex, sharedFileObject.OriginalName, tempFile)
			if duplicated {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprintf(w, `error uploading file, such file already exists, please delete it first`)
				return
			}

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `error uploading the file, {Rest only issue: Please make sure the file key in the form-data is actually "file"}`)
				return
			}

			// Copied successfully, close all the temp files we created, and delete the decrypted file
			fmt.Println("copied file successfully")
			tempDecryptedFile.Close()
			tempFile.Close()
			os.RemoveAll(tempFile.Name())
			return
		}

		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "error while copying file to new location")
	} else {
		// Incase there is no user cookie
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "user header missing")
	}
}

// Get all the users that are registered
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("returning all users - %v\n", Users)

	// Anonymous struct for the users display request
	type displayedUsersStruct struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	displayedUsers := []displayedUsersStruct{}

	// Append to the empty users array
	if len(Users) != 0 {
		for _, user := range Users {
			displayedUsers = append(displayedUsers, displayedUsersStruct{ID: user.ID, Name: user.Name})
		}
	}

	// Send the array to the user
	json.NewEncoder(w).Encode(displayedUsers)
}

// Sign Up function, Creates a new entry in the Users array
func login(w http.ResponseWriter, r *http.Request) {
	// Convert the user request to a bytes array
	reqBody, _ := ioutil.ReadAll(r.Body)

	// Get the "name" key from the request json
	userName := gjson.Get(string(reqBody), "name").String()

	// Sanity check
	if userName == "" {
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, `"name" key is either missing or empty`)
		return
	}

	var user User

	// Create a new user with the recieved data
	user.Name = userName
	user.Created = time.Now().String()
	user.ID = uuid.NewString()
	user.Files = []SavedFile{}

	fmt.Printf("created user - %v\n", user)

	// Return the "user" cookie, if this project also included the frontend site, I will hold it for the next requetst
	w.Header().Set("user", user.ID)

	// Append the user to the users array
	Users = append(Users, user)
}

// Handles router requests
func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/v1/login", login).Methods("POST")
	myRouter.HandleFunc("/v1/users", getAllUsers).Methods("GET")
	myRouter.HandleFunc("/v1/files", uploadFile).Methods("PUT")
	myRouter.HandleFunc("/v1/files", getUserFiles).Methods("GET")
	myRouter.HandleFunc("/v1/files/{id}", getUserFile).Methods("GET")
	myRouter.HandleFunc("/v1/files/{id}", deleteUserFile).Methods("DELETE")
	myRouter.HandleFunc("/v1/files/share", shareFileWithUser).Methods("POST")

	// Serve the routes above
	log.Fatal(http.ListenAndServe(":8081", myRouter))
}

// Start, And also makes sure to listen for termination signals to remove the storage folder that is created at run time
func main() {
	// Makes sure to delete the data after closure (in production it wont be needed becuase we wont use a file array, we will read what is actually on the disk...)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		os.RemoveAll("storage")
		os.Exit(0)
	}()

	// Start the server
	handleRequests()
}
