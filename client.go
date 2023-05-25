package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	MyUUID uuid.UUID
	Username string
	Salt []byte
	PasswordHash []byte
	EncPrivateKey []byte
	EncSignKey []byte
	VerifiedSig []byte
	raw_password string
}

type ShareNode struct{
	MyUUID uuid.UUID
	ChildrenList []uuid.UUID
	InvitationPtr uuid.UUID
	IsOwner bool
	// Use Signature to verify the integrity of the data
	Signature []byte
}


type Invitation struct{
	MyUUID uuid.UUID
	SharePtr uuid.UUID
	InviterName string
	EncDecodeKey []byte
	EncInviteeName []byte
	EncFileRoot []byte
	EncHMACKeyRoot []byte
	EncHMACInvKey []byte
	HMAC []byte
}

type FileMeta struct{
	MyUUID uuid.UUID
	EncContent []byte
	HMAC []byte
}

type FileCount struct{
	MyUUID uuid.UUID
	Num int 
	HMAC []byte
}


func InitUser(username string, password string) (userdataptr *User, err error) {

	// Return an error if username is empty
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	
	var userdata User
	userdata.Username = username
	userdata.raw_password = password

	// Generate a random salt
	userdata.Salt = userlib.RandomBytes(16)

	// Hash the password with the salt
	userdata.PasswordHash = userlib.Argon2Key([]byte(password), userdata.Salt, 16)
	
	// Generate a RSA private/public keypair rsa_pk and rsa_sk
	var rsa_pk userlib.PKEEncKey
	var rsa_sk userlib.PKEDecKey
	rsa_pk, rsa_sk, err = userlib.PKEKeyGen()
	if err != nil {
		return &userdata, err
	}

	// Generate a Signature private/public keypair dsa_pk and dsa_sk
	var dsa_pk userlib.DSVerifyKey
	var dsa_sk userlib.DSSignKey
	dsa_sk, dsa_pk, err = userlib.DSKeyGen()
	if err != nil {
		return &userdata, err
	}

	source_key := userlib.Hash([]byte(password))[:16]

	// Encrypt the RSA private key, and store it in the User struct
	var iv []byte
	var key_for_enc []byte
	iv = userlib.RandomBytes(16)
	key_for_enc, err = userlib.HashKDF(source_key, []byte("EncPrivate"))
	if err != nil {
		return &userdata, err
	}
	rsa_sk_bytes, err := json.Marshal(rsa_sk)
	if err != nil {
		return &userdata, err
	}
	enc_rsa_sk := userlib.SymEnc(key_for_enc[:16], iv, rsa_sk_bytes)
	userdata.EncPrivateKey = enc_rsa_sk


	// Encrypt the Signature private key, and store it in the User struct
	var iv2 []byte
	var key_for_enc2 []byte
	iv2 = userlib.RandomBytes(16)
	key_for_enc2, err = userlib.HashKDF(source_key, []byte("EncSign"))
	if err != nil {
		return &userdata, err
	}
	dsa_sk_bytes, err := json.Marshal(dsa_sk)
	if err != nil {
		return &userdata, err
	}
	enc_dsa_sk := userlib.SymEnc(key_for_enc2[:16], iv2, dsa_sk_bytes)
	userdata.EncSignKey = enc_dsa_sk

	// Generate UUID
	var user_uuid uuid.UUID
	user_uuid, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return &userdata, err
	}
	userdata.MyUUID = user_uuid

	// Sign all the fields in the User struct, and store the signature in the User struct
	fields_combined := user_uuid.String() + userdata.Username + string(userdata.Salt) + string(userdata.PasswordHash) + string(userdata.EncPrivateKey) + string(userdata.EncSignKey)
	signature, err := userlib.DSSign(dsa_sk, []byte(fields_combined))
	if err != nil {
		return &userdata, err
	}
	userdata.VerifiedSig = signature

	// Store the keys in the keystore
	userlib.KeystoreSet(username + "/rsa_pk", rsa_pk)
	userlib.KeystoreSet(username + "/dsa_pk", dsa_pk)

	// Return an error if the user already exists in the datastore
	_, ok := userlib.DatastoreGet(user_uuid)
	if ok {
		return &userdata, errors.New("User already exists.")
	}

	// Store the User struct in the datastore under the uuid generated from the username
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}
	userlib.DatastoreSet(user_uuid, userdata_bytes)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Generate UUID
	var user_uuid uuid.UUID
	user_uuid, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16]) //don't need to check err because the length is fixed

	//Error if there is no initialized user for the given username.
	userdata_bytes, ok := userlib.DatastoreGet(user_uuid);
	if !ok {
		return nil, errors.New("User does not exist.")
	}

	// unMarshal user struct
	var userdata User
	err = json.Unmarshal(userdata_bytes, &userdata)
	userdataptr = &userdata
	if err != nil {
		return nil, err
	}

	if userdata.MyUUID != user_uuid {
		return nil, errors.New("User struct UUID unmatch.")
	}

	//Find dsa_pk in key store by username
	var dsa_pk userlib.DSVerifyKey
	dsa_pk, ok = userlib.KeystoreGet(username + "/dsa_pk")
	if !ok {
		return nil, errors.New("User does not exist.")
	}

	//Error if the user sturct is tampered.
	fields_combined := userdata.MyUUID.String() + userdata.Username + string(userdata.Salt) + string(userdata.PasswordHash) + string(userdata.EncPrivateKey) + string(userdata.EncSignKey)
	signature := userdata.VerifiedSig
	err = userlib.DSVerify(dsa_pk, []byte(fields_combined), signature)
	if err != nil{
		return nil, errors.New("The User struct cannot be obtained due to malicious action, or the integrity of the user struct has been compromised.")
	}

	// Error if the user credentials are invalid.
	new_PasswordHash := userlib.Argon2Key([]byte(password), userdata.Salt, 16)
	if string(new_PasswordHash) != string(userdata.PasswordHash) {
		return nil, errors.New("Invalid password.")
	}
	// should we check the credential by just comparing the raw_passwaord with the input password?
	userdata.raw_password = password
	return userdataptr, nil
}


func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// check if the file is existed, if existed, overwrite it
	check_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	check_shareNode_bytes, ok := userlib.DatastoreGet(check_uuid)
	if ok {
		var check_shareNode ShareNode
		err = json.Unmarshal(check_shareNode_bytes, &check_shareNode)
		if err != nil {
			return err
		}
		userlib.DebugMsg("children: %v in store", check_shareNode.ChildrenList)
		if check_shareNode.MyUUID != check_uuid {
			return errors.New("ShareNode struct UUID unmatch.")
		}
		// find the invitation struct
		var check_invitation Invitation
		check_invitation_bytes, ok := userlib.DatastoreGet(check_shareNode.InvitationPtr)
		if !ok {
			return errors.New("The invitation struct cannot be obtained due to malicious action, or the integrity of the invitation struct has been compromised.")
		}
		err = json.Unmarshal(check_invitation_bytes, &check_invitation)
		if err != nil {
			return err
		}
		if check_shareNode.InvitationPtr != check_invitation.MyUUID {
			return errors.New("Invitation struct UUID unmatch.")
		}
		// decrypt the decode key using the private key of the user
		rsa_sk := userdata.get_privateKey()
		decode_key, err := userlib.PKEDec(rsa_sk, check_invitation.EncDecodeKey)
		if err != nil {
			return err
		}
		// find the first filemeta struct
		var check_filemeta FileMeta
		// find the uuid of the first filemeta struct
		file_root, err := userlib.PKEDec(rsa_sk, check_invitation.EncFileRoot)
		if err != nil {
			return err
		}
		check_filemeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(0)))[:16])
		if err != nil {
			return err
		}
		check_filemeta_bytes, ok := userlib.DatastoreGet(check_filemeta_uuid)
		if !ok {
			return errors.New("The filemeta struct cannot be obtained due to malicious action, or the integrity of the filemeta struct has been compromised.")
		}
		err = json.Unmarshal(check_filemeta_bytes, &check_filemeta)
		if err != nil {
			return err
		}
		if check_filemeta.MyUUID != check_filemeta_uuid {
			return errors.New("FileMeta struct UUID unmatch.")
		}

		// find the filecount struct
		var check_filecount FileCount
		// find the uuid of the filecount struct
		check_filecount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
		if err != nil {
			return err
		}
		check_filecount_bytes, ok := userlib.DatastoreGet(check_filecount_uuid)
		if !ok {
			return errors.New("The filecount struct cannot be obtained due to malicious action, or the integrity of the filecount struct has been compromised.")
		}
		err = json.Unmarshal(check_filecount_bytes, &check_filecount)
		if err != nil {
			return err
		}
		if check_filecount.MyUUID != check_filecount_uuid {
			return errors.New("FileCount struct UUID unmatch.")
		}

		// encrypt the new content using the decode key
		iv_check := userlib.RandomBytes(16)
		enccontent := userlib.SymEnc(decode_key, iv_check, content)
		check_filemeta.EncContent = enccontent
		// use privatekey to decrypt the hmac keyroot in the invitation struct
		var keyroot []byte
		keyroot = userlib.SymDec(decode_key, check_invitation.EncHMACKeyRoot)
		if err != nil {
			return err
		}
		// calculate the hmac key of the filemeta struct
		check_filemeta_hmac_keyroot := userlib.Hash(append(keyroot,[]byte("FileMeta")...))[:16]
		success := calculate_filemeta_hmac(&check_filemeta, check_filemeta_uuid, check_filemeta_hmac_keyroot)
		if !success {
			return errors.New("Failed to update hmac.")
		}

		// update the num in the filecount struct
		// calculate the hmac key of the filecount struct
		check_filecount.Num = 0
		check_filecount_hmac_keyroot := userlib.Hash(append(keyroot,[]byte("FileCount")...))[:16]
		success = calculate_filecount_hmac(&check_filecount, check_filecount_uuid, check_filecount_hmac_keyroot)
		if !success {
			return errors.New("Failed to update hmac.")
		}
		return nil
	}

	// if not, create a new file
	// Create ShareNode struct and do initialization
	var shareNode ShareNode
	shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	shareNode.MyUUID = shareNode_uuid
	shareNode.ChildrenList = make([]uuid.UUID, 0)
	invitation_uuid := uuid.New()
	shareNode.InvitationPtr = invitation_uuid
	shareNode.IsOwner = true
	var childrenList_bytes []byte
	childrenList_bytes, err = json.Marshal(shareNode.ChildrenList)
	if err != nil {
		return err
	}
	fields_combined := shareNode.MyUUID.String() + string(childrenList_bytes) + shareNode.InvitationPtr.String() + strconv.FormatBool(shareNode.IsOwner)
	dsa_sk := userdata.get_dsaKey()
	shareNode.Signature, err = userlib.DSSign(dsa_sk, []byte(fields_combined))
	if err != nil {
		return err
	}
	// Store the ShareNode struct in the datastore under the uuid generated from the username/filename
	shareNode_bytes, err := json.Marshal(shareNode)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(shareNode_uuid, shareNode_bytes)

	// Create Invitation struct and do initialization
	var invitation Invitation
	invitation.MyUUID = invitation_uuid
	invitation.SharePtr = shareNode_uuid
	invitation.InviterName = userdata.Username
	decode_key := userlib.RandomBytes(16)
	// use user's public key to encrypt the decode key
	rsa_pk, ok := userlib.KeystoreGet(userdata.Username + "/rsa_pk")
	if !ok {
		return errors.New("User does not exist.")
	}
	invitation.EncDecodeKey, err = userlib.PKEEnc(rsa_pk, decode_key)
	if err != nil {
		return err
	}
	// use decode_key to encrypt the invitee name
	iv := userlib.RandomBytes(16)
	invitation.EncInviteeName = userlib.SymEnc(decode_key, iv, []byte(userdata.Username))
	// user user's public key to encrypt the random generated FileRoot
	fileRoot := userlib.RandomBytes(16)
	invitation.EncFileRoot, err = userlib.PKEEnc(rsa_pk, fileRoot)
	if err != nil {
		return err
	}
	// use decode_key to encrypt the random generated HMACKeyRoot
	hmacKeyRoot := userlib.RandomBytes(16)
	invitation.EncHMACKeyRoot = userlib.SymEnc(decode_key, userlib.RandomBytes(16), hmacKeyRoot)
	// use decode_key to encrypt the random generated HMACInvKey
	hmacInvKey := userlib.RandomBytes(16)
	invitation.EncHMACInvKey = userlib.SymEnc(decode_key, userlib.RandomBytes(16), hmacInvKey)

	sucess := calculate_inv_hmac(&invitation, invitation_uuid, hmacInvKey)
	if !sucess {
		return errors.New("Failed to store/calculate invitation hmac.")
	}

	// Create FileMeta struct and do initialization
	var fileMeta FileMeta
	// encrypt content of the file using decode key (symmetric encryption)
	iv3 := userlib.RandomBytes(16)
	// generate uuid from the file root
	file_root, err := userlib.PKEDec(userdata.get_privateKey(), invitation.EncFileRoot)
	fileMeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(0)))[:16])
	if err != nil {
		return err
	}
	fileMeta.MyUUID = fileMeta_uuid
	fileMeta.EncContent = userlib.SymEnc(decode_key, iv3, content)
	// get the HMACKeyRoot and append the string "FileMeta"; first 16 hashed bytes as key to generate HMAC of fields in this struct
	hmacFileMetaKey := userlib.Hash(append(hmacKeyRoot,[]byte("FileMeta")...))[:16]
	success := calculate_filemeta_hmac(&fileMeta, fileMeta_uuid, hmacFileMetaKey)
	if !success {
		return errors.New("Failed to calculate HMAC of FileMeta")
	}
	
	// Create FileCount struct and do initialization
	var fileCount FileCount
	// generate uuid from the file root
	fileCount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
	if err != nil {
		return err
	}
	fileCount.MyUUID = fileCount_uuid
	fileCount.Num = 0
	hmacFileCountKey := userlib.Hash(append(hmacKeyRoot, []byte("FileCount")...))[:16]
	success = calculate_filecount_hmac(&fileCount, fileCount_uuid, hmacFileCountKey)
	if !success {
		return errors.New("Failed to calculate HMAC of FileCount struct.")
	}

	return
}


func (userdata *User) AppendToFile(filename string, content []byte) error {
	// get the ShareNode struct from the datastore
	shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	shareNode_bytes, ok := userlib.DatastoreGet(shareNode_uuid)
	if !ok {
		return errors.New("File does not exist.")
	}
	var shareNode ShareNode
	err = json.Unmarshal(shareNode_bytes, &shareNode)
	if err != nil {
		return err
	}
	// verify the shareNode
	err = verify_shareNode(userdata.Username, &shareNode, shareNode_uuid)
	if err != nil {
		return err
	}

	// get the Invitation struct from the datastore
	invitation_uuid := shareNode.InvitationPtr
	var invitation Invitation
	invitation_bytes, ok := userlib.DatastoreGet(invitation_uuid)
	if !ok {
		return errors.New("Invitation does not exist.")
	}
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return err
	}
	// verify the invitation
	success := userdata.verify_invitation(&invitation, invitation_uuid)
	if !success {
		return errors.New("Invitation is not valid due to tampering.")
	}

	// get the FileCount struct from the datastore
	file_root, err := userlib.PKEDec(userdata.get_privateKey(), invitation.EncFileRoot)
	fileCount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
	if err != nil {
		return err
	}
	fileCount_bytes, ok := userlib.DatastoreGet(fileCount_uuid)
	if !ok {
		return errors.New("FileCount does not exist.")
	}
	var fileCount FileCount
	err = json.Unmarshal(fileCount_bytes, &fileCount)
	if err != nil {
		return err
	}
	// verify the fileCount
	success = userdata.verify_filecount(&fileCount, fileCount_uuid, &invitation)
	if !success {
		return errors.New("FileCount is not valid due to tampering.")
	}

	// go through the filemeta structs and verify them
	for i := 0; i <= fileCount.Num; i++ {
		// get the FileMeta struct from the datastore
		fileMeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(i)))[:16])
		if err != nil {
			return err
		}
		fileMeta_bytes, ok := userlib.DatastoreGet(fileMeta_uuid)
		if !ok {
			return errors.New("FileMeta does not exist.")
		}
		var fileMeta FileMeta
		err = json.Unmarshal(fileMeta_bytes, &fileMeta)
		if err != nil {
			return err
		}
		// verify the fileMeta
		err = userdata.verify_filemeta(&fileMeta, fileMeta_uuid, &invitation)
		if err != nil {
			return err
		}
	}

	// create a new FileMeta struct and do initialization
	var fileMeta FileMeta
	// decrypt the decode key using the private key of the user
	// get the private key of the user
	rsa_sk := userdata.get_privateKey()
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	if err != nil {
		return err
	}
	// encrypt content of the file using decode key (symmetric encryption)
	iv3 := userlib.RandomBytes(16)
	fileMeta.EncContent = userlib.SymEnc(decode_key, iv3, content)
	// get the HMACKeyRoot and append the string "FileMeta";
	var keyroot []byte
	keyroot = userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	if err != nil {
		return err
	}
	hmacFileMetaKey := userlib.Hash(append(keyroot, []byte("FileMeta")...))[:16]
	filemeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(fileCount.Num + 1)))[:16])
	if err != nil {
		return err
	}
	fileMeta.MyUUID = filemeta_uuid
	calculate_filemeta_hmac(&fileMeta, filemeta_uuid, hmacFileMetaKey)

	// update the fileCount struct
	fileCount.Num += 1
	hmacFileCountKey := userlib.Hash(append(keyroot, []byte("FileCount")...))[:16]
	calculate_filecount_hmac(&fileCount, fileCount_uuid, hmacFileCountKey)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// get the ShareNode struct from the datastore
	shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return nil, err
	}
	shareNode_bytes, ok := userlib.DatastoreGet(shareNode_uuid)
	if !ok {
		return nil, errors.New("File does not exist.")
	}
	var shareNode ShareNode
	err = json.Unmarshal(shareNode_bytes, &shareNode)
	if err != nil {
		return nil, err
	}
	// verify the shareNode
	err = verify_shareNode(userdata.Username, &shareNode, shareNode_uuid)
	if err != nil {
		return nil, err
	}

	// get the Invitation struct from the datastore
	invitation_uuid := shareNode.InvitationPtr
	var invitation Invitation
	invitation_bytes, ok := userlib.DatastoreGet(invitation_uuid)
	if !ok {
		return nil, errors.New("Invitation does not exist.")
	}
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return nil, err
	}
	// verify the invitation
	success := userdata.verify_invitation(&invitation, invitation_uuid)
	if !success {
		return nil, errors.New("Invitation is not valid due to tampering.")
	}

	// get the FileCount struct from the datastore
	file_root, err := userlib.PKEDec(userdata.get_privateKey(), invitation.EncFileRoot)
	if err != nil {
		return nil, err
	}
	fileCount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
	if err != nil {
		return nil, err
	}
	fileCount_bytes, ok := userlib.DatastoreGet(fileCount_uuid)
	if !ok {
		return nil, errors.New("FileCount does not exist.")
	}
	var fileCount FileCount
	err = json.Unmarshal(fileCount_bytes, &fileCount)
	if err != nil {
		return nil, err
	}
	// verify the fileCount
	success = userdata.verify_filecount(&fileCount, fileCount_uuid, &invitation)
	if !success {
		return nil, errors.New("FileCount is not valid due to tampering.")
	}

	// get the decode key from the invitation
	rsa_sk := userdata.get_privateKey()
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)

	var combined_filecontent []byte
	for i := 0; i <= fileCount.Num; i++ {
		// get the FileMeta struct from the datastore
		fileMeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(i)))[:16])
		if err != nil {
			return nil, err
		}
		fileMeta_bytes, ok := userlib.DatastoreGet(fileMeta_uuid)
		if !ok {
			return nil, errors.New("FileMeta does not exist.")
		}
		var fileMeta FileMeta
		err = json.Unmarshal(fileMeta_bytes, &fileMeta)
		if err != nil {
			return nil, err
		}
		// verify the fileMeta
		err = userdata.verify_filemeta(&fileMeta, fileMeta_uuid, &invitation)
		if err != nil {
			return nil, err
		}
		// decrypt the content of the file using decode key (symmetric encryption)
		content := userlib.SymDec(decode_key, fileMeta.EncContent)
		combined_filecontent = append(combined_filecontent, content...)
	}

	return combined_filecontent, nil
}


func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// try load the file
	_, err = userdata.LoadFile(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// get the ShareNode struct from the datastore
	shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	shareNode_bytes, ok := userlib.DatastoreGet(shareNode_uuid)
	if !ok {
		return uuid.Nil, errors.New("File does not exist.")
	}
	var shareNode ShareNode
	err = json.Unmarshal(shareNode_bytes, &shareNode)
	if err != nil {
		return uuid.Nil, err
	}
	// verify the shareNode
	err = verify_shareNode(userdata.Username, &shareNode, shareNode_uuid)
	if err != nil {
		return uuid.Nil, err
	}

	// get the Invitation struct from the datastore
	invitation_uuid := shareNode.InvitationPtr
	var invitation Invitation
	invitation_bytes, ok := userlib.DatastoreGet(invitation_uuid)
	if !ok {
		return uuid.Nil, errors.New("Invitation does not exist.")
	}
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return uuid.Nil, err
	}
	// verify the invitation
	success := userdata.verify_invitation(&invitation, invitation_uuid)
	if !success {
		return uuid.Nil, errors.New("Invitation is not valid due to tampering.")
	}

	// create the Invitation struct
	var new_invitation Invitation
	new_invitation.SharePtr = shareNode_uuid
	new_invitation.InviterName = userdata.Username
	new_inv_uuid := uuid.New()
	new_invitation.MyUUID = new_inv_uuid
	// decrypt the decode key using the private key of the user
	rsa_sk := userdata.get_privateKey()
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	if err != nil {
		return uuid.Nil, err
	}
	// encrypt the decode key using the public key of the recipient
	rec_rsa_pk, ok := userlib.KeystoreGet(recipientUsername + "/rsa_pk")
	if !ok {
		return uuid.Nil, errors.New("Recipient does not exist.")
	}
	enc_decode_key, err := userlib.PKEEnc(rec_rsa_pk, decode_key)
	if err != nil {
		return uuid.Nil, err
	}
	new_invitation.EncDecodeKey = enc_decode_key
	// encrypt the InviteeName using the decode key (symmetric encryption)
	iv := userlib.RandomBytes(16)
	enc_invitee_name := userlib.SymEnc(decode_key, iv, []byte(recipientUsername))
	new_invitation.EncInviteeName = enc_invitee_name
	// decrypt the fileroot using private key of the user
	fileRoot, err := userlib.PKEDec(rsa_sk, invitation.EncFileRoot)
	if err != nil {
		return uuid.Nil, err
	}
	// encrypt the fileroot using the public key of the recipient
	enc_fileRoot, err := userlib.PKEEnc(rec_rsa_pk, fileRoot)
	if err != nil {
		return uuid.Nil, err
	}
	new_invitation.EncFileRoot = enc_fileRoot
	// decrypt the HMAC key root using the decode key (symmetric encryption)
	keyroot := userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	// encrypt the HMAC key root using the decode key (symmetric encryption)
	new_invitation.EncHMACKeyRoot = userlib.SymEnc(decode_key, userlib.RandomBytes(16), keyroot)
	new_hmacinvkey := userlib.RandomBytes(16)
	new_invitation.EncHMACInvKey = userlib.SymEnc(decode_key, userlib.RandomBytes(16), new_hmacinvkey)
	calculate_inv_hmac(&new_invitation, new_inv_uuid, new_hmacinvkey)

	// update parent shareNode's childrenList and store it in the datastore
	shareNode.ChildrenList = append(shareNode.ChildrenList, new_inv_uuid)
	userlib.DebugMsg("shareNode.ChildrenList: %v, in create inv", shareNode.ChildrenList)
	var childrenList_bytes []byte
	childrenList_bytes, err = json.Marshal(shareNode.ChildrenList)
	if err != nil {
		return uuid.Nil, err
	}
	fields_combined := shareNode.MyUUID.String() + string(childrenList_bytes) + shareNode.InvitationPtr.String() + strconv.FormatBool(shareNode.IsOwner)
	dsa_sk := userdata.get_dsaKey()
	shareNode.Signature, err = userlib.DSSign(dsa_sk, []byte(fields_combined))
	if err != nil {
		return uuid.Nil, err
	}
	shareNode_bytes, err = json.Marshal(shareNode)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(shareNode_uuid, shareNode_bytes)

	return new_inv_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// check if the file already exists
	check_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(check_uuid)
	if ok {
		return errors.New("File already exists.")
	}
	// get the Invitation struct from the datastore
	invitation_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invitation does not exist.")
	}
	var invitation Invitation
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return err
	}
	// verify the invitation
	success := userdata.verify_invitation(&invitation, invitationPtr)
	if !success {
		return errors.New("Invitation is not valid due to tampering.")
	}
	if invitation.InviterName != senderUsername {
		return errors.New("Invitation not sent by the sender.")
	}
		
	// check if the file is revoked
	decode_key, err := userlib.PKEDec(userdata.get_privateKey(), invitation.EncDecodeKey)
	if err != nil {
		return err
	}

	// get the ShareNode struct from the datastore
	shareNode_uuid := invitation.SharePtr
	shareNode_bytes, ok := userlib.DatastoreGet(shareNode_uuid)
	if !ok {
		return errors.New("File does not exist.")
	}
	var shareNode ShareNode
	err = json.Unmarshal(shareNode_bytes, &shareNode)
	if err != nil {
		return err
	}
	// verify the shareNode
	err = verify_shareNode(invitation.InviterName, &shareNode, shareNode_uuid)
	if err != nil {
		return err
	}

	//create a new ShareNode struct
	var new_shareNode ShareNode
	new_shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	new_shareNode.MyUUID = new_shareNode_uuid
	new_shareNode.ChildrenList = make([]uuid.UUID, 0)
	new_shareNode.InvitationPtr = invitationPtr
	new_shareNode.IsOwner = false
	// use dsk_key to sign the fields in the new shareNode
	dsk_key := userdata.get_dsaKey()
	childrenList_bytes, err := json.Marshal(new_shareNode.ChildrenList)
	if err != nil {
		return err
	}
	fields_combined := new_shareNode.MyUUID.String() + string(childrenList_bytes) + new_shareNode.InvitationPtr.String() + strconv.FormatBool(new_shareNode.IsOwner)
	new_shareNode.Signature, err = userlib.DSSign(dsk_key, []byte(fields_combined))
	if err != nil {
		return err
	}
	// store the new shareNode in the datastore
	new_shareNode_bytes, err := json.Marshal(new_shareNode)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(new_shareNode_uuid, new_shareNode_bytes)


	// update the invitation struct
	invitation.SharePtr = new_shareNode_uuid
	inv_hmac_key := userlib.RandomBytes(16)
	if !ok {
		return errors.New("User does not exist.")
	}
	//invitation.EncInviteeName = userlib.SymEnc(decode_key, userlib.RandomBytes(16), []byte(userdata.Username))
	invitee_name := userlib.SymDec(decode_key, invitation.EncInviteeName)
	userlib.DebugMsg("invitee_name: %v when accept!!!!!!!!!!", string(invitee_name))
	invitation.EncHMACInvKey = userlib.SymEnc(decode_key, userlib.RandomBytes(16), inv_hmac_key)
	if err != nil {
		return err
	}
	calculate_inv_hmac(&invitation, invitationPtr, inv_hmac_key)

	// try load the file, if fail, means it's revoked
	_, err = userdata.LoadFile(filename)
	if err != nil {
		userlib.DatastoreDelete(new_shareNode_uuid)
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// find the shareNode of the file
	shareNode_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename))[:16])
	if err != nil {
		return err
	}
	shareNode_bytes, ok := userlib.DatastoreGet(shareNode_uuid)
	if !ok {
		return errors.New("File does not exist.")
	}
	var shareNode ShareNode
	err = json.Unmarshal(shareNode_bytes, &shareNode)
	if err != nil {
		return err
	}
	// verify the shareNode
	err = verify_shareNode(userdata.Username, &shareNode, shareNode_uuid)
	if err != nil {
		return err
	}

	// check if the user is the owner of the file
	if !shareNode.IsOwner {
		return errors.New("User is not the owner of the file.")
	}
	// get the invitation struct
	invitation_bytes, ok := userlib.DatastoreGet(shareNode.InvitationPtr)
	if !ok {
		return errors.New("Invitation does not exist.")
	}
	var invitation Invitation
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return err
	}
	// verify the invitation
	success := userdata.verify_invitation(&invitation, shareNode.InvitationPtr)
	if !success {
		return errors.New("Invitation is not valid due to tampering.")
	}
	rsa_sk := userdata.get_privateKey()
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	// get the fileCount struct
	file_root, err := userlib.PKEDec(userdata.get_privateKey(), invitation.EncFileRoot)
	if err != nil {
		return err
	}
	fileCount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
	if err != nil {
		return err
	}
	fileCount_bytes, ok := userlib.DatastoreGet(fileCount_uuid)
	if !ok {
		return errors.New("FileCount does not exist.")
	}
	var fileCount FileCount
	err = json.Unmarshal(fileCount_bytes, &fileCount)
	if err != nil {
		return err
	}
	// verify the fileCount
	err = rev_verify_filecount(&fileCount, fileCount_uuid, &invitation, decode_key)
	if err != nil {
		return err
	}
	// update the invitation struct
	new_decode_key := userlib.RandomBytes(16)
	new_file_root := userlib.RandomBytes(16)
	new_hmac_key_root := userlib.RandomBytes(16)
	new_hmac_inv_key := userlib.RandomBytes(16)
	rsa_pk, ok := userlib.KeystoreGet(userdata.Username + "/rsa_pk")
	if !ok {
		return errors.New("User does not exist.")
	}

	// go through all the fileMeta structs
	for i := 0; i <= fileCount.Num; i++ {
		// get the FileMeta struct from the datastore
		fileMeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(i)))[:16])
		if err != nil {
			return err
		}
		fileMeta_bytes, ok := userlib.DatastoreGet(fileMeta_uuid)
		if !ok {
			return errors.New("FileMeta does not exist.")
		}
		var fileMeta FileMeta
		err = json.Unmarshal(fileMeta_bytes, &fileMeta)
		if err != nil {
			return err
		}
		// verify the fileMeta
		err = rev_verify_filemeta(&fileMeta, fileMeta_uuid, &invitation, decode_key)
		if err != nil {
			return err
		}
		// update the fileMeta struct
		content := userlib.SymDec(decode_key, fileMeta.EncContent)
		fileMeta.EncContent = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), content)
		hmac_filemeta := userlib.Hash(append(new_hmac_key_root, []byte("FileMeta")...))[:16]
		fileMeta.MyUUID, err = uuid.FromBytes(userlib.Hash([]byte(string(new_file_root) + strconv.Itoa(i)))[:16])
		if err != nil {
			return err
		}
		success = calculate_filemeta_hmac(&fileMeta, fileMeta.MyUUID, hmac_filemeta)
		if !success {
			return errors.New("FileMeta update failed during revocation.")
		}
	}

	invitation.EncDecodeKey, err = userlib.PKEEnc(rsa_pk, new_decode_key)
	if err != nil {
		return err
	}
	invitee_name := userlib.SymDec(decode_key, invitation.EncInviteeName)
	userlib.DebugMsg("invitee_name when first in revoke: %s", string(invitee_name))
	iv := userlib.RandomBytes(16)
	invitation.EncInviteeName = userlib.SymEnc(new_decode_key, iv, []byte(invitee_name))
	invitation.EncFileRoot, err = userlib.PKEEnc(rsa_pk, new_file_root)
	if err != nil {
		return err
	}

	invitation.EncHMACKeyRoot = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), new_hmac_key_root)
	invitation.EncHMACInvKey = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), new_hmac_inv_key)
	calculate_inv_hmac(&invitation, shareNode.InvitationPtr, new_hmac_inv_key)

	// update the fileCount struct
	new_hmac_key_filecount := userlib.Hash(append(new_hmac_key_root, []byte("FileCount")...))[:16]
	fileCount.MyUUID, err = uuid.FromBytes(userlib.Hash([]byte(string(new_file_root) + "FileCount"))[:16])
	if err != nil {
		return err
	}
	calculate_filecount_hmac(&fileCount, fileCount.MyUUID, new_hmac_key_filecount)

	// go through the children list of the shareNode
	for _, child_uuid := range shareNode.ChildrenList {
		// get the invitation struct of the child
		child_invitation_bytes, ok := userlib.DatastoreGet(child_uuid)
		if !ok {
			return errors.New("Child invitation does not exist.")
		}
		var child_invitation Invitation
		err = json.Unmarshal(child_invitation_bytes, &child_invitation)
		if err != nil {
			return err
		}
		// verify the invitation
		success = rev_verify_invitation(&child_invitation, child_uuid, decode_key)
		if !success {
			return errors.New("Child invitation verification failed in revoke.")
		}
		//get invitee name
		invitee_name = userlib.SymDec(decode_key, child_invitation.EncInviteeName)
		if string(invitee_name) == recipientUsername {
			break;
		}
	}
	userlib.DebugMsg("revoke invitee name in revoke: %v", string(invitee_name))
	revoke_uuid := find_revoke_uuid(shareNode.ChildrenList, recipientUsername, decode_key)
	userlib.DebugMsg("revoke_uuid: %v", revoke_uuid)
	userlib.DebugMsg("nil: %v", uuid.Nil)
	if revoke_uuid == uuid.Nil {
		return errors.New("User is not in the childrenlist.")
	}
	err = userdata.update_sharenode_childrenlist(&shareNode, revoke_uuid)
	if err != nil {
		return err
	}
	err = delete_all_structs(decode_key, file_root)
	if err != nil {
		return err
	}
	userlib.DebugMsg("childrenlist: %v after delete all structs", shareNode.ChildrenList)
	for _, child_uuid := range shareNode.ChildrenList {
		// get the invitation struct of the child
		child_invitation_bytes, ok := userlib.DatastoreGet(child_uuid)
		if !ok {
			return errors.New("Invitation does not exist.")
		}
		var child_invitation Invitation
		err = json.Unmarshal(child_invitation_bytes, &child_invitation)
		if err != nil {
			return err
		}
		// verify the invitation
		success := rev_verify_invitation(&child_invitation, child_uuid, decode_key)
		if !success {
			return errors.New("Invitation is not valid due to tampering.")
		}
		// update the invitation struct if the invitee is not the revoked user
		child_invitee_name := userlib.SymDec(decode_key, child_invitation.EncInviteeName)
		userlib.DebugMsg("try to update child_invitee_name: %v", string(child_invitee_name))
		if string(child_invitee_name) != recipientUsername {
			err = update_invitation(&child_invitation, new_decode_key, new_file_root, new_hmac_key_root, decode_key, shareNode_uuid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func find_revoke_uuid(childrenList []uuid.UUID, recipientUsername string, decode_key []byte) uuid.UUID {
	userlib.DebugMsg("childrenlist in find: %v", childrenList)
	for _, child_uuid := range childrenList {
		userlib.DebugMsg("in the loop of find.")
		child_invitation_bytes, ok := userlib.DatastoreGet(child_uuid)
		if !ok {
			userlib.DebugMsg("Invitation does not exist in find.")
			return uuid.Nil
		}
		var child_invitation Invitation
		err := json.Unmarshal(child_invitation_bytes, &child_invitation)
		if err != nil {
			return uuid.Nil
		}
		child_invitee_name := userlib.SymDec(decode_key, child_invitation.EncInviteeName)
		userlib.DebugMsg("child_invitee_name: %v in find", string(child_invitee_name))
		userlib.DebugMsg("recipientUsername: %v in find", recipientUsername)
		if string(child_invitee_name) == recipientUsername {
			userlib.DebugMsg("find: %v", child_uuid)
			return child_uuid
		}
	}
	userlib.DebugMsg("did not find the user in the childrenlist.")
	return uuid.Nil
}

func (userdata *User)update_sharenode_childrenlist(shareNode *ShareNode, child_uuid uuid.UUID) error {
	userlib.DebugMsg("childrenlist: %v before", shareNode.ChildrenList)
	for i, uuid := range shareNode.ChildrenList {
		if uuid == child_uuid {
			shareNode.ChildrenList = append(shareNode.ChildrenList[:i], shareNode.ChildrenList[i+1:]...)
			break
		}
	}
	userlib.DebugMsg("childrenlist: %v after", shareNode.ChildrenList)
	var childrenList_bytes []byte
	childrenList_bytes, err := json.Marshal(shareNode.ChildrenList)
	if err != nil {
		return err
	}
	fields_combined := shareNode.MyUUID.String() + string(childrenList_bytes) + shareNode.InvitationPtr.String() + strconv.FormatBool(shareNode.IsOwner)
	dsa_sk := userdata.get_dsaKey()
	shareNode.Signature, err = userlib.DSSign(dsa_sk, []byte(fields_combined))
	if err != nil {
		return err
	}
	// Store the ShareNode struct in the datastore under the uuid generated from the username/filename
	shareNode_bytes, err := json.Marshal(shareNode)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(shareNode.MyUUID, shareNode_bytes)
	return nil
}

func delete_all_structs (decode_key []byte, file_root []byte) error {
	userlib.DebugMsg("delete_all_structs")
	// find the old fileCount struct
	fileCount_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + "FileCount"))[:16])
	if err != nil {
		return err
	}
	fileCount_bytes, ok := userlib.DatastoreGet(fileCount_uuid)
	if !ok {
		return errors.New("FileCount does not exist.")
	}
	var fileCount FileCount
	err = json.Unmarshal(fileCount_bytes, &fileCount)
	if err != nil {
		return err
	}
	// get the num in the filecount and go through the filemeta
	for i := 0; i < fileCount.Num; i++ {
		fileMeta_uuid, err := uuid.FromBytes(userlib.Hash([]byte(string(file_root) + strconv.Itoa(i)))[:16])
		if err != nil {
			return err
		}
		_, ok := userlib.DatastoreGet(fileMeta_uuid)
		if !ok {
			return errors.New("FileMeta does not exist.")
		}
		userlib.DatastoreDelete(fileMeta_uuid)
	}

	userlib.DatastoreDelete(fileCount_uuid)
	return nil
}

func update_invitation(invitation *Invitation, new_decode_key []byte, new_file_root []byte, new_hmac_key_root []byte, decode_key []byte, shareNode_uuid uuid.UUID) error {
	invitee_name := userlib.SymDec(decode_key, invitation.EncInviteeName)
	userlib.DebugMsg("invitee_name in update: %v", string(invitee_name))
	// update the invitation struct
	rsa_pk, ok := userlib.KeystoreGet(string(invitee_name) + "/rsa_pk")
	if !ok {
		return errors.New("RSA public key does not exist.")
	}
	var err error
	invitation.EncDecodeKey, err = userlib.PKEEnc(rsa_pk, new_decode_key)
	if err != nil {
		return err
	}
	invitation.EncFileRoot, err = userlib.PKEEnc(rsa_pk, new_file_root)
	if err != nil {
		return err
	}
	invitation.EncHMACKeyRoot = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), new_hmac_key_root)
	new_hmac_inv_key := userlib.RandomBytes(16)
	invitation.EncHMACInvKey = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), new_hmac_inv_key)
	invitee_name = userlib.SymDec(decode_key, invitation.EncInviteeName)
	invitation.EncInviteeName = userlib.SymEnc(new_decode_key, userlib.RandomBytes(16), invitee_name)
	// calculate the uuid of the invitation
	calculate_inv_hmac(invitation, invitation.MyUUID, new_hmac_inv_key)

	//get the shareNode struct
	if shareNode_uuid == invitation.SharePtr {
		return nil
	}
	get_shareNode_uuid := invitation.SharePtr
	get_shareNode_bytes, ok := userlib.DatastoreGet(get_shareNode_uuid)
	if !ok {
		return errors.New("ShareNode does not exist.")
	}
	var get_shareNode ShareNode
	err = json.Unmarshal(get_shareNode_bytes, &get_shareNode)
	if err != nil {
		return err
	}
	// verify the shareNode
	err = verify_shareNode(string(invitee_name), &get_shareNode, get_shareNode_uuid)
	if err != nil {
		return err
	}

	// recursively update the invitation struct of the children
	for _, child_uuid := range get_shareNode.ChildrenList {
		// get the invitation struct of the child
		child_invitation_bytes, ok := userlib.DatastoreGet(child_uuid)
		if !ok {
			return errors.New("Invitation does not exist.")
		}
		var child_invitation Invitation
		err = json.Unmarshal(child_invitation_bytes, &child_invitation)
		if err != nil {
			return err
		}
		// verify the invitation
		success := rev_verify_invitation(&child_invitation, child_uuid, decode_key)
		if !success {
			return errors.New("Invitation is not valid due to tampering.")
		}
		update_invitation(&child_invitation, new_decode_key, new_file_root, new_hmac_key_root, decode_key, get_shareNode_uuid)
	}
	return nil
}

func rev_verify_filecount(fileCount *FileCount, fileCount_uuid uuid.UUID, invitation *Invitation, decode_key []byte) error {
	// verify the fileCount
	if fileCount.MyUUID != fileCount_uuid {
		return errors.New("FileCount UUID does not match.")
	}
	// calculate the HMAC of the fileCount
	keyroot := userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	if keyroot == nil {
		return errors.New("Keyroot does not exist when verifying filecount.")
	}
	// append the keyroot to get the hmackey for the filecount
	filecount_hmackey := userlib.Hash(append(keyroot, []byte("FileCount")...))[:16]
	filecount_hmac, err := userlib.HMACEval(filecount_hmackey, []byte(fileCount.MyUUID.String() + strconv.Itoa(fileCount.Num)))
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(filecount_hmac, fileCount.HMAC) {
		return errors.New("FileCount HMAC does not match.")
	}
	return nil
}

func rev_verify_filemeta(fileMeta *FileMeta, fileMeta_uuid uuid.UUID, invitation *Invitation, decode_key []byte) error {
	// verify the fileMeta
	if fileMeta.MyUUID != fileMeta_uuid {
		return errors.New("FileMeta UUID does not match.")
	}
	// calculate the HMAC of the fileMeta
	keyroot := userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	if keyroot == nil {
		return errors.New("Keyroot does not exist when verifying filemeta.")
	}
	// append the keyroot to get the hmackey for the filemeta
	filemeta_hmackey := userlib.Hash(append(keyroot, []byte("FileMeta")...))[:16]
	filemeta_hmac, err := userlib.HMACEval(filemeta_hmackey, []byte(fileMeta.MyUUID.String() + string(fileMeta.EncContent)))
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(filemeta_hmac, fileMeta.HMAC) {
		return errors.New("FileMeta HMAC does not match.")
	}
	return nil
}

func rev_verify_invitation(invitation *Invitation, inv_uuid uuid.UUID, decode_key []byte) bool {
	// verify the invitation
	if invitation.MyUUID != inv_uuid {
		return false
	}
	// get the hmacinvkey
	hmacinvkey := userlib.SymDec(decode_key, invitation.EncHMACInvKey)
	if hmacinvkey == nil {
		return false
	}
	// calculate the HMAC of the invitation
	sharePtr_bytes, err := json.Marshal(invitation.SharePtr)
	if err != nil {
		return false
	}
	fields_combined := invitation.MyUUID.String() + string(sharePtr_bytes) + invitation.InviterName + string(invitation.EncDecodeKey) + string(invitation.EncInviteeName) + string(invitation.EncFileRoot) + string(invitation.EncHMACKeyRoot) + string(invitation.EncHMACInvKey)
	hmacInv, err := userlib.HMACEval(hmacinvkey, []byte(fields_combined))
	if err != nil {
		return false
	}
	if !userlib.HMACEqual(invitation.HMAC, hmacInv) {
		return false
	}
	return true
}

func calculate_inv_hmac(invitation *Invitation, inv_uuid uuid.UUID, hmacinvkey []byte) bool {
	// calculate the HMAC of the invitation
	// user hmacinvkey to encrypt all the fields in the invitation struct
	sharePtr_bytes, err := json.Marshal(invitation.SharePtr)
	if err != nil {
		return false
	}
	fields_combined := invitation.MyUUID.String() + string(sharePtr_bytes) + invitation.InviterName + string(invitation.EncDecodeKey) + string(invitation.EncInviteeName) + string(invitation.EncFileRoot) + string(invitation.EncHMACKeyRoot) + string(invitation.EncHMACInvKey)
	hmacInv, err := userlib.HMACEval(hmacinvkey, []byte(fields_combined))
	if err != nil {
		return false
	}
	invitation.HMAC = hmacInv
	// update the invitation in the datastore
	invitation_bytes, err := json.Marshal(invitation)
	if err != nil {
		return false
	}
	userlib.DatastoreSet(inv_uuid, invitation_bytes)
	return true
}

func calculate_filemeta_hmac(filemeta *FileMeta, filemeta_uuid uuid.UUID, hmac_key []byte) bool {
	// calculate the hmac of the filemeta
	filemeta_hmac, err := userlib.HMACEval(hmac_key, []byte(filemeta.MyUUID.String() + string(filemeta.EncContent)))
	if err != nil {
		return false
	}
	// update the hmac in the filemeta
	filemeta.HMAC = filemeta_hmac
	// update the filemeta in the datastore
	filemeta_bytes, err := json.Marshal(filemeta)
	if err != nil {
		return false
	}
	userlib.DatastoreSet(filemeta_uuid, filemeta_bytes)
	return true
}

func calculate_filecount_hmac(filecount *FileCount, filecount_uuid uuid.UUID, hmac_key []byte) bool {
	// calculate the hmac of the filecount
	filecount_hmac, err := userlib.HMACEval(hmac_key, []byte(filecount.MyUUID.String() + strconv.Itoa(filecount.Num)))
	if err != nil {
		return false
	}
	// update the hmac in the filecount
	filecount.HMAC = filecount_hmac
	// update the filecount in the datastore
	filecount_bytes, err := json.Marshal(filecount)
	if err != nil {
		return false
	}
	userlib.DatastoreSet(filecount_uuid, filecount_bytes)
	return true
}

func verify_shareNode(username string, shareNode *ShareNode, shareNode_uuid uuid.UUID) error {
	if shareNode.MyUUID != shareNode_uuid {
		return errors.New("shareNode uuid does not match")
	}
	// get the public key of the user
	dsa_pk, ok := userlib.KeystoreGet(username + "/dsa_pk")
	if !ok {
		return errors.New("cannot find the public key of the user")
	}
	// combine all the fields in the shareNode struct
	childrenList_bytes, err := json.Marshal(shareNode.ChildrenList)
	if err != nil {
		return err
	}
	fields_combined := shareNode.MyUUID.String() + string(childrenList_bytes) + shareNode.InvitationPtr.String() + strconv.FormatBool(shareNode.IsOwner)
	// verify the signature
	err = userlib.DSVerify(dsa_pk, []byte(fields_combined), shareNode.Signature)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) verify_invitation(invitation *Invitation, invitation_uuid uuid.UUID) bool {
	if invitation.MyUUID != invitation_uuid {
		return false
	}
	// get the private key of the user
	rsa_sk := userdata.get_privateKey()
	// decrypt EncHMACInvKey using decode_key
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	if err != nil {
		return false
	}
	hmacInvKey := userlib.SymDec(decode_key, invitation.EncHMACInvKey)

	// combine all the fields in the invitation struct
	sharePtr_bytes, err := json.Marshal(invitation.SharePtr)
	if err != nil {
		return false
	}
	fields_combined := invitation.MyUUID.String() + string(sharePtr_bytes) + invitation.InviterName + string(invitation.EncDecodeKey) + string(invitation.EncInviteeName) + string(invitation.EncFileRoot) + string(invitation.EncHMACKeyRoot) + string(invitation.EncHMACInvKey)
	// verify the HMAC
	hmacInv, err := userlib.HMACEval(hmacInvKey, []byte(fields_combined))
	if err != nil {
		return false
	}
	if !userlib.HMACEqual(hmacInv, invitation.HMAC) {
		return false
	}
	return true
}

func (userdata *User) verify_filemeta(fileMeta *FileMeta, fileMeta_uuid uuid.UUID, invitation *Invitation) error {
	if fileMeta.MyUUID != fileMeta_uuid {
		return errors.New("fileMeta.MyUUID != fileMeta_uuid")
	}
	// get the private key of the user
	rsa_sk := userdata.get_privateKey()
	// decrypt EncHMACKeyRoot using decodeKey
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	if err != nil {
		return err
	}
	hmacKeyRoot := userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	if err != nil {
		return err
	}
	// get the hmackey for the filemeta by appending "FileMeta" to the hmacKeyRoot
	hmacFileMetaKey := userlib.Hash(append(hmacKeyRoot, []byte("FileMeta")...))[:16]
	// verify the HMAC
	hmacFileMeta, err := userlib.HMACEval(hmacFileMetaKey, []byte(fileMeta.MyUUID.String() + string(fileMeta.EncContent)))
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(hmacFileMeta, fileMeta.HMAC) {
		return errors.New("HMAC not equal")
	}
	return nil
}

func (userdata *User) verify_filecount(fileCount *FileCount, fileCount_uuid uuid.UUID, invitation *Invitation) bool {
	if fileCount.MyUUID != fileCount_uuid {
		return false
	}
	// get the private key of the user
	rsa_sk := userdata.get_privateKey()
	// decrypt EncHMACKeyRoot using decodeKey
	decode_key, err := userlib.PKEDec(rsa_sk, invitation.EncDecodeKey)
	if err != nil {
		return false
	}
	hmacKeyRoot := userlib.SymDec(decode_key, invitation.EncHMACKeyRoot)
	if err != nil {
		return false
	}
	// get the hmackey for the filecount by appending "FileCount" to the hmacKeyRoot
	hmacFileCountKey := userlib.Hash(append(hmacKeyRoot, []byte("FileCount")...))[:16]
	// verify the HMAC
	hmacFileCount, err := userlib.HMACEval(hmacFileCountKey, []byte(fileCount.MyUUID.String() + strconv.Itoa(fileCount.Num)))
	if err != nil {
		return false
	}
	if !userlib.HMACEqual(hmacFileCount, fileCount.HMAC) {
		return false
	}
	return true
}

func (userdata *User) get_privateKey() userlib.PKEDecKey {
	source_key := userlib.Hash([]byte(userdata.raw_password))[:16]
	key_for_enc, err := userlib.HashKDF(source_key, []byte("EncPrivate"))
	if err != nil {
		return userlib.PKEDecKey{}
	}
	rsa_sk_bytes := userlib.SymDec(key_for_enc[:16], userdata.EncPrivateKey)
	var rsa_sk userlib.PKEDecKey
	err = json.Unmarshal(rsa_sk_bytes, &rsa_sk)
	if err != nil {
		return userlib.PKEDecKey{}
	}
	return rsa_sk
}

func (userdata *User) get_dsaKey() userlib.DSSignKey {
	source_key := userlib.Hash([]byte(userdata.raw_password))[:16]
	key_for_sign, err := userlib.HashKDF(source_key, []byte("EncSign"))
	if err != nil {
		return userlib.DSSignKey{}
	}
	dsa_sk_bytes := userlib.SymDec(key_for_sign[:16], userdata.EncSignKey)
	var dsa_sk userlib.DSSignKey
	err = json.Unmarshal(dsa_sk_bytes, &dsa_sk)
	if err != nil {
		return userlib.DSSignKey{}
	}
	return dsa_sk
}