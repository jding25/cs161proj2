package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	"github.com/google/uuid"
	_"fmt"
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const stringSpace = " "
const wrongPassword = "wrongpassword"
const longString = "[1] In the beginning God created the heaven and the earth.[2] And the earth was without form, and void; and darkness was upon the face of the deep. And the Spirit of God moved upon the face of the waters.[3] And God said, Let there be light: and there was light.[4] And God saw the light, that it was good: and God divided the light from the darkness.[5] And God called the light Day, and the darkness he called Night. And the evening and the morning were the first day.[6] And God said, Let there be a firmament in the midst of the waters, and let it divide the waters from the waters.[7] And God made the firmament, and divided the waters which were under the firmament from the waters which were above the firmament: and it was so.[8] And God called the firmament Heaven. And the evening and the morning were the second day.[9] And God said, Let the waters under the heaven be gathered together unto one place, and let the dry land appear: and it was so.[10] And God called the dry land Earth; and the gathering together of the waters called he Seas: and God saw that it was good.[11] And God said, Let the earth bring forth grass, the herb yielding seed, and the fruit tree yielding fruit after his kind, whose seed is in itself, upon the earth: and it was so.[12] And the earth brought forth grass, and herb yielding seed after his kind, and the tree yielding fruit, whose seed was in itself, after his kind: and God saw that it was good."
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User


	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error


	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"


	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("Edge Case Tests", func() {

		Specify("Edge Case Test: InitUser.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice again.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())	

			userlib.DebugMsg("Initializing user with empty username.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())	

			userlib.DebugMsg("Initializing user with empty password.")
			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initalizing user with space password.")
			_, err = client.InitUser("cc",stringSpace)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with space add to the username.")
			_,err = client.InitUser("cc ",emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with long username.")
			_,err =client.InitUser(longString,"")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with long password.")
			_,err =client.InitUser("longString",longString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with upper case username.")
			_,err =client.InitUser("Bob","")
			Expect(err).To(BeNil())
		})

		Specify("Edge Case Test: GetUser.", func() {
			userlib.DebugMsg("Get user Alice before initialization.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Get user Bob before initialization.")
			alice, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user with wrong credentials.")
			_, err = client.GetUser("alice", wrongPassword)
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alice", "")
			Expect(err).ToNot(BeNil())
			
			_, err = client.GetUser(" ", "wrongPasswod")
			Expect(err).ToNot(BeNil())
		
			_,err = client.GetUser("alice ",defaultPassword)
			Expect(err).ToNot(BeNil())

			_,err = client.GetUser("Bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alice", defaultPassword+stringSpace)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Get user with right credential.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Edge Case Test: Store", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(".",[]byte(emptyString))
			Expect(err).To(BeNil())
			err = alice.StoreFile(emptyString, []byte(stringSpace))
			Expect(err).To(BeNil())
			err = alice.StoreFile(stringSpace, []byte(stringSpace))
			Expect(err).To(BeNil())
			err = bob.StoreFile(emptyString, []byte(emptyString))
			Expect(err).To(BeNil())
			err = bob.StoreFile(longString, []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.StoreFile("a.log.b.v",[]byte(longString))
			Expect(err).To(BeNil())

		})

		Specify("Edge Case Test: Load", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file when filename does not exist")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("alice", []byte(contentOne))
			Expect(err).To(BeNil())

			_, err = alice.LoadFile("alice ")
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile(" alice")
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile("Alice")
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile("alice.txt")
			Expect(err).ToNot(BeNil())
			_, err = bob.LoadFile("alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to append to file when he doesn't have access")
			err = bob.AppendToFile("alice", []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			data, err := alice.LoadFile("alice")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("testing overwriting file")
			err = alice.StoreFile("alice",[]byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile("alice")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("non unique filename")
			_ = alice.StoreFile("foo.txt",[]byte("123"))
			_ = bob.StoreFile("foo.txt",[]byte("12"))
			a, err := alice.LoadFile("foo.txt")
			Expect(a).To(Equal([]byte("123")))
			Expect(err).To(BeNil())
			b, err := bob.LoadFile("foo.txt")
			Expect(b).To(Equal([]byte("12")))
			Expect(err).To(BeNil())
			ptr, _ := alice.CreateInvitation("foo.txt","bob")
			b, err = bob.LoadFile("foo.txt")
			Expect(b).To(Equal([]byte("12")))
			Expect(err).To(BeNil())
			_ = bob.AppendToFile("foo.txt",[]byte("12"))
			a, err = alice.LoadFile("foo.txt")
			Expect(a).To(Equal([]byte("123")))
			Expect(err).To(BeNil())
			b, err = bob.LoadFile("foo.txt")
			Expect(b).To(Equal([]byte("1212")))
			Expect(err).To(BeNil())
			_ = bob.AcceptInvitation("alice",ptr,"foo")
			_ = bob.AppendToFile("foo.txt",[]byte("12"))
			a, err = alice.LoadFile("foo.txt")
			Expect(a).To(Equal([]byte("123")))
			Expect(err).To(BeNil())
		})

		Specify("Edge Case Test: Append", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop).")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing users bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("appending file before file exists.")
			err = aliceDesktop.AppendToFile("alice.txt",[]byte(emptyString))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile("alice.txt", []byte(contentOne))
			Expect(err).To(BeNil())
			err = aliceDesktop.AppendToFile("alice.txt",[]byte(""))
			Expect(err).To(BeNil())
			err = aliceLaptop.AppendToFile("alice.txt", []byte(" "))
			Expect(err).To(BeNil())
			err = aliceLaptop.AppendToFile("alice",[]byte("."))
			Expect(err).ToNot(BeNil())	
			err = bob.AppendToFile("alice.txt",[]byte("im bob"))
			Expect(err).ToNot(BeNil())	
			data, err := aliceLaptop.LoadFile("alice.txt")	
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "" + " ")))
			data, err = aliceDesktop.LoadFile("alice.txt")	
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "" + " ")))

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, _ := aliceLaptop.CreateInvitation("alice.txt", "bob")
			//second instance of bob
			bobLaptop, err := client.GetUser("bob", defaultPassword)
			Expect(bobLaptop).ToNot(BeNil())
			Expect(err).To(BeNil())
			err = bobLaptop.AcceptInvitation("alice", invite, "bobalice.txt")
			Expect(err).To(BeNil())

			err = bob.AppendToFile("bobalice",[]byte(""))
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile("bobalice.txt", []byte(" "))
			Expect(err).To(BeNil())
			//alice can't access the file with bobalice.txt
			err = aliceDesktop.AppendToFile("bobalice.txt", []byte(contentThree))
			Expect(err).ToNot(BeNil())
			_, err = aliceLaptop.LoadFile("bobalice.txt")
			Expect(err).ToNot(BeNil())
			_, err = bob.LoadFile("bobalice.txt ")
			Expect(err).ToNot(BeNil())
			databob, err := bob.LoadFile("bobalice.txt")
			Expect(err).To(BeNil())
			Expect(databob).To(Equal([]byte(contentOne + "" + " " + " ")))
			dataalice, err := aliceDesktop.LoadFile("alice.txt")
			Expect(dataalice).To(Equal(databob))
			Expect(err).To(BeNil())
		})
		Specify("Edge Case Test: Sharing", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())	

			//invitation
			userlib.DebugMsg("Filename does not exist in caller's namspace.")
			_ = alice.StoreFile("alice.txt", []byte(""))
			_ = bob.StoreFile("bob.txt", []byte(""))
			_ = charles.StoreFile("charles.txt", []byte(" "))
			_, err := alice.CreateInvitation("bob.txt", "charles")
			Expect(err).ToNot(BeNil())
			_, err = alice.CreateInvitation("alice", "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("recepient's name des not exist")
			_, err = alice.CreateInvitation("alice.txt", "Bob")
			Expect(err).ToNot(BeNil())
			_, err = alice.CreateInvitation("alice.txt", "bob ")
			Expect(err).ToNot(BeNil())


			// accept invitation
			userlib.DebugMsg("alice creates invitation for bob (alice.txt)")
			alicetxt_pointer, err := alice.CreateInvitation("alice.txt", "bob")
			Expect(alicetxt_pointer).ToNot(BeNil())
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob can accept the invitation with space as name")
			err = bob.AcceptInvitation("alice",alicetxt_pointer, "")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Laptop bob can overwrite the file and should be reflected at alice's end")
			laptop_bob, _ := client.GetUser("bob", defaultPassword)
			err  = laptop_bob.StoreFile("",([]byte(".")))
			Expect(err).To(BeNil())
			data, _:= alice.LoadFile("alice.txt")
			Expect(data).ToNot(Equal([]byte("")))
			Expect(data).To(Equal([]byte(".")))

			userlib.DebugMsg("Bob can't accep two invitations with the same filename")
			charlestext_pointer, _ := charles.CreateInvitation("charles.txt","bob")
			err = laptop_bob.AcceptInvitation("charles", charlestext_pointer,"")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("checking it's still alice's file under empty filename")
			data, _ = bob.LoadFile("")
			Expect(data).To(Equal([]byte(".")))
			userlib.DebugMsg("Bob can create the file with a space as the filename")
			err = laptop_bob.AcceptInvitation("charles", charlestext_pointer," ")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Charles can't accept alice to bob's invitation.")
			err = charles.AcceptInvitation("alice", alicetxt_pointer,"")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Can't accept invitaiton after revoke. but can still accept other files from the same user.")
			alicetxt_pointer2, _ := alice.CreateInvitation("alice.txt", "charles")
			_ = alice.StoreFile("alice.txt2", []byte(" "))
			alicetxt_pointer3, _:= alice.CreateInvitation("alice.txt2","charles")
			_ = alice.RevokeAccess("alice.txt", "charles")
			err = charles.AcceptInvitation("alice", alicetxt_pointer2, "_")
			Expect(err).ToNot(BeNil())
			err = charles.AcceptInvitation("alice", alicetxt_pointer3,"_")
			Expect(err).To(BeNil())
			data, _ = charles.LoadFile("_")
			Expect(data).To(Equal([]byte(" ")))
			
			//revoke access
			userlib.DebugMsg("Initializing users doris, eve, and frank.")
			doris, err = client.InitUser("doris", "123")
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", "123")
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", "123")
			Expect(err).To(BeNil())	
			_ = doris.StoreFile("doris.txt",[]byte(""))
			_ = eve.StoreFile("eve.txt",[]byte(""))
			_ = frank.StoreFile("frank.txt",[]byte(""))

			
			userlib.DebugMsg("can't revoke file when the filename does not exist.")
			alicetxt_pointer, err = alice.CreateInvitation("alice.txt", "doris")
			Expect(err).To(BeNil())
			err  = alice.RevokeAccess("doris.txt", "doris")
			Expect(err).ToNot(BeNil())
			err = doris.AcceptInvitation("alice",alicetxt_pointer,"alice_doris.txt")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess("alice_doris.txt", "alice")
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge Case Test: Tree", func() {
			userlib.DebugMsg("Sharing tree: doris -> bob > charles; doris -> alice -> eve ")
			//initialization
			doris, _ :=  client.InitUser("doris",".")
			bob, _:= client.InitUser("bob",".")
			charles, _:= client.InitUser("charles",".")
			alice, _ := client.InitUser("alice",".")
			eve, _ := client.InitUser("eve",".")
			_ = doris.StoreFile("doris.txt",[]byte(""))
			//first layer of tree; share and accept
			doris_bob_ptr, _ := doris.CreateInvitation("doris.txt", "bob")
			doris_alice_ptr, _ := doris.CreateInvitation("doris.txt", "alice")
			_ = alice.AcceptInvitation("doris",doris_alice_ptr, "doris_alice.txt")
			_ = bob.AcceptInvitation("doris", doris_bob_ptr, "doris_bob.txt")
			//second layer
			bob_charles_ptr, _ := bob.CreateInvitation("doris_bob.txt", "charles")
			alice_eve_ptr, _:= alice.CreateInvitation("doris_alice.txt","eve")
			_ = charles.AcceptInvitation("bob", bob_charles_ptr, "bob_charles.txt")
			_ = eve.AcceptInvitation("alice",alice_eve_ptr,"alice_eve.txt")


			userlib.DebugMsg("everyone can load the content of file. doris.txt should be contentOne rn.")
			_ = doris.AppendToFile("doris.txt",[]byte(contentOne))
			data, _ := doris.LoadFile("doris.txt")
			Expect(data).To(Equal([]byte(contentOne)))
			data, _ = alice.LoadFile("doris_alice.txt")
			Expect(data).To(Equal([]byte(contentOne)))
			data, _ = bob.LoadFile("doris_bob.txt")
			Expect(data).To(Equal([]byte(contentOne)))
			data, _ = charles.LoadFile("bob_charles.txt")
			Expect(data).To(Equal([]byte(contentOne)))
			data, _ = eve.LoadFile("alice_eve.txt")
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg(" eve can rewrite the file to content three.")
			err = eve.StoreFile("alice_eve.txt",[]byte(contentThree))
			Expect(err).To(BeNil())
			data, err := doris.LoadFile("doris.txt")
			Expect(data).To(Equal([]byte(contentThree)))
			Expect(err).To(BeNil())
			_ = doris.StoreFile("doris.txt",[]byte(contentOne))
			data, _ = charles.LoadFile("bob_charles.txt")
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("doris revoke access of alice, which should subsequently remove access of eve.")
			err = doris.RevokeAccess("doris.txt", "alice")
			Expect(err).To(BeNil())
			_, err = alice.LoadFile("doris_alice.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("doris revoke access of bob, which should subsequently remove access of charles.")
			err = doris.RevokeAccess("doris.txt", "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile("doris_bob.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("after bob's access got revoked, he cant revoke his child.")
			err = bob.RevokeAccess("doris_bob.txt","charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("check bob and charles can't load file")
			_, err = bob.LoadFile("doris_bob.txt")
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile("bob_charles.txt")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("bob can't append to the file.")
			err = bob.AppendToFile("doris_bob.txt",[]byte("."))
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile("bob_charles.txt",[]byte("."))
			Expect(err).ToNot(BeNil())
			data,_ = doris.LoadFile("doris.txt")
			Expect(data).To(Equal([]byte(contentOne)))
			_ = doris.AppendToFile("doris.txt",[]byte("="))
			userlib.DebugMsg("check charles can't create invitation after gets recoved.")
			_, err = charles.CreateInvitation("bob_charles.txt","eve")
			Expect(err).ToNot(BeNil())


		})

	
	})

		Specify("Tamper Test: Init/Get user.", func() {
			userlib.DebugMsg("Initializing user Alice, Bob, and Eve.")
			alice, _ = client.InitUser("alice", "123")
			bob, _ = client.InitUser("bob", "456")
			eve, _= client.InitUser("eve","")

			datastore := userlib.DatastoreGetMap()
			// retrive the first value in datastore
			var firstval []byte
			var firstkey uuid.UUID
			for key, val := range datastore {
				firstval = val
				firstkey = key
				break
			}
			var nextval []byte
			for  key, val:= range datastore{
				if key != firstkey{
					nextval = val
					break
				}
			}
			//set rest of the uuid to the first values
			for key := range datastore{
				if key != firstkey {
					userlib.DatastoreSet(key, firstval)
				} else {
					userlib.DatastoreSet(key, nextval)
				}
			}


			//alice tries to log into bob and eve's account using her credentials
			_, err = client.GetUser("bob","123")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("eve","123")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("since their information are tampered, bob and eve can't log in either")
			_, err = client.GetUser("eve","")
			Expect(err).ToNot(BeNil()) 
			_, err = client.GetUser("bob","456")
			Expect(err).ToNot(BeNil())
			
			userlib.DebugMsg("tampering the database by modifying their values a little bit.")
			for key, val := range datastore {
				new_val := append(val, []byte(".")...)
				userlib.DatastoreSet(key, new_val)
			}
			_, err = client.GetUser("alice","123")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("bob", "456")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("eve","")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("eve",".")
			Expect(err).ToNot(BeNil())
		})
	

		Specify("Tamper Test: Store, Load, AppendTo", func(){
			alice, _ = client.InitUser("alice","abc")
			bob, _ = client.InitUser("bob","abc")
			eve, _ = client.InitUser("eve", "abc")
			_ = alice.StoreFile("abc.txt", []byte(""))
			_ = bob.StoreFile("abc.txt",[]byte(""))
			_ = eve.StoreFile("abc.txt", []byte(""))

			userlib.DebugMsg("reset all the values of bob and eve to alice")
			datastore := userlib.DatastoreGetMap()
			// retrive the first value in datastore
			var firstval []byte
			var firstkey uuid.UUID
			for key, val := range datastore {
				firstkey = key
				firstval = val
				break
			}
			var lastval []byte
			for key, val := range datastore {
				if key != firstkey{
					lastval = val
					break
				}
			}
			//set rest of the uuid to the first values
			for key := range datastore{
				if key != firstkey{
					userlib.DatastoreSet(key, firstval)
				} else{
					userlib.DatastoreSet(key, lastval)
				}
			}

			userlib.DebugMsg("can't get user.")
			_, err := client.GetUser("bob", "abc")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("eve","abc")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob and eve can't load their file or append to their file")
			_, err = bob.LoadFile("abc.txt")
			Expect(err).ToNot(BeNil())
			_, err = eve.LoadFile("abc.txt")
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile("abc.txt",[]byte(""))
			Expect(err).ToNot(BeNil())
			err = eve.AppendToFile("abc.txt",[]byte(""))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("can't share file after the datastore tampered")
			ptr, err := bob.CreateInvitation("abc.txt","alice")
			Expect(err).ToNot(BeNil())
			err = alice.AcceptInvitation("bob", ptr, "lol")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("can't accept invitation after the datastore tampered")
			ptr, _ = alice.CreateInvitation("abc.txt","bob")
			err = bob.AcceptInvitation("alice", ptr, "lol")
			Expect(err).ToNot(BeNil())

		})


	})

