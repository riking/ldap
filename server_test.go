package ldap

import (
	"bytes"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var listenString = "localhost:3389"
var ldapURL = "ldap://" + listenString
var timeout = 400 * time.Millisecond
var serverBaseDN = "o=testers,c=test"

/////////////////////////
func TestBindAnonOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindAnonFail(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Inappropriate authentication (48)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	time.Sleep(timeout)
	quit <- true
}

/////////////////////////
func TestBindSimpleOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSSL(t *testing.T) {
	ldapURLSSL := "ldaps://" + listenString
	longerTimeout := 300 * time.Millisecond
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServeTLS(listenString, "examples/cert_DONOTUSE.pem", "examples/key_DONOTUSE.pem"); err != nil {
			t.Errorf("s.ListenAndServeTLS failed: %s", err.Error())
		}
	}()

	go func() {
		time.Sleep(longerTimeout * 2)
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 2):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindPanic(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindPanic{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestSearchSimpleOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "uidNumber: 5000") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numResponses: 4") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestSearchSizelimit(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.EnforceLDAP = true
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "9") // effectively no limit for this test
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 3") {
			t.Errorf("ldapsearch sizelimit failed - not enough entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "2")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 2") {
			t.Errorf("ldapsearch sizelimit failed - too many entries: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSearchMulti(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		s.BindFunc("c=testz", bindSimple2{})
		s.SearchFunc("", searchSimple{})
		s.SearchFunc("c=testz", searchSimple2{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test",
			"-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "cn=ned")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("error routing default bind/search functions: %v", string(out))
		}
		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("search default routing failed: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=testz",
			"-D", "cn=testy,o=testers,c=testz", "-w", "ZLike2test", "cn=hamburger")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("error routing custom bind/search functions: %v", string(out))
		}
		if !strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
			t.Errorf("search custom routing failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	quit <- true
}

/////////////////////////
func TestSearchPanic(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchPanic{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 1 Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
type compileSearchFilterTest struct {
	name         string
	filterStr    string
	numResponses string
}

var searchFilterTestFilters = []compileSearchFilterTest{
	compileSearchFilterTest{name: "equalityOk", filterStr: "(uid=ned)", numResponses: "2"},
	compileSearchFilterTest{name: "equalityNo", filterStr: "(uid=foo)", numResponses: "1"},
	compileSearchFilterTest{name: "equalityOk", filterStr: "(objectclass=posixaccount)", numResponses: "4"},
	compileSearchFilterTest{name: "presentEmptyOk", filterStr: "", numResponses: "4"},
	compileSearchFilterTest{name: "presentOk", filterStr: "(objectclass=*)", numResponses: "4"},
	compileSearchFilterTest{name: "presentOk", filterStr: "(description=*)", numResponses: "3"},
	compileSearchFilterTest{name: "presentNo", filterStr: "(foo=*)", numResponses: "1"},
	compileSearchFilterTest{name: "andOk", filterStr: "(&(uid=ned)(objectclass=posixaccount))", numResponses: "2"},
	compileSearchFilterTest{name: "andNo", filterStr: "(&(uid=ned)(objectclass=posixgroup))", numResponses: "1"},
	compileSearchFilterTest{name: "andNo", filterStr: "(&(uid=ned)(uid=trent))", numResponses: "1"},
	compileSearchFilterTest{name: "orOk", filterStr: "(|(uid=ned)(uid=trent))", numResponses: "3"},
	compileSearchFilterTest{name: "orOk", filterStr: "(|(uid=ned)(objectclass=posixaccount))", numResponses: "4"},
	compileSearchFilterTest{name: "orNo", filterStr: "(|(uid=foo)(objectclass=foo))", numResponses: "1"},
	compileSearchFilterTest{name: "andOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(objectclass=posixaccount))", numResponses: "3"},
	compileSearchFilterTest{name: "notOk", filterStr: "(!(uid=ned))", numResponses: "3"},
	compileSearchFilterTest{name: "notOk", filterStr: "(!(uid=foo))", numResponses: "4"},
	compileSearchFilterTest{name: "notAndOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(!(objectclass=posixgroup)))", numResponses: "3"},
	/*
		compileSearchFilterTest{filterStr: "(sn=Mill*)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn=*Mill)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn=*Mill*)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn>=Miller)", filterType: FilterGreaterOrEqual},
		compileSearchFilterTest{filterStr: "(sn<=Miller)", filterType: FilterLessOrEqual},
		compileSearchFilterTest{filterStr: "(sn~=Miller)", filterType: FilterApproxMatch},
	*/
}

/////////////////////////
func TestSearchFiltering(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.EnforceLDAP = true
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	for _, i := range searchFilterTestFilters {
		t.Log(i.name)

		go func() {
			cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
				"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", i.filterStr)
			out, _ := cmd.CombinedOutput()
			if !strings.Contains(string(out), "numResponses: "+i.numResponses) {
				t.Errorf("ldapsearch failed - expected numResponses==%d: %v", i.numResponses, string(out))
			}
			done <- true
		}()

		select {
		case <-done:
		case <-time.After(timeout):
			t.Errorf("ldapsearch command timed out")
		}
	}
	quit <- true
}

/////////////////////////
func TestSearchAttributes(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.EnforceLDAP = true
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		filterString := ""
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", filterString, "cn")
		out, _ := cmd.CombinedOutput()

		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("ldapsearch failed - missing requested DN attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "cn: ned") {
			t.Errorf("ldapsearch failed - missing requested CN attribute: %v", string(out))
		}
		if strings.Contains(string(out), "uidNumber") {
			t.Errorf("ldapsearch failed - uidNumber attr should not be displayed: %v", string(out))
		}
		if strings.Contains(string(out), "accountstatus") {
			t.Errorf("ldapsearch failed - accountstatus attr should not be displayed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestSearchScope(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.EnforceLDAP = true
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "sub", "cn=trent")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'sub' scope failed - didn't find expected DN: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'one' scope failed - didn't find expected DN: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'one' scope failed - found unexpected DN: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "cn=trent,o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'base' scope failed - didn't find expected DN: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'base' scope failed - found unexpected DN: %v", string(out))
		}

		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	quit := make(chan bool)
	done := make(chan bool)
	s := NewServer()

	go func() {
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		s.SetStats(true)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	stats := s.GetStats()
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
	quit <- true
}

/////////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct {
}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindPanic struct {
}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	panic("test panic at the disco")
	return LDAPResultInvalidCredentials, nil
}

type searchSimple struct {
}

func (s searchSimple) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=ned,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"ned"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"ned"}},
			&EntryAttribute{"description", []string{"ned via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=trent,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"trent"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5005"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"trent"}},
			&EntryAttribute{"description", []string{"trent via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=randy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"randy"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5555"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"randy"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct {
}

func (s searchSimple2) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}},
			&EntryAttribute{"o", []string{"testers"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"hamburger"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchPanic struct {
}

func (s searchPanic) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	panic("this is a test panic")
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}
