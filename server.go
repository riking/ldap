package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nmcclain/asn1-ber"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type Binder interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error)
}
type Searcher interface {
	Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error)
}
type Closer interface {
	Close(conn net.Conn) error
}

/////////////////////////
type Server struct {
	bindFns     map[string]Binder
	searchFns   map[string]Searcher
	closeFns    map[string]Closer
	quit        chan bool
	EnforceLDAP bool
	stats       *Stats
}

type Stats struct {
	Conns      int
	Binds      int
	Unbinds    int
	Searches   int
	statsMutex sync.Mutex
}

type ServerSearchResult struct {
	Entries    []*Entry
	Referrals  []string
	Controls   []Control
	ResultCode uint64
}

/////////////////////////
func NewServer() *Server {
	s := new(Server)
	s.quit = make(chan bool)

	d := defaultHandler{}
	s.bindFns = make(map[string]Binder)
	s.searchFns = make(map[string]Searcher)
	s.closeFns = make(map[string]Closer)
	s.bindFns[""] = d
	s.searchFns[""] = d
	s.closeFns[""] = d
	s.stats = nil
	return s
}
func (server *Server) BindFunc(baseDN string, bindFn Binder) {
	server.bindFns[baseDN] = bindFn
}
func (server *Server) SearchFunc(baseDN string, searchFn Searcher) {
	server.searchFns[baseDN] = searchFn
}
func (server *Server) CloseFunc(baseDN string, closeFn Closer) {
	server.closeFns[baseDN] = closeFn
}
func (server *Server) QuitChannel(quit chan bool) {
	server.quit = quit
}

func (server *Server) ListenAndServeTLS(listenString string, certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.ServerName = "localhost"
	ln, err := tls.Listen("tcp", listenString, &tlsConfig)
	if err != nil {
		return err
	}
	err = server.serve(ln)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) SetStats(enable bool) {
	if enable {
		server.stats = &Stats{}
	} else {
		server.stats = nil
	}
}

func (server *Server) GetStats() Stats {
	defer func() {
		server.stats.statsMutex.Unlock()
	}()
	server.stats.statsMutex.Lock()
	return *server.stats
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}
	err = server.serve(ln)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting network connection: %s", err.Error())
				}
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.stats.countConns(1)
			go server.handleConnection(c)
		case <-server.quit:
			ln.Close()
			break listener
		}
	}
	return nil
}

/////////////////////////

func (server *Server) handleConnection(conn net.Conn) {
	boundDN := "" // "" == anonymous

handler:
	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			log.Print("len(packet.Children) < 2")
			break
		}
		// check the message ID and ClassType
		messageID := packet.Children[0].Value.(uint64)
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			log.Print("req.ClassType != ber.ClassApplication")
			break
		}
		// handle controls if present
		if len(packet.Children) > 2 {
			controls := packet.Children[2]
			ber.PrintPacket(controls)
			log.Print("TODO Parse Controls")
			/*
			   Controls ::= SEQUENCE OF control Control

			   Control ::= SEQUENCE {
			        controlType             LDAPOID,
			        criticality             BOOLEAN DEFAULT FALSE, // unavailableCriticalExtension
			        controlValue            OCTET STRING OPTIONAL }
			*/
		}

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			//log.Printf("Bound as %s", boundDN)
			//ber.PrintPacket(packet)
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler

		case ApplicationBindRequest:
			server.stats.countBinds(1)
			ldapResultCode := server.handleBindRequest(req, server.bindFns, conn)
			if ldapResultCode == LDAPResultSuccess {
				boundDN = req.Children[1].Value.(string)
			}
			responsePacket := encodeBindResponse(messageID, ldapResultCode)
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationSearchRequest:
			server.stats.countSearches(1)
			if err := server.handleSearchRequest(req, messageID, boundDN, server.searchFns, conn); err != nil {
				log.Printf("handleSearchRequest error %s", err.Error()) // TODO: make this more testable/better err handling - stop using log, stop using breaks?
				e := err.(*Error)
				if err = sendPacket(conn, encodeSearchDone(messageID, uint64(e.ResultCode))); err != nil {
					log.Printf("sendPacket error %s", err.Error())
				}
				break handler
			} else {
				if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultSuccess)); err != nil {
					log.Printf("sendPacket error %s", err.Error())
					break handler
				}
			}
		case ApplicationUnbindRequest:
			server.stats.countUnbinds(1)
			break handler // simply disconnect - this IS implemented
		case ApplicationExtendedRequest:
			responsePacket := encodeLDAPResponse(messageID, ApplicationExtendedResponse, LDAPResultProtocolError, "Unsupported extended request")
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
			}
			break handler
		case ApplicationAbandonRequest:
			log.Printf("Abandoning request!")
			break handler

			// Unimplemented LDAP operations:
		case ApplicationModifyRequest:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler
		case ApplicationAddRequest:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler
		case ApplicationDelRequest:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler
		case ApplicationModifyDNRequest:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler
		case ApplicationCompareRequest:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			break handler
		}
	}

	for _, c := range server.closeFns {
		c.Close(conn)
	}

	conn.Close()
}

/////////////////////////
func (server *Server) handleSearchRequest(req *ber.Packet, messageID uint64, boundDN string, searchFns map[string]Searcher, conn net.Conn) (resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			resultErr = NewError(LDAPResultOperationsError, fmt.Errorf("Search function panic: %s", r))
		}
	}()

	searchReq, err := parseSearchRequest(boundDN, req)
	if err != nil {
		return NewError(LDAPResultOperationsError, err)
	}

	filterPacket, err := CompileFilter(searchReq.Filter)
	if err != nil {
		return NewError(LDAPResultOperationsError, err)
	}

	fnNames := []string{}
	for k := range searchFns {
		fnNames = append(fnNames, k)
	}
	searchFn := routeFunc(searchReq.BaseDN, fnNames)
	searchResp, err := searchFns[searchFn].Search(boundDN, searchReq, conn)
	if err != nil {
		return NewError(uint8(searchResp.ResultCode), err)
	}

	if server.EnforceLDAP {
		if searchReq.DerefAliases != NeverDerefAliases { // [-a {never|always|search|find}
			// TODO: Server DerefAliases not implemented: RFC4511 4.5.1.3.  SearchRequest.derefAliases
		}
		if len(searchReq.Controls) > 0 {
			return NewError(LDAPResultOperationsError, errors.New("Server controls not implemented")) // TODO
		}
		if searchReq.TimeLimit > 0 {
			return NewError(LDAPResultOperationsError, errors.New("Server TimeLimit not implemented")) // TODO
		}
	}

	for i, entry := range searchResp.Entries {
		if server.EnforceLDAP {
			// size limit
			if searchReq.SizeLimit > 0 && i >= searchReq.SizeLimit {
				break
			}

			// filter
			keep, resultCode := ServerApplyFilter(filterPacket, entry)
			if resultCode != LDAPResultSuccess {
				return NewError(uint8(resultCode), errors.New("ServerApplyFilter error"))
			}
			if !keep {
				continue
			}

			// constrained search scope
			switch searchReq.Scope {
			case ScopeWholeSubtree: // The scope is constrained to the entry named by baseObject and to all its subordinates.
			case ScopeBaseObject: // The scope is constrained to the entry named by baseObject.
				if entry.DN != searchReq.BaseDN {
					continue
				}
			case ScopeSingleLevel: // The scope is constrained to the immediate subordinates of the entry named by baseObject.
				parts := strings.Split(entry.DN, ",")
				if len(parts) < 2 && entry.DN != searchReq.BaseDN {
					continue
				}
				if dn := strings.Join(parts[1:], ","); dn != searchReq.BaseDN {
					continue
				}
			}

			// attributes
			if len(searchReq.Attributes) > 1 || (len(searchReq.Attributes) == 1 && len(searchReq.Attributes[0]) > 0) {
				entry, err = filterAttributes(entry, searchReq.Attributes)
				if err != nil {
					return NewError(LDAPResultOperationsError, err)
				}
			}
		}

		// respond
		responsePacket := encodeSearchResponse(messageID, searchReq, entry)
		if err = sendPacket(conn, responsePacket); err != nil {
			return NewError(LDAPResultOperationsError, err)
		}
	}
	return nil
}

/////////////////////////
func (server *Server) handleBindRequest(req *ber.Packet, bindFns map[string]Binder, conn net.Conn) (resultCode uint64) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
		}
	}()

	// we only support ldapv3
	ldapVersion := req.Children[0].Value.(uint64)
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN := req.Children[1].Value.(string)
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			fnNames := []string{}
			for k := range bindFns {
				fnNames = append(fnNames, k)
			}
			bindFn := routeFunc(bindDN, fnNames)
			resultCode, err := bindFns[bindFn].Bind(bindDN, bindAuth.Data.String(), conn)
			if err != nil {
				log.Printf("BindFn Error %s", err.Error())
			}
			return resultCode
		} else {
			log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication
		}
	case LDAPBindAuthSASL:
		log.Print("SASL authentication is not supported")
		return LDAPResultInappropriateAuthentication
	}
	return LDAPResultOperationsError
}

/////////////////////////
func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())
		return err
	}
	return nil
}

/////////////////////////
func parseSearchRequest(boundDN string, req *ber.Packet) (SearchRequest, error) {
	if len(req.Children) != 8 {
		return SearchRequest{}, NewError(LDAPResultOperationsError, errors.New("Bad search request"))
	}

	// Parse the request
	baseObject := req.Children[0].Value.(string)
	scope := int(req.Children[1].Value.(uint64))
	derefAliases := int(req.Children[2].Value.(uint64))
	sizeLimit := int(req.Children[3].Value.(uint64))
	timeLimit := int(req.Children[4].Value.(uint64))
	typesOnly := false
	if req.Children[5].Value != nil {
		typesOnly = req.Children[5].Value.(bool)
	}
	filter, err := DecompileFilter(req.Children[6])
	if err != nil {
		return SearchRequest{}, err
	}
	attributes := []string{}
	for _, attr := range req.Children[7].Children {
		attributes = append(attributes, attr.Value.(string))
	}
	searchReq := SearchRequest{baseObject, scope,
		derefAliases, sizeLimit, timeLimit,
		typesOnly, filter, attributes, nil}

	return searchReq, nil
}

/////////////////////////
func routeFunc(dn string, funcNames []string) string {
	bestPick := ""
	for _, fn := range funcNames {
		if strings.HasSuffix(dn, fn) {
			l := len(strings.Split(bestPick, ","))
			if bestPick == "" {
				l = 0
			}
			if len(strings.Split(fn, ",")) > l {
				bestPick = fn
			}
		}
	}
	return bestPick
}

/////////////////////////
func filterAttributes(entry *Entry, attributes []string) (*Entry, error) {
	// only return requested attributes
	newAttributes := []*EntryAttribute{}

	for _, attr := range entry.Attributes {
		for _, requested := range attributes {
			if strings.ToLower(attr.Name) == strings.ToLower(requested) {
				newAttributes = append(newAttributes, attr)
			}
		}
	}
	entry.Attributes = newAttributes

	return entry, nil
}

/////////////////////////
type defaultHandler struct {
}

func (h defaultHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	return LDAPResultInappropriateAuthentication, nil
}
func (h defaultHandler) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}, nil
}
func (h defaultHandler) Close(conn net.Conn) error {
	conn.Close()
	return nil
}

/////////////////////////
func encodeBindResponse(messageID uint64, ldapResultCode uint64) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldapResultCode, "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
func encodeSearchResponse(messageID uint64, req SearchRequest, res *Entry) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
	searchEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.DN, "Object Name"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes:")
	for _, attribute := range res.Attributes {
		attrs.AppendChild(encodeSearchAttribute(attribute.Name, attribute.Values))
	}

	searchEntry.AppendChild(attrs)
	responsePacket.AppendChild(searchEntry)

	return responsePacket
}

func encodeSearchAttribute(name string, values []string) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))

	valuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
	for _, value := range values {
		valuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Attribute Value"))
	}

	packet.AppendChild(valuesPacket)

	return packet
}

func encodeSearchDone(messageID uint64, ldapResultCode uint64) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	donePacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search result done")
	donePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldapResultCode, "resultCode: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))
	responsePacket.AppendChild(donePacket)

	return responsePacket
}

func encodeLDAPResponse(messageID uint64, responseType uint8, ldapResultCode uint64, message string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	reponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, responseType, nil, ApplicationMap[responseType])
	reponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldapResultCode, "resultCode: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "errorMessage: "))
	responsePacket.AppendChild(reponse)
	return responsePacket
}

/////////////////////////
func (stats *Stats) countConns(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Conns += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countBinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Binds += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countUnbinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Unbinds += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countSearches(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Searches += delta
		stats.statsMutex.Unlock()
	}
}

/////////////////////////
