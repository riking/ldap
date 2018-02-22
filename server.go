package ldap

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"gopkg.in/asn1-ber.v1"
)

// Recieves notifications of all requests.
type PacketHandler interface {
	OnPacket(boundDN string, packet *ber.Packet, conn net.Conn) (LDAPResultCode, error)
}

// Recieves notifications when a connection is closed.
type CloseHandler interface {
	OnClose(boundDN string, conn net.Conn) error
}

// Handles ApplicationBindRequest (0) requests.
type BindHandler interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationUnbindRequest (2) requests.
type UnbindHandler interface {
	Unbind(boundDN string, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationSearchRequest (3) requests.
type SearchHandler interface {
	Search(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error)
}

// Handles ApplicationModifyRequest (7) requests.
type ModifyHandler interface {
	Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationAddRequest (8) requests.
type AddHandler interface {
	Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationDeleteRequest (10) requests.
type DeleteHandler interface {
	Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationModifyDNRequest (12) requests.
type ModifyDNHandler interface {
	ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationCompareRequest (14) requests.
type CompareHandler interface {
	Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error)
}

// Handles ApplicationAbandonRequest (16) requests.
// TODO - this should be using context.Context
type AbandonHandler interface {
	Abandon(boundDN string, conn net.Conn) error
}

// Handles ApplicationExtendedRequest (23) requests.
type ExtendedHandler interface {
	Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error)
}

const (
	ApplicationSpecialOnPacket = 256 + 0
	ApplicationSpecialOnClose  = 256 + 1
)

var validRequestIDs = [...]uint16{ApplicationBindRequest,
	ApplicationUnbindRequest,
	ApplicationSearchRequest,
	ApplicationModifyRequest,
	ApplicationAddRequest,
	ApplicationDelRequest,
	ApplicationModifyDNRequest,
	ApplicationCompareRequest,
	ApplicationAbandonRequest,
	ApplicationExtendedRequest,
	ApplicationSpecialOnPacket,
	ApplicationSpecialOnClose,
}

// The handlerMap maps from Distinguished Name prefixes to the above interfaces.
type handlerMap map[string]interface{}

type Server struct {
	Handlers    map[uint16]handlerMap
	ctx         context.Context
	ctxCancel   func()
	EnforceLDAP bool
	Stats       *Stats

	closeErr error
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
	ResultCode LDAPResultCode
}

func NewServer() *Server {
	s := new(Server)
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.ctxCancel = cancel

	for _, reqID := range validRequestIDs {
		s.Handlers[reqID] = make(map[string]interface{})
	}
	s.Stats = nil
	return s
}

// HandleRequest binds all implemented handler functions on f to the given DN
// suffix.
//
// PacketHandler and CloseHandler are special, they ignore the given baseDN
// argument and instead select a unique internal identifier.
func (server *Server) HandleRequest(baseDN string, f interface{}) {
	matched := false

	if h, ok := f.(BindHandler); ok {
		server.Handlers[ApplicationBindRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(SearchHandler); ok {
		server.Handlers[ApplicationSearchRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(ModifyHandler); ok {
		server.Handlers[ApplicationModifyRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(AddHandler); ok {
		server.Handlers[ApplicationAddRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(DeleteHandler); ok {
		server.Handlers[ApplicationDelRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(ModifyDNHandler); ok {
		server.Handlers[ApplicationModifyDNRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(CompareHandler); ok {
		server.Handlers[ApplicationCompareRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(AbandonHandler); ok {
		server.Handlers[ApplicationAbandonRequest][baseDN] = h
		matched = true
	}
	if h, ok := f.(ExtendedHandler); ok {
		server.Handlers[ApplicationExtendedRequest][baseDN] = h
		matched = true
	}

	if h, ok := f.(PacketHandler); ok {
		m := server.Handlers[ApplicationSpecialOnPacket]
		m[strconv.Itoa(len(m))] = h
		matched = true
	}
	if h, ok := f.(CloseHandler); ok {
		m := server.Handlers[ApplicationSpecialOnClose]
		m[strconv.Itoa(len(m))] = h
		matched = true
	}

	if !matched {
		panic(errors.Errorf("ldap: Passed object (%T %v) does not satisfy any server handler interfaces", f, f))
	}
}

// Return the Context that will terminate when the server closes.
func (server *Server) Context() context.Context {
	return server.ctx
}

// (TODO) Start shutting down the server.
func (server *Server) Shutdown() error {
	server.ctxCancel()
	// TODO
	return server.closeErr
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
	return server.serve(ln)
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}
	return server.serve(ln)
}

func (server *Server) Serve(ln net.Listener) error {
	return server.serve(ln)
}

func (server *Server) serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()

			select {
			case <-server.ctx.Done():
				// server is closing, listener was closed
				break
			default:
			}

			if err != nil {
				server.closeErr = err
				log.Printf("Error accepting network connection: %s", err.Error())
				server.ctxClose()
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.Stats.countConns(1)
			go server.handleConnection(c)
		case <-server.ctx.Done():
			ln.Close()
			break listener
		}
	}
	return server.closeErr
}

func (server *Server) SetStats(enable bool) {
	if enable {
		server.Stats = &Stats{}
	} else {
		server.Stats = nil
	}
}

func (server *Server) GetStats() Stats {
	defer func() {
		server.Stats.statsMutex.Unlock()
	}()
	server.Stats.statsMutex.Lock()
	return *server.Stats
}

//
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
		messageID, ok := packet.Children[0].Value.(uint64)
		if !ok {
			log.Print("malformed messageID")
			break
		}
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			log.Print("req.ClassType != ber.ClassApplication")
			break
		}
		// handle controls if present
		controls := []Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				controls = append(controls, DecodeControl(child))
			}
		}

		//log.Printf("DEBUG: handling operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
		//ber.PrintPacket(packet) // DEBUG

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			responsePacket := encodeLDAPResponse(messageID, ApplicationAddResponse, LDAPResultOperationsError, "Unsupported operation: add")
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
			}
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[uint8(req.Tag)], req.Tag)
			break handler

		case ApplicationBindRequest:
			server.Stats.countBinds(1)
			ldapResultCode := HandleBindRequest(req, server.BindFns, conn)
			if ldapResultCode == LDAPResultSuccess {
				boundDN, ok = req.Children[1].Value.(string)
				if !ok {
					log.Printf("Malformed Bind DN")
					break handler
				}
			}
			responsePacket := encodeBindResponse(messageID, ldapResultCode)
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationSearchRequest:
			server.Stats.countSearches(1)
			if err := HandleSearchRequest(req, &controls, messageID, boundDN, server, conn); err != nil {
				log.Printf("handleSearchRequest error %s", err.Error()) // TODO: make this more testable/better err handling - stop using log, stop using breaks?
				e := err.(*Error)
				if err = sendPacket(conn, encodeSearchDone(messageID, e.ResultCode)); err != nil {
					log.Printf("sendPacket error %s", err.Error())
					break handler
				}
				break handler
			} else {
				if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultSuccess)); err != nil {
					log.Printf("sendPacket error %s", err.Error())
					break handler
				}
			}
		case ApplicationUnbindRequest:
			// TODO - call unbind handler
			server.Stats.countUnbinds(1)
			break handler // simply disconnect
		case ApplicationExtendedRequest:
			ldapResultCode := HandleExtendedRequest(req, boundDN, server.ExtendedFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationExtendedResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationAbandonRequest:
			HandleAbandonRequest(req, boundDN, server.AbandonFns, conn)
			break handler

		case ApplicationAddRequest:
			ldapResultCode := HandleAddRequest(req, boundDN, server.AddFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationAddResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationModifyRequest:
			ldapResultCode := HandleModifyRequest(req, boundDN, server.ModifyFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationModifyResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationDelRequest:
			ldapResultCode := HandleDeleteRequest(req, boundDN, server.DeleteFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationDelResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationModifyDNRequest:
			ldapResultCode := HandleModifyDNRequest(req, boundDN, server.ModifyDNFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationModifyDNResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationCompareRequest:
			ldapResultCode := HandleCompareRequest(req, boundDN, server.CompareFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationCompareResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		}
	}

	unbindH := routeFunc(boundDN, server.Handlers[ApplicationUnbindRequest])
	unbindH.(UnbindHandler).Unbind(boundDN, conn)

	for _, h := range server.Handlers[ApplicationSpecialOnClose] {
		h.(CloseHandler).OnClose(boundDN, conn)
	}

	conn.Close()
}

//
func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())
		return err
	}
	return nil
}

// Returns the best handler function for the given DN.
func routeFunc(dn string, handlers handlerMap) interface{} {
	bestDN := ""
	var bestHandler interface{} = nil
	for handlerDN, h := range funcNames {
		if strings.HasSuffix(dn, handlerDN) {
			l := strings.Count(bestDN, ",")
			if bestPick == "" {
				l = 0
			}
			if strings.Count(handlerDN, ",") > l || bestHandler == nil {
				bestDN = handlerDN
				bestHandler = h
			}
		}
	}
	if bestHandler == nil {
		return defaultHandler{}
	}
	return bestHandler
}

// TODO - reindent this
func encodeLDAPResponse(messageID uint64, responseType uint8, ldapResultCode LDAPResultCode, message string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	reponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(responseType), nil, ApplicationMap[uint8(responseType)])
	reponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "errorMessage: "))
	responsePacket.AppendChild(reponse)
	return responsePacket
}

//
type defaultHandler struct {
}

func (h defaultHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInvalidCredentials, nil
}

func (h defaultHandler) Search(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}, nil
}

func (h defaultHandler) Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}

func (h defaultHandler) Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}

func (h defaultHandler) Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}

func (h defaultHandler) ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}

func (h defaultHandler) Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}

func (h defaultHandler) Abandon(boundDN string, conn net.Conn) error {
	return nil
}

func (h defaultHandler) Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultProtocolError, nil
}

func (h defaultHandler) Unbind(boundDN string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultSuccess, nil
}

func (h defaultHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close()
	return nil
}

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
