package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"gopkg.in/asn1-ber.v1"
)

var (
	ControlTypeNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
)

const (
	ApplicationSpecialOnPacket = 256 + 0
	ApplicationSpecialOnClose  = 256 + 1
)

var validRequestIDs = [...]uint16{
	ApplicationBindRequest,
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

	// owned by serve()
	nextConnID int64

	closeErr error
}

type Stats struct {
	Conns      int
	Binds      int
	Unbinds    int
	Searches   int
	statsMutex sync.Mutex
}

// Recieves notifications of all requests.
type PacketHandler interface {
	OnPacket(boundDN string, packet *ber.Packet, conn net.Conn)
}

// Recieves notifications when a connection is closed.
type CloseHandler interface {
	OnClose(boundDN string, conn net.Conn)
}

// Handles ApplicationBindRequest (0) requests.
type BindHandler interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error)
}

type BindSASLHandler interface {
	BindHandler
	BindSASL(bindDN string, mechanism string, credentials []byte, conn net.Conn) (res LDAPResultCode, err error)
}

// Handles ApplicationUnbindRequest (2) requests.
type UnbindHandler interface {
	Unbind(boundDN string, conn net.Conn)
}

// Handles ApplicationSearchRequest (3) requests.
//
// r.Body is of type ldap.SearchRequest.
type SearchHandler interface {
	Search(w ResponseWriter, r *Request) (ServerSearchResult, error)
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
// TODO - this should be done by the server using context.Context
type AbandonHandler interface {
	Abandon(boundDN string, conn net.Conn) error
}

// Handles ApplicationExtendedRequest (23) requests.
type ExtendedHandler interface {
	Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error)
}

type ResponseWriter interface {
	// Any write errors are stored, and returned by the Err() method.
	SendPacket(packet *ber.Packet)
	SendResult(respType uint8, resultCode LDAPResultCode, errMessage string)
	SendReferral(respType uint8, referTo []string, errMessage string)
	SendSASLBindResult(resultCode LDAPResultCode, serverCreds string, errMessage string)
	SendExtendedResponse(resultCode LDAPResultCode, oid string, value string, errMessage string)

	AddControl(c Control)
	SetMatchedDN(matchedDN string)
	Err() error
}

type Request struct {
	conn   net.Conn
	connID int64
	ctx    context.Context

	// The Distinguished Name that the client has authenticated for.
	BoundDN string

	// Protocol Identifier for the request, e.g. ApplicationModifyRequest.  In
	// the case of special handlers (OnClose etc), the value will be >255.
	PacketID uint16

	// Controls sent with the request
	Controls []Control

	fullPacket *ber.Packet
	reqData    *ber.Packet

	// Body can be cast to one of the Request types, e.g. ModifyRequest.
	// In certain cases, it may not be set (e.g. OnPacket handlers).
	Body RequestBody
}

// A RequestBody can be encoded to be sent to the LDAP server.
type RequestBody interface {
	encode() *ber.Packet
}

// Use the ConnID to identify the connection when storing data related to the
// client.  Make sure to implement CloseHandler so you know when to clean up
// client data.
func (r *Request) GetConnID() int64 {
	return r.connID
}

// Returns the underlying net.Conn.
func (r *Request) Conn() net.Conn {
	return r.conn
}

func (r *Request) Context() context.Context {
	return r.ctx
}

func (r *Request) FullPacket() *ber.Packet {
	return r.fullPacket
}

func (r *Request) GetData() *ber.Packet {
	return r.reqData
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

// Get the handler map for a given request type.
//
// this function is dirty: callers can do bad things with it
func (server *Server) GetHandlers(reqCode uint16) map[string]interface{} {
	return server.Handlers[reqCode]
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

// Note: you will need to use this function if you need a custom tls.Config
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
				server.ctxCancel()
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
			server.nextConnID++
			go server.handleConnection(c, server.nextConnID)
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

const (
	TagLDAPDN     = ber.TagOctetString
	TagLDAPString = ber.TagOctetString
)

type responseWriter struct {
	conn      net.Conn
	writeErr  error
	boundDN   string
	matchDN   string
	messageID uint64
	controls  []Control

	hasWrittenResponse bool
}

func (w *responseWriter) SendPacket(packet *ber.Packet) {
	_, err := w.conn.Write(packet.Bytes())
	w.hasWrittenResponse = true
	if err != nil {
		w.writeErr = err
	}
}

func (w *responseWriter) Err() error {
	return w.writeErr
}

func (w *responseWriter) SetMatchedDN(dn string) {
	w.matchDN = dn
}

func (w *responseWriter) AddControl(c Control) {
	// TODO
}

func (w *responseWriter) basicLDAPResult(respType uint8, resultCode LDAPResultCode, errMessage string) *ber.Packet {
	// 4.1.10 LDAPResult
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ber.Tag(respType), nil, ApplicationMap[respType],
	)
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagEnumerated, uint64(resultCode), "resultCode",
	))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
		TagLDAPDN, w.matchDN, "matchedDN",
	))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
		TagLDAPString, errMessage, "errMessage",
	))
	return response
}

func (w *responseWriter) SendResult(respType uint8, resultCode LDAPResultCode, errMessage string) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed,
		ber.TagSequence, nil, "LDAP Response",
	)
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagInteger, w.messageID, "msg ID",
	))

	response := w.basicLDAPResult(respType, resultCode, errMessage)
	packet.AppendChild(response)
	w.SendPacket(packet)
}

func (w *responseWriter) SendReferral(respType uint8, referTo []string, errMessage string) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed,
		ber.TagSequence, nil, "LDAP Response",
	)
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagInteger, w.messageID, "msg ID",
	))

	response := w.basicLDAPResult(respType, LDAPResultReferral, errMessage)
	referral := ber.Encode(ber.ClassContext, ber.TypeConstructed,
		ber.Tag(3), nil, "[3] Referral: SEQUENCE OF LDAPURL",
	)
	for _, v := range referTo {
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
			TagLDAPString, v, "",
		))
	}

	response.AppendChild(referral)
	packet.AppendChild(response)
	w.SendPacket(packet)
}

func (w *responseWriter) SendSASLBindResult(resultCode LDAPResultCode, serverCreds string, errMessage string) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed,
		ber.TagSequence, nil, "LDAP Response",
	)
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagInteger, w.messageID, "msg ID",
	))

	response := w.basicLDAPResult(
		ApplicationBindResponse,
		resultCode, errMessage,
	)
	response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
		ber.Tag(7), serverCreds, "serverSaslCreds [7] OCTET STRING",
	))

	packet.AppendChild(response)
	w.SendPacket(packet)
}

func (w *responseWriter) SendExtendedResponse(resultCode LDAPResultCode, oid string, value string, errMessage string) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed,
		ber.TagSequence, nil, "LDAP Response",
	)
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagInteger, w.messageID, "msg ID",
	))
	response := w.basicLDAPResult(
		ApplicationExtendedResponse,
		resultCode, errMessage,
	)
	if oid != "" {
		response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
			ber.Tag(10), oid, "responseName [10] LDAPOID OPTIONAL",
		))
	}
	if value != "" {
		response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
			ber.Tag(11), string(value), "responseValue [11] OCTET STRING OPTIONAL",
		))
	}
	packet.AppendChild(response)
	w.SendPacket(packet)
}

func sendAbnormalClose(w ResponseWriter, code LDAPResultCode, msg string) {
	fmt.Printf("Closing connection %s: %s %s\n", w.Conn().RemoteAddr(), LDAPResultCodeMap[code], msg)
	w.SendExtendedResponse(code, msg, ControlTypeNoticeOfDisconnection, "")
}

func isSuccessResult(code LDAPResultCode) bool {
	return code == LDAPResultSuccess || code == LDAPResultCompareFalse || code == LDAPResultCompareTrue || code == LDAPResultReferral || code == LDAPResultSaslBindInProgress
}

func errToResultCode(code LDAPResultCode, err error) (LDAPResultCode, string) {
	if err == nil {
		// Success codes
		if isSuccessResult(code) {
			return code, ""
		}
		return code, LDAPResultCodeMap[code]
	}

	if err == context.DeadlineExceeded {
		return LDAPResultTimeLimitExceeded, "time limit exceeded"
	} else if err == context.Canceled {
		return LDAPResultTimeLimitExceeded, "operation aborted"
	}

	// TODO - handle more different error types

	return code, err.Error()
}

func (server *Server) handleConnection(conn net.Conn, connID int64) {
	defer func() {
		if rec := recover(); rec != nil {
			// we use pkg/errors to print a stacktrace
			if recErr, ok := rec.(error); ok {
				fmt.Fprintf(os.Stderr, "ldap: %+v\n", errors.Wrap(recErr, "error in handleConnection"))
			} else {
				fmt.Fprintf(os.Stderr, "ldap: %+v\n", errors.Errorf("panic in handleConnection: %#v", rec))
			}
		}
	}()

	// TODO - make a clientconn struct
	boundDN := "" // "" == anonymous

	ctx, cancel := context.WithCancel(server.ctx)
	defer cancel()

handler:
	for {
		w := responseWriter{
			conn:    conn,
			boundDN: boundDN,
		}

		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF { // Client closed connection
			break
		} else if err != nil {
			sendAbnormalClose(&w, LDAPResultProtocolError, "read error")
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			sendAbnormalClose(&w, LDAPResultProtocolError, "not enough items in SEQUENCE")
			break
		}
		// check the message ID and ClassType
		messageID, ok := packet.Children[0].Value.(uint64)
		if !ok {
			sendAbnormalClose(&w, LDAPResultProtocolError, "malformed messageID")
			break
		}
		w.messageID = messageID
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			sendAbnormalClose(&w, LDAPResultProtocolError, "malformed message: second-level BER not ClassApplication")
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

		// casting to uint8 first so clients can't select the Special handlers
		handlerFn := routeFunc(boundDN, server.Handlers[uint16(uint8(req.Tag))])

		ldapReq := &Request{
			conn:       conn,
			connID:     connID,
			BoundDN:    boundDN,
			PacketID:   uint16(req.Tag),
			fullPacket: packet,
			reqData:    req,
			Controls:   controls,
			ctx:        ctx,
		}

		for _, fn := range server.Handlers[ApplicationSpecialOnPacket] {
			fn.(PacketHandler).OnPacket(boundDN, packet, conn)
		}

		var resultCode LDAPResultCode
		// var err error
		var errMsg string

		switch req.Tag { // ldap op code
		default:
			sendAbnormalClose(&w, LDAPResultProtocolError, fmt.Sprintf("Unsupported request ID %v", req.Tag))
			break handler

		case ApplicationBindRequest:
			resultCode, err = dispatchBindRequest(&w, ldapReq, handlerFn.(BindHandler))
			if resultCode == LDAPResultSuccess {
				boundDN = req.Children[1].Value.(string)
			}

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationBindResponse, resultCode, errMsg)
			}
		case ApplicationUnbindRequest:
			server.Stats.countUnbinds(1)
			handlerFn.(UnbindHandler).Unbind(boundDN, conn)
			break handler // Disconnect, client knows it's coming
		case ApplicationSearchRequest:
			server.Stats.countSearches(1)
			resultCode, err = dispatchSearchRequest(&w, ldapReq, handlerFn.(SearchHandler))

			resultCode, errMsg = errToResultCode(resultCode, err)
			w.SendPacket(encodeSearchDone(&w, resultCode, errMsg))
		case ApplicationExtendedRequest:
			resultCode, err = HandleExtendedRequest(req, boundDN, handlerFn.(ExtendedHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationExtendedResponse, resultCode, errMsg)
			}
		case ApplicationAbandonRequest:
			HandleAbandonRequest(req, boundDN, handlerFn.(AbandonHandler), conn)

		case ApplicationAddRequest:
			resultCode, err = HandleAddRequest(req, boundDN, handlerFn.(AddHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationAddResponse, resultCode, errMsg)
			}
		case ApplicationModifyRequest:
			resultCode, err = HandleModifyRequest(req, boundDN, handlerFn.(ModifyHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationModifyResponse, resultCode, errMsg)
			}
		case ApplicationDelRequest:
			resultCode, err = HandleDeleteRequest(req, boundDN, handlerFn.(DeleteHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationDelResponse, resultCode, errMsg)
			}
		case ApplicationModifyDNRequest:
			resultCode, err = HandleModifyDNRequest(req, boundDN, handlerFn.(ModifyDNHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationModifyDNResponse, resultCode, errMsg)
			}
		case ApplicationCompareRequest:
			resultCode, err = HandleCompareRequest(req, boundDN, handlerFn.(CompareHandler), conn)

			resultCode, errMsg = errToResultCode(resultCode, err)
			if !w.hasWrittenResponse {
				w.SendResult(ApplicationCompareResponse, resultCode, errMsg)
			}
		}

		// Check write errors
		if w.Err() != nil {
			log.Printf("send error on %s: %v", conn.RemoteAddr(), w.Err())
			break handler
		}
	} // loop handler

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
	for handlerDN, h := range handlers {
		if strings.HasSuffix(dn, handlerDN) {
			l := strings.Count(bestDN, ",")
			if bestDN == "" {
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
