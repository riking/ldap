package ldap

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"gopkg.in/asn1-ber.v1"
)

func (server *Server) dispatchSearchRequest(w ResponseWriter, ldapReq *Request, fn SearchHandler) (resultCode LDAPResultCode, resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			if rErr, ok := r.(error); ok {
				resultErr = errors.Wrap(rErr, "search panic")
			} else {
				resultErr = errors.Errorf("search panic: %v", r)
			}
		}
	}()

	searchReq, err := parseSearchRequest(ldapReq.BoundDN, ldapReq.reqBody, ldapReq.Controls)
	if err != nil {
		return LDAPResultOperationsError, err
	}

	filterPacket, err := CompileFilter(searchReq.Filter)
	if err != nil {
		return LDAPResultOperationsError, err
	}

	ctx := ldapReq.Context()
	if searchReq.TimeLimit > 0 {
		ctx_, cancel := context.WithTimeout(ldapReq.Context(), searchReq.TimeLimit*time.Second)
		defer cancel()
		ctx = ctx_
	}
	ldapReq.ctx = ctx
	ldapReq.Body = searchReq

	// TODO - allow for streaming searches.
	searchResp, err := fn.Search(boundDN, searchReq, conn)
	if err != nil {
		return searchResp.ResultCode, err
	}

	if server.EnforceLDAP {
		if searchReq.DerefAliases != NeverDerefAliases { // [-a {never|always|search|find}
			// Server DerefAliases not supported: RFC4511 4.5.1.3
			return LDAPResultOperationsError, errors.New("Server DerefAliases not supported")
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
				return NewError(resultCode, errors.New("ServerApplyFilter error"))
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
					return LDAPResultOperationsError, err
				}
			}
		}

		// respond
		responsePacket := encodeSearchResponse(messageID, searchReq, entry)
		if err = sendPacket(conn, responsePacket); err != nil {
			return LDAPResultOperationsError, err
		}
	}
	return LDAPResultSuccess, nil
}

/////////////////////////
func parseSearchRequest(boundDN string, req *ber.Packet, controls *[]Control) (SearchRequest, error) {
	if len(req.Children) != 8 {
		return SearchRequest{}, NewError(LDAPResultOperationsError, errors.New("Bad search request"))
	}

	// Parse the request
	baseObject, ok := req.Children[0].Value.(string)
	if !ok {
		return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
	}
	s, ok := req.Children[1].Value.(uint64)
	if !ok {
		return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
	}
	scope := int(s)
	d, ok := req.Children[2].Value.(uint64)
	if !ok {
		return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
	}
	derefAliases := int(d)
	s, ok = req.Children[3].Value.(uint64)
	if !ok {
		return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
	}
	sizeLimit := int(s)
	t, ok := req.Children[4].Value.(uint64)
	if !ok {
		return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
	}
	timeLimit := int(t)
	typesOnly := false
	if req.Children[5].Value != nil {
		typesOnly, ok = req.Children[5].Value.(bool)
		if !ok {
			return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
		}
	}
	filter, err := DecompileFilter(req.Children[6])
	if err != nil {
		return SearchRequest{}, err
	}
	attributes := []string{}
	for _, attr := range req.Children[7].Children {
		a, ok := attr.Value.(string)
		if !ok {
			return SearchRequest{}, NewError(LDAPResultProtocolError, errors.New("Bad search request"))
		}
		attributes = append(attributes, a)
	}
	searchReq := SearchRequest{baseObject, scope,
		derefAliases, sizeLimit, timeLimit,
		typesOnly, filter, attributes, *controls}

	return searchReq, nil
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

func encodeSearchDone(w ResponseWriter, ldapResultCode LDAPResultCode, errMsg string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed,
		ber.TagSequence, nil, "LDAP Response",
	)
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagInteger, w.messageID, "Message ID",
	))
	donePacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ApplicationSearchResultDone, nil, "Search result done",
	)
	donePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagEnumerated, uint64(ldapResultCode), "resultCode: ",
	))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagOctetString, w.matchedDN, "matchedDN: ",
	))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
		ber.TagOctetString, errMsg, "errorMessage: ",
	))
	responsePacket.AppendChild(donePacket)

	return responsePacket
}