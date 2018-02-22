package ldap

import (
	"log"
	"net"

	"gopkg.in/asn1-ber.v1"
)

func HandleBindRequest(req *ber.Packet, fn BindHandler, conn net.Conn) (resultCode LDAPResultCode, done bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
		}
	}()

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(uint64)
	if !ok {
		return LDAPResultProtocolError, false, nil
	}
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication, false, nil
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError, false, nil
	}
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			resultCode, err := fn.Bind(bindDN, bindAuth.Data.String(), conn)
			if err != nil {
				return LDAPResultOperationsError, false, err
			}
			return resultCode, true, nil
		} else {
			return LDAPResultInappropriateAuthentication, false, nil
		}
	case LDAPBindAuthSASL:
		saslFn, ok := fn.(BindSASLHandler)
		if !ok {
			return LDAPResultInappropriateAuthentication, false, nil
		}
		var resultCode LDAPResultCode
		var isDone bool
		var err error
		if len(req.Children) == 3 {
			resultCode, isDone, err = fn.BindSASL(bindDN, req.Children[2].Data.String(), "", conn)
		} else if len(req.Children) == 4 {
			resultCode, isDone, err = fn.BindSASL(bindDN, req.Children[2].Data.String(), req.Children[3].Data.String(), conn)
		}
		return resultCode, isDone, err
	}
	return LDAPResultOperationsError, false, nil
}

func encodeBindResponse(messageID uint64, ldapResultCode LDAPResultCode) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
