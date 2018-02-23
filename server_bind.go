package ldap

import (
	stdErrors "errors"
	"log"
)

func dispatchBindRequest(w ResponseWriter, ldapReq *Request, fn BindHandler) (resultCode LDAPResultCode, err error) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
			if rErr, ok := r.(error); ok {
				err = rErr
			}
		}
	}()

	req := ldapReq.reqBody

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(uint64)
	if !ok {
		return LDAPResultProtocolError, stdErrors.New("bad LDAP version")
	}
	if ldapVersion != 3 {
		return LDAPResultInappropriateAuthentication, stdErrors.New("bad LDAP version, expected 3")
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError, stdErrors.New("bad username")
	}
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			return fn.Bind(bindDN, bindAuth.Data.String(), conn)
		} else {
			return LDAPResultInappropriateAuthentication, stdErrors.New("bad simple-auth packet")
		}
	case LDAPBindAuthSASL:
		saslFn, ok := fn.(BindSASLHandler)
		if !ok {
			return LDAPResultInappropriateAuthentication, stdErrors.New("SASL auth not supported")
		}

		if len(req.Children) == 3 {
			return fn.BindSASL(bindDN, req.Children[2].Data.String(), nil, conn)
		} else if len(req.Children) == 4 {
			return fn.BindSASL(bindDN, req.Children[2].Data.String(), req.Children[3].Data.Bytes(), conn)
		}
	}
	return LDAPResultOperationsError, stdErrors.New("Internal server error")
}
