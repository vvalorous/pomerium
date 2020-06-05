package identity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
)

var (
	maxTime     = time.Unix(1<<63-62135596801, 999999999)
	maxDuration = time.Duration(1<<63 - 1)
)

type managerSessionItem struct {
	*session.Session
	lastRefresh                   time.Time
	sessionRefreshCoolOffDuration time.Duration
}

func (item managerSessionItem) NextRefresh() time.Time {
	min := maxTime

	expires, err := ptypes.Timestamp(item.GetExpiresAt())
	if err == nil {
		if expires.Before(min) {
			min = expires
		}
	}

	oauthExpires, err := ptypes.Timestamp(item.GetExpiresAt())
	if err == nil {
		if oauthExpires.Before(min) {
			min = oauthExpires
		}
	}

	return getMaxTime(
		item.lastRefresh.Add(item.sessionRefreshCoolOffDuration),
		min,
	)
}

type managerUserItem struct {
	*user.User
	lastRefresh          time.Time
	groupRefreshInterval time.Duration
}

func (item managerUserItem) NextRefresh() time.Time {
	min := maxTime
	tm := item.lastRefresh.Add(item.groupRefreshInterval)
	if tm.Before(min) {
		min = tm
	}
	return min
}

type managerItem struct {
	session            *session.Session
	user               *user.User
	lastSessionRefresh time.Time
	lastGroupRefresh   time.Time

	sessionRefreshCoolOffDuration time.Duration
	groupRefreshInterval          time.Duration
}

func (item *managerItem) IsSessionExpired(now time.Time) bool {
	if item == nil || item.session == nil {
		return false
	}
	expiresAt, err := ptypes.Timestamp(item.session.ExpiresAt)
	if err != nil {
		return false
	}
	return expiresAt.Before(now)
}

func (item *managerItem) NextGroupRefreshTime() time.Time {
	min := maxTime
	if item != nil {
		tm := item.lastGroupRefresh.Add(item.groupRefreshInterval)
		if tm.Before(min) {
			min = tm
		}
	}
	return min
}

func (item *managerItem) NextSessionRefreshTime() time.Time {
	min := maxTime
	if item != nil && item.session != nil {
		expires, err := ptypes.Timestamp(item.session.GetExpiresAt())
		if err == nil {
			if expires.Before(min) {
				min = expires
			}
		}

		oauthExpires, err := ptypes.Timestamp(item.session.GetExpiresAt())
		if err == nil {
			if oauthExpires.Before(min) {
				min = oauthExpires
			}
		}
	}
	return getMaxTime(
		item.lastSessionRefresh.Add(item.sessionRefreshCoolOffDuration),
		min,
	)
}

func (item *managerItem) SessionID() string {
	if item.session == nil {
		return ""
	}
	return item.session.GetId()
}

func (item *managerItem) UserID() string {
	if item.user == nil {
		return ""
	}
	return item.user.GetId()
}

type managerItemByTimestamp struct {
	*managerItem
}

func (item managerItemByTimestamp) Less(than btree.Item) bool {
	x := item
	y := than.(managerItemByTimestamp)

	xtm := minTime(x.NextSessionRefreshTime(), x.NextGroupRefreshTime())
	ytm := minTime(y.NextSessionRefreshTime(), y.NextGroupRefreshTime())

	// first sort by timestamp
	switch {
	case xtm.Before(ytm):
		return true
	case ytm.Before(xtm):
		return false
	}

	// fallback to sorting by (user_id, session_id)
	return managerItemByID(x).Less(managerItemByID(y))
}

type managerItemByID struct {
	*managerItem
}

func (item managerItemByID) Less(than btree.Item) bool {
	x := item
	y := than.(managerItemByID)

	switch {
	case x.UserID() < y.UserID():
		return true
	case y.UserID() < x.UserID():
		return false
	}

	switch {
	case x.SessionID() < y.SessionID():
		return true
	case y.SessionID() < x.SessionID():
		return false
	}

	return false
}

func (item *managerItem) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// session fields

	if item.session == nil {
		item.session = new(session.Session)
	}

	if item.session.IdToken == nil {
		item.session.IdToken = new(session.IDToken)
	}

	if iss, ok := raw["iss"]; ok {
		_ = json.Unmarshal(iss, &item.session.IdToken.Issuer)
		delete(raw, "iss")
	}
	if sub, ok := raw["sub"]; ok {
		_ = json.Unmarshal(sub, &item.session.IdToken.Subject)
		delete(raw, "sub")
	}
	if exp, ok := raw["exp"]; ok {
		var secs int64
		if err := json.Unmarshal(exp, &secs); err == nil {
			item.session.IdToken.ExpiresAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "exp")
	}
	if iat, ok := raw["iat"]; ok {
		var secs int64
		if err := json.Unmarshal(iat, &secs); err == nil {
			item.session.IdToken.ExpiresAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "iat")
	}

	// user fields
	if item.user == nil {
		item.user = new(user.User)
	}

	item.user.Id = item.session.IdToken.Issuer + "/" + item.session.IdToken.Subject

	if email, ok := raw["email"]; ok {
		_ = json.Unmarshal(email, &item.user.Email)
		delete(raw, "email")
	}
	if groups, ok := raw["groups"]; ok {
		_ = json.Unmarshal(groups, &item.user.Groups)
		delete(raw, "groups")
	}

	item.session.Claims = make(map[string]*anypb.Any)
	for k, rawv := range raw {
		var v interface{}
		if json.Unmarshal(rawv, &v) != nil {
			continue
		}

		if anyv, err := toAny(v); err == nil {
			item.session.Claims[k] = anyv
		}
	}

	return nil
}

func toAny(value interface{}) (*anypb.Any, error) {
	switch v := value.(type) {
	case bool:
		return ptypes.MarshalAny(&wrapperspb.BoolValue{Value: v})
	case []byte:
		return ptypes.MarshalAny(&wrapperspb.BytesValue{Value: v})
	case float64:
		return ptypes.MarshalAny(&wrapperspb.DoubleValue{Value: v})
	case float32:
		return ptypes.MarshalAny(&wrapperspb.FloatValue{Value: v})
	case int32:
		return ptypes.MarshalAny(&wrapperspb.Int32Value{Value: v})
	case int64:
		return ptypes.MarshalAny(&wrapperspb.Int64Value{Value: v})
	case string:
		return ptypes.MarshalAny(&wrapperspb.StringValue{Value: v})
	case uint32:
		return ptypes.MarshalAny(&wrapperspb.UInt32Value{Value: v})
	case uint64:
		return ptypes.MarshalAny(&wrapperspb.UInt64Value{Value: v})
	}
	return nil, fmt.Errorf("unknown type %T", value)
}

func getStringClaim(claims map[string]*anypb.Any, field string) string {
	var str wrapperspb.StringValue
	ptypes.UnmarshalAny(claims[field], &str)
	return str.Value
}