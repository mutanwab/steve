package accesscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/sirupsen/logrus"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/user"
)

type AccessSetLookup interface {
	AccessFor(user user.Info) *AccessSet
	PurgeUserData(id string)
}

type AccessStore struct {
	users     *policyRuleIndex
	groups    *policyRuleIndex
	cache     *cache.LRUExpireCache
	UsersKeys sync.Map
}

type roleKey struct {
	namespace string
	name      string
}

func NewAccessStore(ctx context.Context, cacheResults bool, rbac v1.Interface) *AccessStore {
	revisions := newRoleRevision(ctx, rbac)
	as := &AccessStore{
		users:     newPolicyRuleIndex(true, revisions, rbac),
		groups:    newPolicyRuleIndex(false, revisions, rbac),
		UsersKeys: sync.Map{},
	}
	if cacheResults {
		as.cache = cache.NewLRUExpireCache(50)
	}
	return as
}

func (l *AccessStore) AccessFor(user user.Info) *AccessSet {
	var cacheKey string
	if l.cache != nil {
		cacheKey = l.CacheKey(user)
		val, ok := l.cache.Get(cacheKey)
		if ok {
			as, _ := val.(*AccessSet)
			return as
		}
	}

	result := l.users.get(user.GetName())
	for _, group := range user.GetGroups() {
		result.Merge(l.groups.get(group))
	}

	if l.cache != nil {
		result.ID = cacheKey
		l.cache.Add(cacheKey, result, 24*time.Hour)
	}

	return result
}

func (l *AccessStore) PurgeUserData(id string) {
	l.cache.Remove(id)
}

func (l *AccessStore) CacheKey(user user.Info) string {
	logrus.Info("==========user: %#v", user)
	d := sha256.New()

	l.users.addRolesToHash(d, user.GetName())

	groupBase := user.GetGroups()
	groups := make([]string, 0, len(groupBase))
	copy(groups, groupBase)

	sort.Strings(groups)
	for _, group := range user.GetGroups() {
		l.groups.addRolesToHash(d, group)
	}

	return hex.EncodeToString(d.Sum(nil))
}

func (l *AccessStore) CacheKeyGet(user user.Info) string {
	if strings.HasPrefix(user.GetName(), "u-") || strings.HasPrefix(user.GetName(), "user-") {
		key, ok := l.UsersKeys.Load(user.GetName())
		if ok {
			return key.(string)
		}
		return l.CacheKeyAdd(user)
	}
	return l.CacheKey(user)
}

func (l *AccessStore) CacheKeyAdd(user user.Info) string {
	key := l.CacheKey(user)
	l.UsersKeys.Store(user.GetName(), key)
	return key
}
