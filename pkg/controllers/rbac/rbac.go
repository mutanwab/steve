package rbac

import (
	"context"
	asl "github.com/rancher/steve/pkg/accesscontrol"
	"github.com/rancher/steve/pkg/resources/common"
	rbacControllerV1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/rbac/v1"
	user2 "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/discovery"
	"sync"
)

type handler struct {
	sync.Mutex

	ctx      context.Context
	toSync   int32
	client   discovery.DiscoveryInterface
	cols     *common.DynamicColumns
	rb       rbacControllerV1.RoleBindingController
	crb      rbacControllerV1.ClusterRoleBindingController
	aslStore *asl.AccessStore
}

func Register(ctx context.Context,
	cols *common.DynamicColumns,
	discovery discovery.DiscoveryInterface,
	rb rbacControllerV1.RoleBindingController,
	crb rbacControllerV1.ClusterRoleBindingController,
	aslStore *asl.AccessStore) {

	h := &handler{
		ctx:      ctx,
		cols:     cols,
		client:   discovery,
		rb:       rb,
		crb:      crb,
		aslStore: aslStore,
	}

	crb.OnChange(ctx, "rbc-controller", h.OnChangeClusterRoleBinding)
	rb.OnChange(ctx, "rb-controller", h.OnChangeRoleBinding)
}

func (h *handler) OnChangeRoleBinding(key string, rb *v1.RoleBinding) (*v1.RoleBinding, error) {
	logrus.Info("===========rolebinding: %#v", rb)
	userName := ""
	for _, subject := range rb.Subjects {
		if subject.Kind == "User" {
			userName = subject.Name
		}
	}
	if userName == "" {
		return nil, nil
	}
	groups := make([]string, 0)
	groups = append(groups, "system:authenticated")
	groups = append(groups, "system:cattle:authenticated")
	user := &user2.DefaultInfo{
		Name:   userName,
		Groups: groups,
	}

	h.aslStore.CacheKeyAdd(user)

	return rb, nil
}

func (h *handler) OnChangeClusterRoleBinding(key string, crb *v1.ClusterRoleBinding) (*v1.ClusterRoleBinding, error) {
	logrus.Info("===========clusterrolebinding: %#v", crb)
	userName := ""
	for _, subject := range crb.Subjects {
		if subject.Kind == "User" {
			userName = subject.Name
		}
	}
	if userName == "" {
		return nil, nil
	}
	groups := make([]string, 0)
	groups = append(groups, "system:authenticated")
	groups = append(groups, "system:cattle:authenticated")
	user := &user2.DefaultInfo{
		Name:   userName,
		Groups: groups,
	}
	h.aslStore.CacheKeyAdd(user)
	return crb, nil
}
