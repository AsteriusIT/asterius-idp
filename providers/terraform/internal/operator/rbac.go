package operator

import "context"

type RoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}
type RBACSubject struct {
	Kind     string `json:"kind"`
	APIGroup string `json:"apiGroup"`
	Name     string `json:"name"`
}
type RoleBinding struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   Metadata      `json:"metadata"`
	RoleRef    RoleRef       `json:"roleRef"`
	Subjects   []RBACSubject `json:"subjects"`
}

// Exact pre-existing RoleBindings only. This adapter never creates/deletes a binding.
func (k *Kube) GetRoleBinding(ctx context.Context, name string) (RoleBinding, error) {
	var out RoleBinding
	err := k.request(ctx, "GET", "/apis/rbac.authorization.k8s.io/v1/namespaces/"+k.namespace+"/rolebindings/"+name, nil, &out)
	return out, err
}
func (k *Kube) PatchRoleBindingSubjects(ctx context.Context, name, uid, version string, subjects []RBACSubject) error {
	return k.request(ctx, "PATCH", "/apis/rbac.authorization.k8s.io/v1/namespaces/"+k.namespace+"/rolebindings/"+name,
		map[string]any{"metadata": map[string]string{"uid": uid, "resourceVersion": version}, "subjects": subjects}, nil)
}
