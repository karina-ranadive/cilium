// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// An alternative registration backend that writes spire-controller-manager
// ClusterSPIFFEID custom resources to the Kubernetes API server instead of
// calling the SPIRE server Entry API directly. A spire-controller-manager then
// reconciles these CRs into the SPIRE server datastore, making the Kubernetes
// API server the source of truth for registration intent.
//
// One ClusterSPIFFEID is created per enrolled namespace. It is scoped to that
// namespace via namespaceSelector and renders each pod's SPIFFE ID from the pod's
// namespace and service account. The parent ID is intentionally NOT set: the SPIRE
// server assigns it dynamically to the node agent that attests each pod, so the
// registration follows the workload across nodes with no CR change.

// clusterSPIFFEIDGVR is the GroupVersionResource for the spire-controller-manager
// ClusterSPIFFEID CRD (spire.spiffe.io/v1alpha1).
var clusterSPIFFEIDGVR = schema.GroupVersionResource{
	Group:    "spire.spiffe.io",
	Version:  "v1alpha1",
	Resource: "clusterspiffeids",
}

const (
	// crdManagedByLabel/Value tag every ClusterSPIFFEID this operator creates so
	// they can be listed and pruned without touching CRs owned by anything else.
	crdManagedByLabel = "app.kubernetes.io/managed-by"
	crdManagedByValue = "cilium-operator"
	// crdFieldManager is the server-side apply field manager for operator-owned fields.
	crdFieldManager = "cilium-operator-ztunnel"
	// maxCRDNameLen is the Kubernetes object name length limit.
	maxCRDNameLen = 63
)

// namespaceFromID extracts the namespace from a workload id of the form
// "namespace/serviceaccount".
func namespaceFromID(id string) string {
	return strings.SplitN(id, "/", 2)[0]
}

// crdSPIFFEIDName derives a deterministic, DNS-safe ClusterSPIFFEID name for a namespace.
// A namespace can be up to 63 chars, so the "ztunnel-" prefix can push the name past the
// 63-char object-name limit; when it would, truncate and append a short content hash to
// keep the name unique and within bounds.
func crdSPIFFEIDName(namespace string) string {
	name := "ztunnel-" + strings.ToLower(namespace)
	if len(name) <= maxCRDNameLen {
		return name
	}
	sum := sha256.Sum256([]byte(namespace))
	suffix := "-" + hex.EncodeToString(sum[:])[:8]
	return name[:maxCRDNameLen-len(suffix)] + suffix
}

// buildClusterSPIFFEID builds the unstructured ClusterSPIFFEID for a namespace.
// It matches all pods in the namespace and renders spiffe://<trustDomain>/ns/<ns>/sa/<sa>
// for each. No parentID is set; SPIRE assigns the attesting node agent dynamically.
func (c *Client) buildClusterSPIFFEID(namespace string) *unstructured.Unstructured {
	template := fmt.Sprintf(
		"spiffe://%s/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}",
		c.cfg.SpiffeTrustDomain,
	)

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "spire.spiffe.io",
		Version: "v1alpha1",
		Kind:    "ClusterSPIFFEID",
	})
	obj.SetName(crdSPIFFEIDName(namespace))
	obj.SetLabels(map[string]string{
		crdManagedByLabel: crdManagedByValue,
	})
	obj.Object["spec"] = map[string]any{
		"spiffeIDTemplate": template,
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{
				"kubernetes.io/metadata.name": namespace,
			},
		},
	}
	return obj
}

// upsertNamespaceCRD creates or updates the ClusterSPIFFEID for a namespace using
// server-side apply. Apply only owns the fields this operator sets (name, labels, spec),
// so it never clobbers fields owned by the spire-controller-manager (finalizers, status,
// className, etc.) the way a full-object Get+Update would.
func (c *Client) upsertNamespaceCRD(ctx context.Context, namespace string) error {
	if c.dynamicClient == nil {
		return fmt.Errorf("dynamic client not initialized")
	}
	desired := c.buildClusterSPIFFEID(namespace)
	_, err := c.dynamicClient.Resource(clusterSPIFFEIDGVR).Apply(
		ctx, desired.GetName(), desired,
		metav1.ApplyOptions{FieldManager: crdFieldManager, Force: true},
	)
	return err
}

// deleteNamespaceCRD deletes the ClusterSPIFFEID for a namespace (NotFound is ignored).
func (c *Client) deleteNamespaceCRD(ctx context.Context, namespace string) error {
	if c.dynamicClient == nil {
		return fmt.Errorf("dynamic client not initialized")
	}
	err := c.dynamicClient.Resource(clusterSPIFFEIDGVR).Delete(ctx, crdSPIFFEIDName(namespace), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// upsertCRD ensures the ClusterSPIFFEID for the id's namespace exists.
func (c *Client) upsertCRD(ctx context.Context, id string) error {
	return c.upsertNamespaceCRD(ctx, namespaceFromID(id))
}

// upsertCRDBatch ensures a ClusterSPIFFEID exists for each unique namespace in ids.
func (c *Client) upsertCRDBatch(ctx context.Context, ids []string) error {
	var errs []error
	for _, namespace := range uniqueNamespaces(ids) {
		if err := c.upsertNamespaceCRD(ctx, namespace); err != nil {
			errs = append(errs, fmt.Errorf("upsert ClusterSPIFFEID for namespace %s: %w", namespace, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("upsertCRDBatch had %d errors: %w", len(errs), errs[0])
	}
	c.log.Debug("upsertCRDBatch completed", logfields.Count, len(ids))
	return nil
}

// deleteCRD is a no-op: a single service account removal does not delete the
// namespace-scoped ClusterSPIFFEID; the controller-manager drops the entry when
// the pod goes away, and the CR is removed only when the namespace is unenrolled.
func (c *Client) deleteCRD(_ context.Context, _ string) error {
	return nil
}

// deleteCRDBatch deletes the ClusterSPIFFEID for each unique namespace in ids.
// This is invoked when a namespace is unenrolled.
func (c *Client) deleteCRDBatch(ctx context.Context, ids []string) error {
	var errs []error
	for _, namespace := range uniqueNamespaces(ids) {
		if err := c.deleteNamespaceCRD(ctx, namespace); err != nil {
			errs = append(errs, fmt.Errorf("delete ClusterSPIFFEID for namespace %s: %w", namespace, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("deleteCRDBatch had %d errors: %w", len(errs), errs[0])
	}
	c.log.Debug("deleteCRDBatch completed", logfields.Count, len(ids))
	return nil
}

// uniqueNamespaces returns the distinct namespaces from a list of "namespace/serviceaccount" ids.
func uniqueNamespaces(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	var namespaces []string
	for _, id := range ids {
		ns := namespaceFromID(id)
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		namespaces = append(namespaces, ns)
	}
	return namespaces
}
