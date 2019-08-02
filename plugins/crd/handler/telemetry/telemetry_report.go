package telemetry


import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"time"

	"k8s.io/apimachinery/pkg/util/runtime"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"
	"github.com/ligato/cn-infra/logging"

	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	listers "github.com/contiv/vpp/plugins/crd/pkg/client/listers/telemetry/v1"
)

//CRDReport implements generation of reports to CRD
type CRDReport struct {
	Deps

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

type Deps struct {
	Lister             listers.TelemetryReportLister
	Log                logging.Logger
	CollectionInterval time.Duration
	CrdClient          *crdClientSet.Clientset
}

// appendIfMissing is utility function to append to list only if it do not contains the data already
func appendIfMissing(slice []telemetrymodel.NodeInfo, i telemetrymodel.NodeInfo) []telemetrymodel.NodeInfo {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

//GenerateCRDReport updates the CRD status in Kubernetes with the current status from the sfc-controller
func (cr *CRDReport) GenerateCRDReport() {
	// Fetch crdContivTelemetry from K8s cache
	// The name in sfc is the namespace/name, which is the "namespace key". Split it out.

	key := "default/default-telemetry"
	namespace, name, err := k8sCache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return
	}

	var crdTelemetryReport *v1.TelemetryReport
	shouldCreate := false

	crdTelemetryReport, errGet := cr.Lister.TelemetryReports(namespace).Get(name)
	if errGet != nil {
		cr.Log.Errorf("Could not get '%s' with namespace '%s', err: %v", name, namespace, errGet)

		crdTelemetryReport = &v1.TelemetryReport{
			ObjectMeta: meta.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			TypeMeta: meta.TypeMeta{
				Kind:       "TelemetryReport",
				APIVersion: v1.CRDGroupVersion,
			},
			Spec: v1.TelemetryReportSpec{
				ReportPollingPeriodSeconds: uint32(cr.CollectionInterval.Seconds()),
			},
		}

		shouldCreate = true
	}

	crdTelemetryReportCopy := crdTelemetryReport.DeepCopy()
	crdTelemetryReportCopy.Status.UpdatedAt = time.Now().String()

	for _, node := range cr.VppCache.RetrieveAllNodes() {
		crdTelemetryReportCopy.Status.Nodes = appendIfMissing(crdTelemetryReportCopy.Status.Nodes, *node.NodeInfo)
	}

	crdTelemetryReportCopy.Status.Reports = cr.Report.RetrieveReport().DeepCopy()

	// Until #38113 is merged, we must use Update instead of UpdateStatus to
	// update the Status block of the NetworkNode resource. UpdateStatus will not
	// allow changes to the Spec of the resource, which is ideal for ensuring
	// nothing other than resource status has been updated.

	if shouldCreate {
		cr.Log.Debug("Create '%s' namespace '%s, and value: %v", name, namespace, crdTelemetryReportCopy)
		_, err = cr.CrdClient.TelemetryV1().TelemetryReports(namespace).Create(crdTelemetryReportCopy)
		if err != nil {
			cr.Log.Errorf("Could not create '%s'  err: %v, namespace '%s'", name, err, namespace)
		}
	} else {
		cr.Log.Debug("Update '%s' namespace '%s, and value: %v", name, namespace, crdTelemetryReportCopy)
		_, err := cr.CrdClient.TelemetryV1().TelemetryReports(namespace).Update(crdTelemetryReportCopy)
		if err != nil {
			cr.Log.Errorf("Could not update '%s'  err: %v, namespace '%s'", name, err, namespace)
		}
	}
}

