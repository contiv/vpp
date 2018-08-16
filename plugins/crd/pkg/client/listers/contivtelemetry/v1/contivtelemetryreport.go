// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivtelemetry/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ContivTelemetryReportLister helps list ContivTelemetryReports.
type ContivTelemetryReportLister interface {
	// List lists all ContivTelemetryReports in the indexer.
	List(selector labels.Selector) (ret []*v1.ContivTelemetryReport, err error)
	// ContivTelemetryReports returns an object that can list and get ContivTelemetryReports.
	ContivTelemetryReports(namespace string) ContivTelemetryReportNamespaceLister
	ContivTelemetryReportListerExpansion
}

// contivTelemetryReportLister implements the ContivTelemetryReportLister interface.
type contivTelemetryReportLister struct {
	indexer cache.Indexer
}

// NewContivTelemetryReportLister returns a new ContivTelemetryReportLister.
func NewContivTelemetryReportLister(indexer cache.Indexer) ContivTelemetryReportLister {
	return &contivTelemetryReportLister{indexer: indexer}
}

// List lists all ContivTelemetryReports in the indexer.
func (s *contivTelemetryReportLister) List(selector labels.Selector) (ret []*v1.ContivTelemetryReport, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ContivTelemetryReport))
	})
	return ret, err
}

// ContivTelemetryReports returns an object that can list and get ContivTelemetryReports.
func (s *contivTelemetryReportLister) ContivTelemetryReports(namespace string) ContivTelemetryReportNamespaceLister {
	return contivTelemetryReportNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ContivTelemetryReportNamespaceLister helps list and get ContivTelemetryReports.
type ContivTelemetryReportNamespaceLister interface {
	// List lists all ContivTelemetryReports in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.ContivTelemetryReport, err error)
	// Get retrieves the ContivTelemetryReport from the indexer for a given namespace and name.
	Get(name string) (*v1.ContivTelemetryReport, error)
	ContivTelemetryReportNamespaceListerExpansion
}

// contivTelemetryReportNamespaceLister implements the ContivTelemetryReportNamespaceLister
// interface.
type contivTelemetryReportNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ContivTelemetryReports in the indexer for a given namespace.
func (s contivTelemetryReportNamespaceLister) List(selector labels.Selector) (ret []*v1.ContivTelemetryReport, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ContivTelemetryReport))
	})
	return ret, err
}

// Get retrieves the ContivTelemetryReport from the indexer for a given namespace and name.
func (s contivTelemetryReportNamespaceLister) Get(name string) (*v1.ContivTelemetryReport, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("contivtelemetryreport"), name)
	}
	return obj.(*v1.ContivTelemetryReport), nil
}
