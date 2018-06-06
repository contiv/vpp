package ksr_test

import (
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
)

const (
	defaultName = "ksr"
	packageName = "ksr"
)

func TestDefaultWiring(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	err := plugin.Wire(plugin.DefaultWiring(true))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(defaultName))
	gomega.Expect(plugin.Log).ShouldNot(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).ShouldNot(gomega.BeNil())
}

func TestWithNameDefault(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	err := plugin.Wire(ksr.WithName(true))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(defaultName))
	gomega.Expect(plugin.Log).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).Should(gomega.BeNil())
}

func TestWithNameNonDefault(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	name := "foo"
	err := plugin.Wire(ksr.WithName(true, name))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(name))
	gomega.Expect(plugin.Log).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).Should(gomega.BeNil())
}

func TestWithLogNonDefault(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	log := logging.ForPlugin(defaultName, logrus.NewLogRegistry())
	err := plugin.Wire(ksr.WithLog(true, log))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.Log).Should(gomega.BeEquivalentTo(log))
	gomega.Expect(plugin.PluginConfig).Should(gomega.BeNil())
}

func TestNilWiring(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	err := plugin.Wire(nil)
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(defaultName))
	gomega.Expect(plugin.Log).ShouldNot(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).ShouldNot(gomega.BeNil())
}

func TestDefaultWiringOverwriteTrue(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	name := "foo"

	err := plugin.Wire(ksr.WithName(true, name))
	gomega.Expect(err).Should(gomega.BeNil())

	err = plugin.Wire(ksr.DefaultWiring(true))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(defaultName))
	gomega.Expect(plugin.Log).ShouldNot(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).ShouldNot(gomega.BeNil())

}

func TestWithNamePrefix(t *testing.T) {
	gomega.RegisterTestingT(t)
	plugin := &ksr.Plugin{}
	name := "foo"
	err := plugin.Wire(ksr.WithNamePrefix(true, name))
	gomega.Expect(err).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginName).Should(gomega.BeEquivalentTo(name + defaultName))
	gomega.Expect(plugin.Log).Should(gomega.BeNil())
	gomega.Expect(plugin.PluginConfig).Should(gomega.BeNil())
}
