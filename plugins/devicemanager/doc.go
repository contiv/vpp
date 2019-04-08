// Package devicemanager is responsible for allocation & connection of special devices that may need
// to be connected to pods in case they are defined in resources section of a pod definition.
//
// The only supported device as of now is contivpp.io/memif - e.g.:
//
// spec:
//  containers:
//    - name: test-container
//      resources:
//        requests:
//          contivpp.io/memif: 1
//        limits:
//          contivpp.io/memif: 1
//
package devicemanager
