"""
Library to parse output (stdout) of kubectl command
"""

def parse_kubectl_get_pods(stdout):
    """Parse kubectl get pods output"""
    lines = stdout.splitlines()
    result = {}
    if "No resources found." in stdout:
        return result
    kws = lines[0].split()
    for line in lines[1:]:
        parsed_line = line.split()
        item = {}
        for i in range(len(kws)):
            item[kws[i]] = parsed_line[i]
        print item, kws
        name = item.pop('NAME')
        result[name] = item
    return result

def parse_kubectl_get_pods_and_get_pod_name(stdout, pod_prefix):
    """Get list of pod names with given prefix"""
    pods = parse_kubectl_get_pods(stdout)
    print pods
    pod = [pod_name for pod_name, pod_value in pods.iteritems() if pod_prefix in pod_name]
    return pod
    

def parse_kubectl_describe_pod(stdout):
    """Parse kubectl describe pod output"""
    lines = stdout.splitlines()
    result = {}
    info = ["IP", "Name", "Status"]
    for line in lines:
        for item in info:
            if line.startswith("{}: ".format(item)):
                result[item] = line.split(":")[-1].strip()
    name = result.pop("Name")
    return {name: result}
