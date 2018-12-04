export class AppConfig {
  public static K8S_REST_MASTER_URL = 'http://localhost:8080/';
  public static K8S_REST_WORKER1_URL = 'http://localhost:8081/';
  public static K8S_REST_WORKER2_URL = 'http://localhost:8082/';
  public static VPP_REST_MASTER_URL = 'http://localhost:9999/';
  public static VPP_REST_WORKER1_URL = 'http://localhost:9991/';
  public static VPP_REST_WORKER2_URL = 'http://localhost:9992/';
  public static API_V1 = 'api/v1/';
  public static API_V1_NETWORKING = 'apis/networking.k8s.io/v1/';
  public static API_V1_CONTIV = 'contiv/v1/';
  public static API_V1_VPP = 'vpp/dump/v1/';
}
