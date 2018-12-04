export class VppRouteModel {

  public dstIp: string;
  public nextHopIp: string;
  public outInterface: string;
  public weight: number;

  constructor(data: any) {
    if (data.Route) {
      this.dstIp = data.Route.dst_ip_addr;
      this.nextHopIp = data.Route.next_hop_addr;
      this.outInterface = data.Route.outgoing_interface;
      this.weight = data.Route.weight;
    }
  }

}
