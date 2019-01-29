import { Component, OnInit, OnDestroy, Output, EventEmitter } from '@angular/core';
import { Subscription } from 'rxjs';
import { SidepanelService } from './sidepanel.service';
import { Router, ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-sidepanel',
  templateUrl: './sidepanel.component.html',
  styleUrls: ['./sidepanel.component.css']
})
export class SidepanelComponent implements OnInit, OnDestroy {

  @Output() toggled = new EventEmitter<boolean>();

  private subscriptions: Subscription[];

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private sidepanelService: SidepanelService
  ) { }

  ngOnInit() {
    this.subscriptions = [];

    this.subscriptions.push(
      this.sidepanelService.getSpNodeItem().subscribe(item => {
        if (item.node) {
          this.openSidepanel();

          this.router.navigate([item.nodeType, item.node.id], {relativeTo: this.route});
        } else {
          if (item.topology === 'k8s') {
            if (this.router.url.includes('node')) {
              this.router.navigate(['nodes'], {relativeTo: this.route});
            } else if (this.router.url.includes('pod') || this.router.url.includes('vppPod') || this.router.url.includes('vswitch')) {
              this.router.navigate(['pods'], {relativeTo: this.route});
            }
          } else if (item.topology === 'vpp') {
            // this.closeSidepanel();
            this.router.navigate(['./'], {relativeTo: this.route});
          } else if (item.topology === 'bd') {
            this.closeSidepanel();
            this.router.navigate(['./'], {relativeTo: this.route});
          }
        }
      })
    );

    this.subscriptions.push(
      this.sidepanelService.getSpLinkItem().subscribe(item => {
        if (item.link && item.linkType) {
          this.openSidepanel();
          this.router.navigate([item.linkType, item.link.from, item.link.to], {relativeTo: this.route});
        }
      })
    );

    this.subscriptions.push(
      this.sidepanelService.getSidepanelState().subscribe(state => this.toggled.emit(state))
    );
  }

  public openSidepanel() {
    this.toggled.emit(true);
  }

  public closeSidepanel() {
    this.toggled.emit(false);
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
