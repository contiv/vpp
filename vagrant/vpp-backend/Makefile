
all: app

app:
	docker build -t contiv-ui .

run_debug:
	cd ui && npm install && node_modules/@angular/cli/bin/ng serve --host 0.0.0.0

.PHONY: all build app run_debug