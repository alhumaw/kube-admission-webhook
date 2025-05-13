# kube-admission-webhook
- This is a kubernettes admission webhook utlizing validating admission webhooks. 

## What it Does
- Scans docker images for vulnerabilities and checks the version if it is High or Critical.
- 
## How it Works
- When building a container image the API that this webhook utilizes will flag potentially dangerous conatiners to initialized.
- Once flagged the webhook will reject building the image based on CVE's pulled utlizing `grype`.
- If the version of the image version is below High then the image will be built with no obstruction.

## To Run
- Ensure that docker, kubernettes, and python3 are installed.
	- `git clone https://github.com/alhumaw/kube-admission-webhook.git`
- Navigate to kube-admission-webhooks.
	- `docker <directory>  build <your_username>/kube-admission-webhook:latest .`
	- `docker push <your_username>/kube-admission-webhook:latest`
- Deploy kubernettes cluster
	- `kubectl apply -f deploy/app-dep.yaml`
	- `kubectl apply -f deploy/app-svc.yaml`
	- `kubectl apply -f deploy/webhook.yaml`
- Validate webhook
	- `kubectl logs -l app=kube-admission-webhook -n <namespace>`
