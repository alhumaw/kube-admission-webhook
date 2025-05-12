from flask import Flask, request, jsonify
import ssl, json, logging
import subprocess

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route("/validate", methods=["POST"])
def cve_scan():
    review = request.get_json()
    uid    = review["request"]["uid"]

    allowed = True
    msg     = ""

    try:
        imgs = [
            c["image"]
            for c in review["request"]["object"]["spec"]["containers"]
        ]
        for img in imgs:
            # run grype in JSON mode, capture both streams
            proc = subprocess.run(
                ["grype", img, "-o", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # log returncode, stdout, stderr for debugging
            logging.info("grype rc=%d stdout=%r stderr=%r",
                         proc.returncode, proc.stdout, proc.stderr)

            # if grype itself failed, surface the stderr
            if proc.returncode != 0 or not proc.stdout:
                allowed = False
                msg     = f"grype error scanning {img}: {proc.stderr.strip()}"
                break

            # parse the JSON
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                allowed = False
                msg     = f"invalid JSON from grype for {img}: {e}"
                break

            matches = data.get("matches", [])
            bad     = [
                v for v in matches
                if v["vulnerability"]["severity"] in ("High","Critical")
            ]
            if bad:
                allowed = False
                msg     = f"{img} has {len(bad)} high/critical CVEs"
                break

    except Exception as e:
        allowed = False
        msg     = str(e)

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind":       "AdmissionReview",
        "response": {
            "uid":     uid,
            "allowed": allowed,
            "status": {
                "message": msg
            }
        }
    }
    return jsonify(response)


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile='/etc/webhook/tls/tls.crt',
        keyfile ='/etc/webhook/tls/tls.key'
    )
    app.run(host='0.0.0.0', port=443, ssl_context=context)
