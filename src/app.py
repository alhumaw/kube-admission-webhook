from flask import Flask, request, jsonify
import ssl, json, logging
import subprocess
import datetime
import shutil
import os
import uuid

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route("/validate", methods=["POST"])
def cve_scan():
    review = request.get_json()
    uid    = review["request"]["uid"]
    now = datetime.datetime.now()

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

            if allowed:
                # check bad commands (new)
                flagCMD, respCMD = check_commands_system(review)
                if not flagCMD:
                    allowed = False
                    msg = respCMD
                    break

            # time check (new)
            if allowed:
                flagCMD, respCMD = check_time(review, now)
                if not flagCMD:
                    allowed = False
                    msg = respCMD
                    break

            # check binaries (new)
            if allowed:
                flagCMD, respCMD = check_bin(img)
                if not flagCMD:
                    allowed = False
                    msg = respCMD
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

# function to check bad commands
def check_commands_system(review):
    con = review["request"]["object"]["spec"]["containers"]
    flag = True
    command = []
    # just some dump commands
    bad = ['curl', 'wget', 'bash', 'nc', 'telnet', 'socat', 'nmap', 'chmod 777', 'bin', 'sh', '/bin/sh']
    #badCmds = imgs.get("command", [])
    # search for comands and flag if bad commands found
    for c in con:
        name = c.get("name", "unknown")
        badCmds = c.get("command", [])
        for cmd in badCmds:
            for i in bad:
                if i in cmd:
                    flag = False
                    command.append(f"Container {name} uses restricted command: {i}") 
    return flag, " ".join(command)

def check_time(review, time):
    flag = True
    comment = ""
    # set time
    clientHour = time.hour
    clientMinute = time.minute
    con = review["request"]["object"]["spec"]["containers"]
    # get name and timestamp
    for c in con:
        name = c.get("name", "unknown")
        if clientHour < 9 or clientHour > 17:
            flag = False
            comment = f"Time deployment restriction: Container {name} did not deploy at {clientHour}:{clientMinute}. Can only deploy between hours 9-17"
    return flag, comment

def check_bin(review):
    #flag = True
    #comment = ""
    #crew = review["request"]["object"]["spec"]["containers"]
    # sus binaries
    sus = ["nc", "nmap", "socat", "xmrig", "netcat", "minerd", "bash", "curl", "wget"]
    amongus = []
    # collect suspicious binaries
    ship =  ["/bin", "/usr/bin", "/usr/local/bin"]
    crewID = f"susp-scan-{uuid.uuid4().hex[:8]}"
    try:
        # Pulls and creates a stopped container/ Does not run it
        subprocess.run(["docker", "pull", review], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        create = subprocess.run(["docker", "create", "--name", crewID, review], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check if container creation failed
        if create.returncode != 0:
            return False, f"Failed to create container from image: {create.stderr.strip()}"
        # temp path for storing container file systems
        pathing = f"/tmp/{crewID}.tar"
        # export the files as a tar
        with open(pathing, "wb") as file:
            subprocess.run(["docker", "export", crewID], stdout=file)
        # create directory to extract the tar file
        extract_dir = f"/tmp/{crewID}"
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(["tar", "-xf", pathing, "-C", extract_dir])
        # search for sus binaries
        for subdir in ship:
            full_dir = os.path.join(extract_dir, subdir.lstrip("/"))
            if not os.path.isdir(full_dir):
                continue
            for fname in os.listdir(full_dir):
                if fname in sus:
                    amongus.append(os.path.join(subdir, fname))
        # flag if found binaries
        if amongus:
            return False, f"Image {review} contains suspicious binaries: {', '.join(amongus)}"
        return True, ""


    except Exception as e:
        return False, f"Error scanning image: {e}"
    # delete temp conatiner
    finally:
        subprocess.run(["docker", "rm", "-f", crewID], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            os.remove(pathing)
            shutil.rmtree(extract_dir)
        except:
            pass


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
