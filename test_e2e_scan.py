import time
import requests
import zipfile
import io

BASE_URL = "http://localhost:8000"

def test_github_scan():
    print("\n[1/2] Testing GitHub Scan Endpoint...")
    payload = {
        "repo_url": "https://github.com/octocat/Hello-World"
    }
    resp = requests.post(f"{BASE_URL}/api/scans/github", json=payload)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.json()}")
    assert resp.status_code == 202, f"GitHub scan request failed: {resp.text}"
    scan_id = resp.json().get("scan_id")
    print(f"Scan ID: {scan_id}")
    
    # Poll until scan completes or fails
    for _ in range(60):
        time.sleep(3)
        poll_resp = requests.get(f"{BASE_URL}/api/scans/{scan_id}")
        data = poll_resp.json()
        status = data.get("status")
        progress = data.get("progress")
        print(f"Polling scan {scan_id}... Status: {status}, Progress: {progress}%")
        if status in ("COMPLETED", "FAILED"):
            print("Final Scan Details:", data)
            assert status == "COMPLETED", f"Scan failed: {data.get('failureReason')}"
            print(">>> GitHub scan passed successfully!")
            break

def test_zip_scan():
    print("\n[2/2] Testing ZIP Upload Scan Endpoint...")
    # Create in-memory zip containing a python file with a hardcoded secret
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "API_KEY = 'hardcoded_secret_key_12345'\n")
    zip_buffer.seek(0)
    
    files = {"file": ("test_app.zip", zip_buffer, "application/zip")}
    resp = requests.post(f"{BASE_URL}/api/scans/zip", files=files)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.json()}")
    assert resp.status_code == 202, f"ZIP upload scan request failed: {resp.text}"
    scan_id = resp.json().get("scan_id")
    print(f"Scan ID: {scan_id}")
    
    for _ in range(60):
        time.sleep(3)
        poll_resp = requests.get(f"{BASE_URL}/api/scans/{scan_id}")
        data = poll_resp.json()
        status = data.get("status")
        progress = data.get("progress")
        print(f"Polling scan {scan_id}... Status: {status}, Progress: {progress}%")
        if status in ("COMPLETED", "FAILED"):
            print("Final Scan Details:", data)
            assert status == "COMPLETED", f"Scan failed: {data.get('failureReason')}"
            print(">>> ZIP upload scan passed successfully!")
            break

if __name__ == "__main__":
    try:
        test_github_scan()
        test_zip_scan()
        print("\nALL E2E TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\nTest failed: {e}")

