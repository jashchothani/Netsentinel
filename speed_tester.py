import speedtest
from system_logger import log_event

def run_speed_test():
    """Runs a real bandwidth test and returns the metrics."""
    print("[SYSTEM] Initiating active bandwidth speed test. This takes ~15 seconds...")
    try:
        st = speedtest.Speedtest()
        
        # 1. Find the best server based on ping
        st.get_best_server()
        ping_ms = st.results.ping
        
        # 2. Test Download (Returns bits/s, we convert to Mbps)
        print("[SYSTEM] Testing download speed...")
        download_bps = st.download()
        download_mbps = round(download_bps / 1_000_000, 2)
        
        # 3. Test Upload
        print("[SYSTEM] Testing upload speed...")
        upload_bps = st.upload()
        upload_mbps = round(upload_bps / 1_000_000, 2)
        
        # Log the test to your central database
        log_event("Network", "Info", f"Speedtest completed: DL {download_mbps} Mbps | UL {upload_mbps} Mbps | Ping {ping_ms} ms")
        
        return {
            "success": True,
            "ping": ping_ms,
            "download": download_mbps,
            "upload": upload_mbps
        }
    except Exception as e:
        print(f"[ERROR] Speedtest failed: {e}")
        log_event("Network", "Error", f"Bandwidth speed test failed: {str(e)}")
        return {"success": False, "error": str(e)}