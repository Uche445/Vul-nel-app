import time

def brute_force(service, host, wordlist):
    # Simulate a brute force process
    print(f"[INFO] Starting brute force on {service}@{host} with {len(wordlist)} passwords")

    for attempt in wordlist:
        time.sleep(0.2)  # simulate delay
        if attempt == "letmein":  # Simulated correct password
            return {
                "status": "Completed",
                "success": True,
                "message": f"Password found for {service}@{host}: {attempt}"
            }

    return {
        "status": "Completed",
        "success": False,
        "message": f"No valid password found for {service}@{host}"
    }
