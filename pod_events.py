def handle_pod_created_event(event):
    # Logic to handle pod creation event
    print("Pod Created Event:", event.message)

def handle_pod_deleted_event(event):
    # Logic to handle pod deletion event
    print("Pod Deleted Event:", event.message)
