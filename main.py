from kubernetes import client, config
import time
from pod_events import handle_pod_created_event, handle_pod_deleted_event
from security_events import handle_privilege_escalation_event, handle_suspicious_container_event

def monitor_security_events():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    security_event_types = ["PodCreated", "PodDeleted", "PrivilegeEscalation", "SuspiciousContainerBehavior"]

    while True:
        try:
            events = v1.list_event_for_all_namespaces(watch=True)

            for event in events:
                event_type = event.type
                event_reason = event.reason

                if event_type == "Normal" and event_reason in security_event_types:
                    process_security_event(event)

        except Exception as e:
            print("Error occurred while monitoring events:", str(e))

        except KeyboardInterrupt:
            print("Monitoring stopped by the user.")
            break

        time.sleep(5)

def process_security_event(event):
    event_type = event.type
    event_reason = event.reason
    event_message = event.message

    if event_reason == "PodCreated":
        handle_pod_created_event(event)

    elif event_reason == "PodDeleted":
        handle_pod_deleted_event(event)

    elif event_reason == "PrivilegeEscalation":
        handle_privilege_escalation_event(event)

    elif event_reason == "SuspiciousContainerBehavior":
        handle_suspicious_container_event(event)

    generate_report(event)

def generate_report(event):
    # Logic to generate reports based on the event
    print("Generated Report for Event:", event.message)

if __name__ == "__main__":
    monitor_security_events()
