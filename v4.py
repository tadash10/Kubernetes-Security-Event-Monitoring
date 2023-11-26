import time
import signal
import logging
from kubernetes import client, config
from requests.exceptions import RequestException

class SecurityEventsMonitor:
    def __init__(self, kubeconfig_path=None):
        self._logger = self._setup_logging()
        self._stop_monitoring = False
        self._kubeconfig_path = kubeconfig_path

        # Handle termination signal
        signal.signal(signal.SIGTERM, self._handle_terminate_signal)

    def _setup_logging(self):
        logger = logging.getLogger("security_events_monitor")
        logger.setLevel(logging.DEBUG)

        # Create and set up the console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Add file handler for logging to a file
        file_handler = logging.FileHandler("security_events.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def start_monitoring(self, interval=5):
        self._logger.info("Starting security events monitoring...")
        if self._kubeconfig_path:
            config.load_kube_config(config_file=self._kubeconfig_path)
        else:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        security_event_types = ["PodCreated", "PodDeleted", "PrivilegeEscalation", "SuspiciousContainerBehavior"]

        while not self._stop_monitoring:
            try:
                events = v1.list_event_for_all_namespaces(watch=True)

                for event in events:
                    event_type = event.type
                    event_reason = event.reason

                    if event_type == "Normal" and event_reason in security_event_types:
                        self._process_security_event(event)

            except client.rest.ApiException as api_ex:
                self._logger.error("Kubernetes API Error: %s", api_ex)
                self._handle_api_exception_retry(api_ex)

            except RequestException as req_ex:
                self._logger.error("Request Error: %s", req_ex)
                self._handle_request_exception_retry(req_ex)

            except Exception as e:
                self._logger.error("Error occurred while monitoring events: %s", str(e))

            time.sleep(interval)

        self._logger.info("Security events monitoring stopped.")

    def _handle_api_exception_retry(self, exception):
        self._logger.warning("Retrying after Kubernetes API error...")
        time.sleep(10)

    def _handle_request_exception_retry(self, exception):
        self._logger.warning("Retrying after request error...")
        time.sleep(10)

    def _handle_terminate_signal(self, signum, frame):
        self._logger.info("Termination signal received. Stopping monitoring.")
        self._stop_monitoring = True

    def _process_security_event(self, event):
        event_type = event.type
        event_reason = event.reason
        event_message = event.message

        if event_reason == "PodCreated":
            self._handle_pod_created_event(event)

        elif event_reason == "PodDeleted":
            self._handle_pod_deleted_event(event)

        elif event_reason == "PrivilegeEscalation":
            self._handle_privilege_escalation_event(event)

        elif event_reason == "SuspiciousContainerBehavior":
            self._handle_suspicious_container_event(event)

        self._generate_report(event)

    def _handle_pod_created_event(self, event):
        # Logic to handle pod creation event
        self._logger.info("Pod Created Event: %s", event.message)

    def _handle_pod_deleted_event(self, event):
        # Logic to handle pod deletion event
        self._logger.info("Pod Deleted Event: %s", event.message)

    def _handle_privilege_escalation_event(self, event):
        # Logic to handle privilege escalation event
        self._logger.info("Privilege Escalation Event: %s", event.message)

    def _handle_suspicious_container_event(self, event):
        # Logic to handle suspicious container behavior event
        self._logger.info("Suspicious Container Event: %s", event.message)

    def _generate_report(self, event):
        # Logic to generate reports based on the event
        self._logger.info("Generated Report for Event: %s", event.message)

if __name__ == "__main__":
    # Specify the path to the kubeconfig file if needed
    kubeconfig_path = "/path/to/kubeconfig.yaml"
    
    monitor = SecurityEventsMonitor(kubeconfig_path)
    monitor.start_monitoring()
