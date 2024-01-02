# Kubernetes-Security-Event-Monitoring

Kubernetes Security Events Monitor

This Python script allows you to monitor security events from Kubernetes clusters, such as pod creations, deletions, privilege escalations, and suspicious container behavior. It connects to the Kubernetes API and watches for relevant security events.
Installation

    Clone the repository:

bash

git clone <repository_url>
cd kubernetes-security-events-monitor

    Install the required dependencies:

bash

pip install -r requirements.txt

Usage

To start monitoring security events from Kubernetes, run the following command:

bash

python main.py

The script will connect to the Kubernetes API and start watching for security events. When it detects a relevant event (e.g., PodCreated, PodDeleted, PrivilegeEscalation, SuspiciousContainerBehavior), it will process the event and generate a report.
Stopping the Monitoring

To stop the monitoring process, you can use the Ctrl+C keyboard interrupt. The script will handle the termination signal and stop monitoring gracefully.
Logging

The script uses Python's built-in logging module to display log messages. By default, log messages are displayed in the console. You can modify the logging configuration in the main.py file if you want to change the logging behavior.
Customization

You can customize the handling of each security event by modifying the corresponding functions in the pod_events.py and security_events.py files. Each event type has a dedicated function for handling the event logic.
Troubleshooting

If the script encounters errors while monitoring events, it will log them with appropriate error messages. You can check the logs to identify the issue.
Contributions

Contributions to this project are welcome! If you find any bugs or want to add new features, please open an issue or submit a pull request.
License

This project is licensed under the MIT License - see the LICENSE file for details.
