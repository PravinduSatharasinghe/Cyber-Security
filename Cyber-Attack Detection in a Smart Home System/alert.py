import logging
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", email_config=None):
        """
        Initializes the AlertSystem for logging and sending alerts.
        
        :param log_file: Path to the log file where alerts will be saved.
        :param email_config: Dictionary containing email configuration for notifications.
        """
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # Log file handler
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Email notification configuration (optional)
        self.email_config = email_config

    def generate_alert(self, threat, packet_info):
        """
        Generates an alert for the detected threat and logs it.

        :param threat: The threat information containing type and confidence.
        :param packet_info: Packet information such as source and destination IPs.
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        # Log alert as a warning
        self.logger.warning(json.dumps(alert))

        # If threat confidence is high, log as critical and send notifications
        if threat['confidence'] > 0.8:
            self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")
            # Send email notification if email_config is provided
            if self.email_config:
                self.send_email(alert)

    def send_email(self, alert):
        """
        Sends an email notification with the alert details.

        :param alert: The alert details to be sent via email.
        """
        if not self.email_config:
            return

        # Email setup
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = self.email_config['to_email']
            msg['Subject'] = f"IDS Alert - {alert['threat_type']}"

            body = f"Alert Details:\n\n{json.dumps(alert, indent=4)}"
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(self.email_config['from_email'], self.email_config['password'])
                text = msg.as_string()
                server.sendmail(self.email_config['from_email'], self.email_config['to_email'], text)

            self.logger.info(f"Alert email sent for threat: {alert['threat_type']}")
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")

