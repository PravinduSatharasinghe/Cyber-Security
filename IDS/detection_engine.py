from collections import defaultdict
import logging

class DetectionEngine:
    def __init__(self):
        """
        Initializes the DetectionEngine with signature rules and normal baseline values.
        """
        self.signature_rules = self.load_signature_rules()
        self.normal_baselines = {
            'max_packet_size': 1500,  # Example baseline values
            'max_packet_rate': 100,
            'max_byte_rate': 100000
        }
        
        # Set up logging for detected threats
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def load_signature_rules(self):
        """
        Loads the predefined signature-based rules for detecting attacks.
        """
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def detect_threats(self, features):
        """
        Detects potential threats based on signature rules and anomaly detection.

        :param features: Dictionary containing packet features.
        :return: List of detected threats.
        """
        threats = []

        # Signature-based detection (matches known patterns)
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threat = {
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                }
                threats.append(threat)
                self.logger.info(f"Threat detected: {rule_name} (Signature-based)")

        # Threshold-based anomaly detection
        anomaly_flags = []
        
        if (features['packet_size'] > self.normal_baselines['max_packet_size'] * 1.5 or
            features['packet_size'] < self.normal_baselines['max_packet_size'] * 0.3):
            anomaly_flags.append('packet_size')
            
        if features['packet_rate'] > self.normal_baselines['max_packet_rate'] * 1.5:
            anomaly_flags.append('packet_rate')
            
        if features['byte_rate'] > self.normal_baselines['max_byte_rate'] * 1.5:
            anomaly_flags.append('byte_rate')

        # If anomalies are found, create a threat
        if anomaly_flags:
            confidence = min(1.0, len(anomaly_flags) * 0.33)  # 33% confidence for each anomaly flag
            threats.append({
                'type': 'anomaly',
                'triggers': anomaly_flags,
                'confidence': confidence
            })
            self.logger.info(f"Anomaly detected: {', '.join(anomaly_flags)} (Threshold-based)")

        return threats

    def update_signature_rules(self, new_rules):
        """
        Updates the signature-based detection rules with new ones.

        :param new_rules: Dictionary of new signature rules to be added.
        """
        self.signature_rules.update(new_rules)
        self.logger.info(f"Signature rules updated: {list(new_rules.keys())}")

    def set_baselines(self, max_packet_size=None, max_packet_rate=None, max_byte_rate=None):
        """
        Allows dynamic adjustment of baseline values for anomaly detection.

        :param max_packet_size: Optional new max packet size for baseline.
        :param max_packet_rate: Optional new max packet rate for baseline.
        :param max_byte_rate: Optional new max byte rate for baseline.
        """
        if max_packet_size:
            self.normal_baselines['max_packet_size'] = max_packet_size
        if max_packet_rate:
            self.normal_baselines['max_packet_rate'] = max_packet_rate
        if max_byte_rate:
            self.normal_baselines['max_byte_rate'] = max_byte_rate
        self.logger.info("Baseline values updated.")
