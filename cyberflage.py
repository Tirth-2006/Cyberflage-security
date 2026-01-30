"""
CyberFlage is an educational / research project.
Destructive mode is disabled by default.
Do NOT use on production systems.
The author is not responsible for misuse.
"""
import os
import sys
import time
import logging
import argparse
import shutil
import socket
import getpass
import requests
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
from threading import Lock


try:
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("Error: Required libraries not found. Please run: pip install watchdog psutil requests")
    sys.exit(1)

# --- CONFIGURATION ---

CONFIG = {
    "protected_paths": [],  # List of paths to monitor
    "decoy_path": "",  # Path to the decoy directory
    "allow_destructive": False,  # Master switch for live mode
    "simulation_mode": True,  # Will be False if allow_destructive is True

    # Alerting
    "discord_webhook_url": "",
    "slack_webhook_url": "",
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_recipient": "",
    "canary_token_url": "",  # For CanaryTokens integration

    # Behavioral Triggers
    "freq_threshold": 10,  # 10 events...
    "freq_time_window": 5,  # ...within 5 seconds

    # Environmental Triggers
    "process_blacklist": ["mimikatz.exe", "procdump.exe"],  # Example blacklisted processes

}


logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')


def generate_honey_files(decoy_dir):
    """Generates fake honey files in the specified directory."""
    if not os.path.exists(decoy_dir):
        os.makedirs(decoy_dir)

    honey_files = {
        "Financials_Q4_2025_DRAFT.xlsx": (
            "Employee,Salary\n"
            "Alice Example,88000\n"
            "Bob Example,94000\n"
        ),

        "Passwords.txt": (
            "aws_access_key=NOT_A_REAL_AWS_KEY\n"
            "stripe_secret_key=NOT_A_REAL_STRIPE_KEY\n"
            "db_password=THIS_IS_FAKE_DATA"
        ),

        "project_apollo_source_code.zip": (
            "FAKE ARCHIVE FILE\n"
            "No real source code is stored here."
        ),

        "network_diagram.vsdx": (
            "FAKE VISIO CONTENT\n"
            "Placeholder network diagram."
        ),

        "api_keys.json": (
            '{'
            '"google_maps_api": "FAKE_GOOGLE_MAPS_KEY", '
            '"openai_api": "FAKE_OPENAI_KEY", '
            '"internal_service": "FAKE_INTERNAL_KEY"'
            '}'
        )
    }

    logging.info(f"Generating honey files in '{decoy_dir}'...")
    for filename, content in honey_files.items():
        try:
            with open(os.path.join(decoy_dir, filename), "w") as f:
                f.write(content)
        except IOError as e:
            logging.error(f"Failed to create honey file {filename}: {e}")
    logging.info("Honey files generated successfully.")





class AlertManager:
    """Handles dispatching alerts to configured services."""

    def __init__(self, config):
        self.config = config

    def _get_system_fingerprint(self):
        """Gathers basic information about the host system."""
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except socket.error:
            ip = "unknown"

        return {
            "hostname": socket.gethostname(),
            "os": sys.platform,
            "user": getpass.getuser(),
            "ip_address": ip
        }


    def dispatch(self, reason, details):
        """Sends an alert to all configured channels."""
        fingerprint = self._get_system_fingerprint()

        title = "🛡️ CyberFlage Alert Triggered!"
        message = (
            f"**Reason:** {reason}\n"
            f"**Details:**\n```\n{details}\n```\n"
            f"**System Fingerprint:**\n"
            f"  - Hostname: {fingerprint['hostname']}\n"
            f"  - OS: {fingerprint['os']}\n"
            f"  - User: {fingerprint['user']}\n"
            f"  - IP Address: {fingerprint['ip_address']}\n"
        )

        logging.warning(f"ALERT: {reason}. Details: {details}")

        if self.config["discord_webhook_url"]:
            self._send_discord_alert(title, message)
        if self.config["slack_webhook_url"]:
            self._send_slack_alert(title, message)
        if self.config["smtp_server"] and self.config["smtp_recipient"]:
            self._send_smtp_alert(title, message)
        if self.config["canary_token_url"]:
            self._trigger_canary_token(reason)

    def _send_discord_alert(self, title, message):
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": 15158332  # Red
            }]
        }
        try:
            requests.post(self.config["discord_webhook_url"], json=payload, timeout=5)
            logging.info("Discord alert sent.")
        except requests.RequestException as e:
            logging.error(f"Failed to send Discord alert: {e}")

    def _send_slack_alert(self, title, message):
        payload = {
            "attachments": [{
                "color": "#ff0000",  # Red
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": title}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": message}}
                ]
            }]
        }
        try:
            requests.post(self.config["slack_webhook_url"], json=payload, timeout=5)
            logging.info("Slack alert sent.")
        except requests.RequestException as e:
            logging.error(f"Failed to send Slack alert: {e}")

    def _send_smtp_alert(self, title, message):
        msg = MIMEText(message.replace('**', '').replace('```', ''))  # Clean markdown
        msg['Subject'] = title
        msg['From'] = self.config["smtp_user"]
        msg['To'] = self.config["smtp_recipient"]

        try:
            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                server.starttls()
                server.login(self.config["smtp_user"], self.config["smtp_password"])
                server.sendmail(self.config["smtp_user"], [self.config["smtp_recipient"]], msg.as_string())
            logging.info("SMTP alert sent.")
        except Exception as e:
            logging.error(f"Failed to send SMTP alert: {e}")

    def _trigger_canary_token(self, reason):
        """Triggers the configured CanaryToken URL."""
        try:
            # Add reason to user-agent for context
            headers = {'User-Agent': f'CyberFlage Trigger: {reason}'}
            requests.get(self.config["canary_token_url"], headers=headers, timeout=5)
            logging.info(f"CanaryToken triggered for reason: {reason}")
        except requests.RequestException as e:
            logging.error(f"Failed to trigger CanaryToken: {e}")


class DecoyManager:
    """Handles the atomic swapping of protected and decoy directories."""

    def __init__(self, config):
        self.config = config
        self.lock = Lock()
        self.swapped_map = {}  # Maps original protected path to a temporary name

    def swap(self, triggered_path):
        """
        Atomically swaps the protected directory with the decoy.
        This operation is simulated unless allow_destructive is True.
        """
        with self.lock:
            # Find which protected path contains the triggered path
            protected_dir = None
            for p_path in self.config["protected_paths"]:
                if os.path.commonpath([p_path, triggered_path]) == p_path:
                    protected_dir = p_path
                    break

            if not protected_dir:
                logging.error(f"Could not map triggered path '{triggered_path}' to a protected directory.")
                return

            decoy_dir = self.config["decoy_path"]

            if not os.path.exists(protected_dir) or not os.path.exists(decoy_dir):
                logging.error(
                    f"Swap failed: Protected ('{protected_dir}') or decoy ('{decoy_dir}') directory not found.")
                return

            if self.config["simulation_mode"]:
                logging.warning(f"[SIMULATION] Decoy swap triggered for '{protected_dir}'. No changes made.")
                return

            logging.warning(f"[LIVE MODE] Swapping '{protected_dir}' with '{decoy_dir}' NOW.")
            try:
                # Use rename for atomicity
                temp_name = f"{protected_dir}_{int(time.time())}_swapped"
                self.swapped_map[protected_dir] = temp_name

                os.rename(protected_dir, temp_name)
                os.rename(decoy_dir, protected_dir)
                logging.info(f"Swap complete. '{decoy_dir}' is now at '{protected_dir}'.")
                logging.info(f"Original directory moved to '{temp_name}'.")

            except OSError as e:
                logging.critical(f"CRITICAL: Decoy swap failed: {e}. System may be in an inconsistent state.")
                # Attempt to revert if something went wrong
                if os.path.exists(temp_name) and not os.path.exists(protected_dir):
                    os.rename(temp_name, protected_dir)
                    logging.info("Attempted to revert swap.")


class TriggerManager:
    """Monitors events and evaluates if a trigger condition is met."""

    def __init__(self, config):
        self.config = config
        self.access_log = defaultdict(list)
        self.lock = Lock()

    def check_triggers(self, event_path):
        """Checks all configured triggers for a given event."""

        # 1. High-Frequency Access Trigger
        with self.lock:
            now = time.time()
            self.access_log[event_path].append(now)
            # Prune old events
            time_window = self.config["freq_time_window"]
            self.access_log[event_path] = [t for t in self.access_log[event_path] if now - t < time_window]

            if len(self.access_log[event_path]) >= self.config["freq_threshold"]:
                details = f"Path: {event_path}\nAccess Count: {len(self.access_log[event_path])} times in {time_window}s."
                return "High-Frequency Access Detected", details

        # 2. Process Blacklist Trigger
        for proc in psutil.process_iter(['name']):
            name = proc.info.get('name')
            if name and name.lower() in self.config["process_blacklist"]:
                details = f"Blacklisted process detected: {name}"
                return "Blacklisted Process Detected", details


        return None, None  # No trigger fired


class FileSystemMonitor(FileSystemEventHandler):
    """Event handler for filesystem changes, orchestrating triggers and actions."""

    def __init__(self, config, alert_manager, decoy_manager, trigger_manager):
        self.config = config
        self.alert_manager = alert_manager
        self.decoy_manager = decoy_manager
        self.trigger_manager = trigger_manager
        self.tripped = False
        self.lock = Lock()
       
        self.protected_root = self.config["protected_paths"][0] if self.config["protected_paths"] else None

        self.decoy_root = self.config["decoy_path"]

    def _get_decoy_path(self, protected_path):
        """Translates a path from the protected dir to its decoy equivalent."""
        if not self.protected_root:
            return None

        relative_path = os.path.relpath(protected_path, self.protected_root)
        return os.path.join(self.decoy_root, relative_path)

    def on_created(self, event):
        """Called when a file or directory is created."""
        with self.lock:
            if self.tripped: return
            logging.info(f"FS Event: {event.event_type} on {event.src_path}")

          
            decoy_path = self._get_decoy_path(event.src_path)
            try:
                if event.is_directory:
                    os.makedirs(decoy_path, exist_ok=True)
                    logging.info(f"Mirrored directory created at: {decoy_path}")
                else:
                    
                    os.makedirs(os.path.dirname(decoy_path), exist_ok=True)
                  
                    with open(decoy_path, 'w') as f:
                        pass  # Creates a 0-byte file
                    logging.info(f"Mirrored empty file created at: {decoy_path}")
            except Exception as e:
                logging.error(f"Failed to mirror creation for {decoy_path}: {e}")
        

            self._check_and_trigger(event.src_path)

    def on_deleted(self, event):
        """Called when a file or directory is deleted."""
        with self.lock:
            if self.tripped: return
            logging.info(f"FS Event: {event.event_type} on {event.src_path}")

          
            decoy_path = self._get_decoy_path(event.src_path)
            try:
                if os.path.isfile(decoy_path):
                    os.remove(decoy_path)
                    logging.info(f"Mirrored file deleted at: {decoy_path}")
                elif os.path.isdir(decoy_path):
                    shutil.rmtree(decoy_path)
                    logging.info(f"Mirrored directory deleted at: {decoy_path}")
            except Exception as e:
                logging.error(f"Failed to mirror deletion for {decoy_path}: {e}")
           

            self._check_and_trigger(event.src_path)

    def on_moved(self, event):
        """Called when a file or directory is moved or renamed."""
        with self.lock:
            if self.tripped: return
            logging.info(f"FS Event: {event.event_type} from {event.src_path} to {event.dest_path}")

           
            old_decoy_path = self._get_decoy_path(event.src_path)
            new_decoy_path = self._get_decoy_path(event.dest_path)
            try:
                os.rename(old_decoy_path, new_decoy_path)
                logging.info(f"Mirrored move from {old_decoy_path} to {new_decoy_path}")
            except Exception as e:
                logging.error(f"Failed to mirror move: {e}")
          

            self._check_and_trigger(event.dest_path)

    def on_modified(self, event):
        """Called when a file is modified."""
        with self.lock:
            if self.tripped: return
            if event.is_directory: return  # Ignore directory modifications
            logging.info(f"FS Event: {event.event_type} on {event.src_path}")
            self._check_and_trigger(event.src_path)

    def _check_and_trigger(self, event_path):
        """Central method to check triggers and fire alerts."""
        reason, details = self.trigger_manager.check_triggers(event_path)
        if reason:
            self.tripped = True
            self.alert_manager.dispatch(reason, details)
            self.decoy_manager.swap(event_path)
            logging.critical("CyberFlage has been tripped. Shutting down monitor to prevent further action.")
            sys.exit(0)


class CyberFlage:
    """The main orchestrator class."""

    def __init__(self, config):
        self.config = config
        self.alert_manager = AlertManager(config)
        self.decoy_manager = DecoyManager(config)
        self.trigger_manager = TriggerManager(config)
        self.event_handler = FileSystemMonitor(config, self.alert_manager, self.decoy_manager, self.trigger_manager)
        self.observer = Observer()

    def run(self):
        """Starts the filesystem monitoring."""
        if not self.config["protected_paths"] or not self.config["decoy_path"]:
            logging.error("Configuration error: Protected paths and decoy path must be specified.")
            sys.exit(1)

        if not self.config["simulation_mode"]:
            logging.warning("=" * 60)
            logging.warning("            !!! LIVE DESTRUCTIVE MODE ENABLED !!!")
            logging.warning("This mode will RENAME directories. Use only on test systems.")
            logging.warning("You have 5 seconds to abort (Ctrl+C)...")
            logging.warning("=" * 60)
            time.sleep(5)
        else:
            logging.info("Starting in Simulation Mode. No filesystem changes will be made.")

        
        generate_honey_files(self.config["decoy_path"])

        for path in self.config["protected_paths"]:
            if not os.path.exists(path):
                logging.error(f"Protected path not found: '{path}'. Aborting.")
                sys.exit(1)
            self.observer.schedule(self.event_handler, path, recursive=True)
            logging.info(f"Monitoring protected path: {path}")

        self.observer.start()
        logging.info("CyberFlage is now active. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutting down CyberFlage...")
            self.observer.stop()
        self.observer.join()
        logging.info("CyberFlage has stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberFlage: A decoy-based cybersecurity system.")
    parser.add_argument('--protected', nargs='+', required=True, help='One or more paths to protected directories.')
    parser.add_argument('--decoy', required=True, help='Path to the decoy directory.')
    parser.add_argument('--allow-destructive', action='store_true',
                        help='Enable live mode. DANGEROUS: Allows directory swaps.')

    # Alerting arguments
    parser.add_argument('--discord-webhook', help='Discord webhook URL for alerts.')
    parser.add_argument('--slack-webhook', help='Slack webhook URL for alerts.')
    parser.add_argument('--canary-token', help='CanaryToken URL to trigger on alert.')

    parser.add_argument('--smtp-server', help='SMTP server for email alerts.')
    parser.add_argument('--smtp-port', type=int, help='SMTP port.')
    parser.add_argument('--smtp-user', help='SMTP username.')
    parser.add_argument('--smtp-password', help='SMTP password.')
    parser.add_argument('--smtp-recipient', help='Email recipient for alerts.')

    args = parser.parse_args()

    # Update CONFIG with CLI arguments
    CONFIG["protected_paths"] = args.protected
    CONFIG["decoy_path"] = args.decoy
    if args.allow_destructive:
        CONFIG["allow_destructive"] = True
        CONFIG["simulation_mode"] = False
    if args.discord_webhook:
        CONFIG["discord_webhook_url"] = args.discord_webhook
    if args.slack_webhook:
        CONFIG["slack_webhook_url"] = args.slack_webhook
    if args.canary_token:
        CONFIG["canary_token_url"] = args.canary_token
    if args.smtp_server:
        CONFIG["smtp_server"] = args.smtp_server
        CONFIG["smtp_port"] = args.smtp_port or 587
        CONFIG["smtp_user"] = args.smtp_user
        CONFIG["smtp_password"] = args.smtp_password
        CONFIG["smtp_recipient"] = args.smtp_recipient

   
    cyberflage_system = CyberFlage(CONFIG)
    cyberflage_system.run()
