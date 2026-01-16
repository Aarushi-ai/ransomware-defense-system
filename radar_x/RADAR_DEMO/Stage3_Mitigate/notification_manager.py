
import threading
import time
import logging

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

logger = logging.getLogger(__name__)

class NotificationManager:
    """
    Handles desktop notifications for RADAR-X actions.
    Uses 'plyer' if available, otherwise logs to console/dashboard.
    """
    
    def __init__(self):
        self.enabled = True
        if not PLYER_AVAILABLE:
            logger.warning("Plyer not installed. Desktop notifications disabled (Console only).")
            
    def send_notification(self, title, message, timeout=5):
        """
        Send a desktop toast notification.
        Non-blocking (runs in thread).
        """
        if not self.enabled:
            return

        if PLYER_AVAILABLE:
            threading.Thread(
                target=self._show_toast,
                args=(title, message, timeout)
            ).start()
        else:
            # Fallback: Print loud message for now (Dashboard will handle visual alert)
            print(f"\n🔔 [NOTIFICATION] {title}: {message}\n")

    def _show_toast(self, title, message, timeout):
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="RADAR-X Defense System",
                timeout=timeout,
                # Icon path could be added here if available
            )
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

    def alert_threat_detected(self, threat_level, threat_type):
        self.send_notification(
            title=f"🚨 Threat Detected: {threat_level}",
            message=f"RADAR-X found {threat_type}. Initating response...",
            timeout=10
        )

    def alert_mitigation_success(self, action_count):
        self.send_notification(
            title="✅ Threat Neutralized",
            message=f"Successfully performed {action_count} mitigation actions. System secure.",
            timeout=10
        )

# Test
if __name__ == "__main__":
    nm = NotificationManager()
    nm.send_notification("RADAR-X Test", "This is a test notification.")
