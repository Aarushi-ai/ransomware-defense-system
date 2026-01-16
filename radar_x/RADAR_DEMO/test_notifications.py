import sys
import os
import time

# Add path to find notification_manager
sys.path.append(os.path.join(os.getcwd(), 'Stage3_Mitigate'))

from Stage3_Mitigate.notification_manager import NotificationManager
import winsound

print("Testing RADAR-X Audio/Visual Alerts...")
print("1. Playing Sound...")
winsound.Beep(2500, 500)
print("   Done.")

print("2. Sending Toast Notification...")
nm = NotificationManager()
nm.alert_threat_detected("CRITICALTEST", "Ransomware Simulator")
print("   Notification sent (Check your system tray!)")

print("\nSuccess if you heard a beep and saw a popup.")
