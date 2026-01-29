# Modern Logging & Monitoring

## Structured Logging

```python
import structlog
import logging
from pythonjsonlogger import jsonlogger

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    amount = request.json['amount']
    from_account = request.json['from']
    to_account = request.json['to']
    
    logger.info(
        "money_transfer_initiated",
        amount=amount,
        from_account=from_account,
        to_account=to_account,
        user_id=current_user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        correlation_id=get_correlation_id(),
        service="payment-api",
        environment="production"
    )
```

## Distributed Tracing

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure OpenTelemetry
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(endpoint="localhost:4317")
span_processor = BatchSpanProcessor(otlp_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

@app.route('/process-order')
def process_order():
    with tracer.start_as_current_span("process_order") as span:
        span.set_attribute("order.id", order_id)
        span.set_attribute("user.id", user_id)
        
        # Operations are traced
        validate_order()
        charge_payment()
        send_confirmation()
```

## Security Monitoring

```python
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityMonitor:
    def __init__(self):
        self.events = []
        self.alerts = []
    
    def log_security_event(self, event_type, **kwargs):
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'severity': self.calculate_severity(event_type),
            **kwargs
        }
        
        self.events.append(event)
        
        # Real-time anomaly detection
        if self.is_anomalous(event):
            self.trigger_alert(event)
        
        # Send to SIEM
        self.send_to_siem(event)
    
    def is_anomalous(self, event):
        # Detect patterns
        if event['type'] == 'failed_login':
            recent_failures = self.count_recent_events(
                'failed_login',
                {'user_id': event['user_id']},
                minutes=5
            )
            return recent_failures > 5
        
        if event['type'] == 'privilege_escalation':
            return True  # Always alert
        
        return False
    
    def trigger_alert(self, event):
        alert = {
            'alert_id': generate_alert_id(),
            'timestamp': datetime.now().isoformat(),
            'severity': 'high',
            'event': event,
            'recommended_action': self.get_recommendation(event)
        }
        
        # Send to security team
        send_to_slack(alert)
        send_to_pagerduty(alert)
        create_jira_ticket(alert)
        
        # Automated response
        if event['type'] == 'brute_force':
            block_ip(event['ip_address'])
```

## Cloud-Native Logging

```python
# Kubernetes-aware logging
import logging
import os

class K8sFormatter(logging.Formatter):
    def format(self, record):
        record.pod_name = os.environ.get('HOSTNAME')
        record.namespace = os.environ.get('NAMESPACE')
        record.node_name = os.environ.get('NODE_NAME')
        return super().format(record)

# Log to stdout (collected by Fluentd/Fluent Bit)
handler = logging.StreamHandler()
handler.setFormatter(K8sFormatter(
    '{"time":"%(asctime)s","pod":"%(pod_name)s",'
    '"namespace":"%(namespace)s","level":"%(levelname)s",'
    '"message":"%(message)s"}'
))
```
