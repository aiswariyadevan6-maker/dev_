import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class UploadBatch(models.Model):
    STATUS_CHOICES = [("PENDING","Pending"),("PROCESSING","Processing"),("DONE","Done"),("FAILED","Failed")]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    filename = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    uploaded_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="PENDING")
    error_message = models.TextField(blank=True, default="")
    row_count = models.PositiveIntegerField(default=0)
    benign_count = models.PositiveIntegerField(default=0)
    known_attack_count = models.PositiveIntegerField(default=0)
    zero_day_count = models.PositiveIntegerField(default=0)
    confirmed_attack_count = models.PositiveIntegerField(default=0)
    processing_ms = models.FloatField(null=True, blank=True)
    class Meta: ordering = ["-uploaded_at"]
    @property
    def malicious_count(self): return self.known_attack_count + self.zero_day_count + self.confirmed_attack_count


class Detection(models.Model):
    VERDICT_CHOICES = [("BENIGN","Benign"),("KNOWN_ATTACK","Known Attack"),("ZERO_DAY","Zero-Day Anomaly"),("CONFIRMED_ATTACK","Confirmed Attack")]
    SEVERITY_CHOICES = [("LOW","Low"),("MEDIUM","Medium"),("HIGH","High"),("CRITICAL","Critical")]
    batch = models.ForeignKey(UploadBatch, on_delete=models.CASCADE, related_name="detections")
    row_index = models.PositiveIntegerField()
    timestamp = models.DateTimeField(default=timezone.now)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.PositiveIntegerField()
    destination_port = models.PositiveIntegerField()
    rf_prediction = models.PositiveSmallIntegerField()
    rf_confidence = models.FloatField()
    reconstruction_error = models.FloatField()
    anomaly_threshold = models.FloatField()
    is_anomaly = models.BooleanField(default=False)
    true_label = models.PositiveSmallIntegerField(null=True, blank=True)
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["-timestamp"]), models.Index(fields=["verdict"])]


class Alert(models.Model):
    STATUS_CHOICES = [("ACTIVE","Active"),("ACKNOWLEDGED","Acknowledged"),("RESOLVED","Resolved")]
    detection = models.OneToOneField(Detection, on_delete=models.CASCADE, related_name="alert")
    created_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default="ACTIVE")
    handled_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    handled_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")
    class Meta: ordering = ["-created_at"]


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, blank=True, default="")
    blocked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    blocked_at = models.DateTimeField(default=timezone.now)
    active = models.BooleanField(default=True)
    class Meta: ordering = ["-blocked_at"]


class EvaluationMetric(models.Model):
    model_name = models.CharField(max_length=100, unique=True)
    accuracy = models.FloatField()
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    false_positive_rate = models.FloatField()
    false_negative_rate = models.FloatField()
    recorded_at = models.DateTimeField(default=timezone.now)
    class Meta: ordering = ["model_name"]


class LiveDetection(models.Model):
    """
    Each row = one real-time simulated detection.
    Populated by the /api/live-feed/ endpoint which samples
    the dataset and runs genuine model predictions.
    """
    VERDICT_CHOICES = [("BENIGN","Benign"),("KNOWN_ATTACK","Known Attack"),("ZERO_DAY","Zero-Day Anomaly"),("CONFIRMED_ATTACK","Confirmed Attack")]
    SEVERITY_CHOICES = [("LOW","Low"),("MEDIUM","Medium"),("HIGH","High"),("CRITICAL","Critical")]

    timestamp        = models.DateTimeField(default=timezone.now, db_index=True)
    source_ip        = models.GenericIPAddressField()
    destination_ip   = models.GenericIPAddressField()
    source_port      = models.PositiveIntegerField()
    destination_port = models.PositiveIntegerField()
    protocol         = models.CharField(max_length=10, default="TCP")

    # Raw model outputs
    rf_prediction        = models.PositiveSmallIntegerField()
    rf_confidence        = models.FloatField()
    reconstruction_error = models.FloatField()
    anomaly_threshold    = models.FloatField()
    is_anomaly           = models.BooleanField(default=False)

    # Final verdict
    verdict  = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)

    # Human-readable explanation of the hybrid decision
    decision_explanation = models.TextField(default="")

    # Processing speed for this single record (microseconds)
    processing_us = models.FloatField(default=0.0)

    class Meta:
        ordering = ["-timestamp"]

    @property
    def is_malicious(self):
        return self.verdict != "BENIGN"


class SystemStats(models.Model):
    """
    Running system statistics — updated on every live detection tick.
    Always only one row (singleton pattern via get_or_create(pk=1)).
    """
    total_live_processed   = models.PositiveIntegerField(default=0)
    total_live_malicious   = models.PositiveIntegerField(default=0)
    total_live_benign      = models.PositiveIntegerField(default=0)
    avg_processing_us      = models.FloatField(default=0.0)
    last_updated           = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "System Stats"
