from django.contrib import admin
from .models import Alert, BlockedIP, Detection, EvaluationMetric, LiveDetection, SystemStats, UploadBatch

@admin.register(UploadBatch)
class UploadBatchAdmin(admin.ModelAdmin):
    list_display = ("filename","uploaded_by","uploaded_at","status","row_count","malicious_count","processing_ms")
    list_filter = ("status",)

@admin.register(Detection)
class DetectionAdmin(admin.ModelAdmin):
    list_display = ("timestamp","source_ip","verdict","severity","rf_confidence","is_anomaly")
    list_filter = ("verdict","severity")

@admin.register(LiveDetection)
class LiveDetectionAdmin(admin.ModelAdmin):
    list_display = ("timestamp","source_ip","protocol","verdict","severity","rf_confidence","processing_us")
    list_filter = ("verdict","severity","protocol")

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("id","detection","status","created_at","handled_by")
    list_filter = ("status",)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip_address","active","reason","blocked_by","blocked_at")

@admin.register(EvaluationMetric)
class EvaluationMetricAdmin(admin.ModelAdmin):
    list_display = ("model_name","accuracy","precision","recall","f1_score","false_positive_rate")

@admin.register(SystemStats)
class SystemStatsAdmin(admin.ModelAdmin):
    list_display = ("total_live_processed","total_live_malicious","avg_processing_us","last_updated")
