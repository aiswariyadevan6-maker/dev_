from pathlib import Path
import pandas as pd
from django.core.management.base import BaseCommand, CommandError
from dashboard.models import EvaluationMetric

class Command(BaseCommand):
    help = "Load comparison.csv into EvaluationMetric (safe to re-run, no duplicates)."
    def add_arguments(self, p): p.add_argument("--path", type=str, default=None)
    def handle(self, *args, **opts):
        from django.conf import settings
        candidates = [
            Path(opts["path"]) if opts["path"] else None,
            Path(settings.BASE_DIR).parent / "results" / "metrics" / "comparison.csv",
            Path.home() / "Desktop" / "Dissertation-" / "results" / "metrics" / "comparison.csv",
            Path.home() / "Downloads" / "Dissertation__" / "results" / "metrics" / "comparison.csv",
            Path.home() / "project" / "results" / "metrics" / "comparison.csv",
        ]
        csv_path = next((p for p in candidates if p and p.exists()), None)
        if not csv_path:
            raise CommandError("comparison.csv not found. Use --path.")
        df = pd.read_csv(csv_path)
        required = {"model","accuracy","precision","recall","f1_score","false_positive_rate","false_negative_rate"}
        if miss := required - set(df.columns):
            raise CommandError(f"Missing columns: {miss}")
        created = updated = 0
        for _, row in df.iterrows():
            _, was_created = EvaluationMetric.objects.update_or_create(
                model_name=row["model"],
                defaults={"accuracy":row["accuracy"],"precision":row["precision"],
                          "recall":row["recall"],"f1_score":row["f1_score"],
                          "false_positive_rate":row["false_positive_rate"],
                          "false_negative_rate":row["false_negative_rate"]})
            if was_created: created += 1
            else: updated += 1
        self.stdout.write(self.style.SUCCESS(f"Done: {created} created, {updated} updated from {csv_path}"))
