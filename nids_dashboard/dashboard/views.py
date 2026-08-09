import csv, io, ipaddress, random, time
from datetime import timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Avg, Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Alert, BlockedIP, Detection, EvaluationMetric, LiveDetection, SystemStats, UploadBatch

def is_admin(u): return u.is_authenticated and u.is_staff

_INTERNAL  = ["10.0.1.","10.0.2.","192.168.10.","172.16.5."]
_PROTOCOLS = ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","FTP","SSH"]

def _rand_ext():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32-1))
        if ip.is_global and not ip.is_multicast: return str(ip)

def _rand_int(): return f"{random.choice(_INTERNAL)}{random.randint(2,254)}"

def _classify(rf_pred, anomaly):
    if rf_pred==1 and anomaly: return "CONFIRMED_ATTACK","CRITICAL"
    if rf_pred==1: return "KNOWN_ATTACK","HIGH"
    if anomaly:    return "ZERO_DAY","MEDIUM"
    return "BENIGN","LOW"

def _explanation(rf_pred, rf_conf, err, thr, anomaly, verdict):
    pct = rf_conf*100
    parts = []
    parts.append(f"Random Forest: {'MALICIOUS' if rf_pred==1 else 'BENIGN'} ({pct:.1f}% confidence).")
    parts.append(f"Autoencoder: reconstruction error {err:.4f} {'EXCEEDS' if anomaly else 'within'} threshold {thr:.4f}.")
    vm = {"CONFIRMED_ATTACK":"FINAL: CONFIRMED ATTACK — both models agree.",
          "KNOWN_ATTACK":"FINAL: KNOWN ATTACK — RF detected known signature.",
          "ZERO_DAY":"FINAL: ZERO-DAY ANOMALY — novel traffic pattern the RF has never seen.",
          "BENIGN":"FINAL: BENIGN — traffic within normal parameters."}
    parts.append(vm.get(verdict,""))
    return " ".join(parts)

_DATASET_CACHE = None
def _load_dataset():
    global _DATASET_CACHE
    if _DATASET_CACHE is not None: return _DATASET_CACHE
    for p in [
        Path.home()/"Desktop"/"Dissertation-"/"data"/"raw"/"UNSW-NB15_clean.csv",
        Path.home()/"Downloads"/"Dissertation__"/"data"/"raw"/"UNSW-NB15_clean.csv",
        Path.home()/"project"/"data"/"raw"/"UNSW-NB15_clean.csv",
    ]:
        if p.exists():
            _DATASET_CACHE = pd.read_csv(p)
            return _DATASET_CACHE
    return None

_rf=_scaler=_ae=_threshold=None; _loaded=False
def _load_models():
    global _rf,_scaler,_ae,_threshold,_loaded
    if _loaded: return True
    import joblib
    from django.conf import settings
    dirs=[Path(getattr(settings,'MODELS_DIR','/nonexistent'))]
    dirs+=[Path.home()/"Desktop"/"Dissertation-"/"models"/"saved",
           Path.home()/"Downloads"/"Dissertation__"/"models"/"saved",
           Path.home()/"project"/"models"/"saved"]
    md=next((d for d in dirs if (d/"rf_final.pkl").exists()),None)
    if not md: return False
    try:
        _rf=joblib.load(md/"rf_final.pkl"); _scaler=joblib.load(md/"scaler_final.pkl")
        _threshold=float(np.load(md/"threshold_final.npy"))
        try:
            from tensorflow import keras
            _ae=keras.models.load_model(md/"autoencoder_final.keras")
        except: pass
        _loaded=True
    except: pass
    return _loaded

def _predict(X):
    if not _load_models(): return None
    X=np.asarray(X,dtype=np.float32)
    if X.ndim==1: X=X.reshape(1,-1)
    Xs=_scaler.transform(X)
    preds=_rf.predict(Xs); proba=_rf.predict_proba(Xs)
    confs=proba[np.arange(len(proba)),preds]
    if _ae:
        rec=_ae.predict(Xs,verbose=0); errs=np.mean(np.square(Xs-rec),axis=1)
        anomaly=errs>_threshold
    else:
        errs=np.zeros(len(Xs)); anomaly=np.zeros(len(Xs),dtype=bool)
    out=[]
    for p,c,e,a in zip(preds,confs,errs,anomaly):
        v,s=_classify(int(p),bool(a))
        out.append({"rf_prediction":int(p),"rf_confidence":float(c),
                    "reconstruction_error":float(e),"anomaly_threshold":_threshold or 0.0,
                    "is_anomaly":bool(a),"verdict":v,"severity":s})
    return out

# AUTH
def login_view(request):
    if request.user.is_authenticated: return redirect("dashboard:index")
    if request.method=="POST":
        u=authenticate(request,username=request.POST.get("username","").strip(),password=request.POST.get("password",""))
        if u: login(request,u); return redirect(request.POST.get("next") or "dashboard:index")
        messages.error(request,"Invalid credentials.")
    return render(request,"dashboard/login.html",{"next":request.GET.get("next","")})

def logout_view(request): logout(request); return redirect("dashboard:login")

# MAIN DASHBOARD
@login_required
def index(request):
    _load_models()
    metric=EvaluationMetric.objects.filter(model_name__icontains="hybrid").first() or EvaluationMetric.objects.first()
    avg_us=LiveDetection.objects.aggregate(a=Avg("processing_us"))["a"] or 0
    ctx={
        "system_health":"ONLINE" if _loaded else "OFFLINE",
        "models_loaded":_loaded,"autoencoder_loaded":_ae is not None,
        "total_connections":Detection.objects.count()+LiveDetection.objects.count(),
        "active_threats":Alert.objects.filter(status="ACTIVE").count(),
        "live_total":LiveDetection.objects.count(),
        "live_malicious":LiveDetection.objects.exclude(verdict="BENIGN").count(),
        "accuracy_pct":f"{metric.accuracy*100:.1f}%" if metric else "N/A",
        "accuracy_model_name":metric.model_name if metric else None,
        "avg_processing_ms":f"{avg_us/1000:.3f}",
        "recent_detections":Detection.objects.select_related("batch")[:10],
        "live_recent":LiveDetection.objects.order_by("-timestamp")[:5],
    }
    return render(request,"dashboard/index.html",ctx)

# FEATURE 1+7: LIVE DETECTION + DECISION EXPLANATION
@login_required
def api_live_feed(request):
    n=min(int(request.GET.get("n",5)),20)
    df=_load_dataset(); ok=_load_models(); new=0
    if df is not None and ok:
        sample=df.sample(n=min(n,len(df)),random_state=random.randint(0,99999))
        fcols=[c for c in sample.columns if c!="label"]
        X=sample[fcols].values.astype(np.float32)
        t0=time.perf_counter(); results=_predict(X)
        us=(time.perf_counter()-t0)*1_000_000/max(len(X),1)
        for r in (results or []):
            exp=_explanation(r["rf_prediction"],r["rf_confidence"],r["reconstruction_error"],r["anomaly_threshold"],r["is_anomaly"],r["verdict"])
            LiveDetection.objects.create(
                source_ip=_rand_ext(),destination_ip=_rand_int(),
                source_port=random.randint(1024,65535),
                destination_port=random.choice([80,443,22,3389,53,8080,21,25]),
                protocol=random.choice(_PROTOCOLS),
                rf_prediction=r["rf_prediction"],rf_confidence=r["rf_confidence"],
                reconstruction_error=r["reconstruction_error"],anomaly_threshold=r["anomaly_threshold"],
                is_anomaly=r["is_anomaly"],verdict=r["verdict"],severity=r["severity"],
                decision_explanation=exp,processing_us=us)
        new=len(results or [])
        stats,_=SystemStats.objects.get_or_create(pk=1)
        mal=sum(1 for r in (results or []) if r["verdict"]!="BENIGN")
        stats.total_live_processed+=new; stats.total_live_malicious+=mal
        stats.total_live_benign+=new-mal; stats.avg_processing_us=us
        stats.last_updated=timezone.now(); stats.save()
    latest=LiveDetection.objects.order_by("-timestamp")[:10]
    rows=[{"timestamp":d.timestamp.strftime("%H:%M:%S"),"source_ip":d.source_ip,
           "destination_ip":d.destination_ip,"protocol":d.protocol,
           "source_port":d.source_port,"destination_port":d.destination_port,
           "verdict":d.get_verdict_display(),"verdict_code":d.verdict,
           "severity":d.severity,"rf_confidence":round(d.rf_confidence*100,1),
           "reconstruction_error":round(d.reconstruction_error,4),
           "anomaly_threshold":round(d.anomaly_threshold,4),
           "is_anomaly":d.is_anomaly,"processing_us":round(d.processing_us,2),
           "decision_explanation":d.decision_explanation} for d in latest]
    return JsonResponse({"detections":rows,"new_count":new})

# FEATURE 3+5: STATS
@login_required
def api_stats(request):
    stats=SystemStats.objects.filter(pk=1).first()
    us=stats.avg_processing_us if stats else 0
    return JsonResponse({
        "total_processed":Detection.objects.count()+LiveDetection.objects.count(),
        "live_malicious":stats.total_live_malicious if stats else 0,
        "live_benign":stats.total_live_benign if stats else 0,
        "avg_processing_ms":round(us/1000,3),"avg_processing_us":round(us,2),
        "throughput_per_sec":round(1_000_000/us,1) if us>0 else 0,
        "active_alerts":Alert.objects.filter(status="ACTIVE").count(),
        "blocked_ips":BlockedIP.objects.filter(active=True).count(),
        "models_online":_loaded,"autoencoder_online":_ae is not None,
    })

# FEATURE 4: DETECTION SUMMARY
@login_required
def api_detection_summary(request):
    verdicts=["BENIGN","KNOWN_ATTACK","ZERO_DAY","CONFIRMED_ATTACK"]
    labels=["Benign","Known Attack","Zero-Day","Confirmed Attack"]
    u={r["verdict"]:r["count"] for r in Detection.objects.values("verdict").annotate(count=Count("id"))}
    l={r["verdict"]:r["count"] for r in LiveDetection.objects.values("verdict").annotate(count=Count("id"))}
    sev={}
    for r in list(LiveDetection.objects.values("severity").annotate(count=Count("id")))+\
             list(Detection.objects.values("severity").annotate(count=Count("id"))):
        sev[r["severity"]]=sev.get(r["severity"],0)+r["count"]
    return JsonResponse({
        "labels":labels,
        "upload_data":[u.get(v,0) for v in verdicts],
        "live_data":[l.get(v,0) for v in verdicts],
        "total_data":[u.get(v,0)+l.get(v,0) for v in verdicts],
        "severity":{"LOW":sev.get("LOW",0),"MEDIUM":sev.get("MEDIUM",0),
                    "HIGH":sev.get("HIGH",0),"CRITICAL":sev.get("CRITICAL",0)},
    })

# CHART APIs
@login_required
def api_traffic_overview(request):
    now=timezone.now(); start=now-timedelta(hours=24)
    buckets=[]
    for h in range(24):
        bs=start+timedelta(hours=h); be=bs+timedelta(hours=1)
        b=Detection.objects.filter(timestamp__gte=bs,timestamp__lt=be)
        lv=LiveDetection.objects.filter(timestamp__gte=bs,timestamp__lt=be)
        buckets.append({"label":bs.strftime("%H:%M"),
            "benign":b.filter(verdict="BENIGN").count()+lv.filter(verdict="BENIGN").count(),
            "malicious":b.exclude(verdict="BENIGN").count()+lv.exclude(verdict="BENIGN").count()})
    return JsonResponse({"labels":[b["label"] for b in buckets],
        "benign":[b["benign"] for b in buckets],"malicious":[b["malicious"] for b in buckets]})

@login_required
def api_attack_distribution(request):
    vs=["BENIGN","KNOWN_ATTACK","ZERO_DAY","CONFIRMED_ATTACK"]
    ls=["Benign","Known Attack","Zero-Day Anomaly","Confirmed Attack"]
    u={r["verdict"]:r["count"] for r in Detection.objects.values("verdict").annotate(count=Count("id"))}
    l={r["verdict"]:r["count"] for r in LiveDetection.objects.values("verdict").annotate(count=Count("id"))}
    return JsonResponse({"labels":ls,"counts":[u.get(v,0)+l.get(v,0) for v in vs]})

@login_required
def api_algorithm_comparison(request):
    m=EvaluationMetric.objects.order_by("model_name")
    return JsonResponse({"labels":[x.model_name for x in m],
        "accuracy":[round(x.accuracy*100,2) for x in m],
        "precision":[round(x.precision*100,2) for x in m],
        "recall":[round(x.recall*100,2) for x in m]})

@login_required
def api_recent_activity(request):
    rows=[{"timestamp":d.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
           "source_ip":d.source_ip,"destination_ip":d.destination_ip,
           "verdict":d.get_verdict_display(),"verdict_code":d.verdict,
           "severity":d.severity,"confidence":round(d.rf_confidence*100,1)}
          for d in Detection.objects.select_related("batch")[:100]]
    return JsonResponse({"rows":rows})

# UPLOAD
@login_required
def upload_csv(request):
    if request.method=="POST":
        f=request.FILES.get("csv_file")
        if not f: messages.error(request,"No file selected."); return redirect("dashboard:upload")
        try:
            df=pd.read_parquet(f) if f.name.lower().endswith(".parquet") else pd.read_csv(f)
        except Exception as e:
            messages.error(request,f"Parse error: {e}"); return redirect("dashboard:upload")
        batch=UploadBatch.objects.create(filename=f.name,uploaded_by=request.user)
        _load_models()
        import json as _json
        from pathlib import Path as _Path
        _fcols_file = _Path("/home/kali/Dissertation__/models/saved/feature_cols.json")
        if _fcols_file.exists():
            saved_cols = _json.load(open(_fcols_file))
            # Encode any string columns first
            from sklearn.preprocessing import LabelEncoder as _LE
            for col in df.columns:
                if df[col].dtype == object and col not in ("label","attack_cat"):
                    df[col] = _LE().fit_transform(df[col].astype(str))
            # Keep only the exact columns the model was trained on
            missing = [c for c in saved_cols if c not in df.columns]
            for c in missing:
                df[c] = 0.0
            fcols = saved_cols
            X = df[fcols].values.astype(np.float32)
        else:
            drop = {"label","attack_cat","id","verdict","severity",
                    "source_ip","destination_ip","timestamp","class","target"}
            from sklearn.preprocessing import LabelEncoder as _LE
            for col in df.columns:
                if df[col].dtype == object and col not in drop:
                    df[col] = _LE().fit_transform(df[col].astype(str))
            feature_df = df.drop(columns=[c for c in df.columns
                                           if c.lower() in drop], errors="ignore")
            feature_df = feature_df.select_dtypes(include=[np.number])
            fcols = list(feature_df.columns)
            X = feature_df.values.astype(np.float32)
        t0=time.perf_counter(); results=_predict(X); ms=(time.perf_counter()-t0)*1000
        if results is None:
            batch.status="FAILED"; batch.error_message="Models not loaded."; batch.save()
            messages.error(request,"Models not loaded."); return redirect("dashboard:upload")
        counts={"BENIGN":0,"KNOWN_ATTACK":0,"ZERO_DAY":0,"CONFIRMED_ATTACK":0}
        dets=[]
        for i,r in enumerate(results):
            tl=int(df["label"].iloc[i]) if "label" in df.columns else None
            dets.append(Detection(batch=batch,row_index=i,
                source_ip=_rand_ext(),destination_ip=_rand_int(),
                source_port=random.randint(1024,65535),
                destination_port=random.choice([80,443,22,3389,53,8080]),
                rf_prediction=r["rf_prediction"],rf_confidence=r["rf_confidence"],
                reconstruction_error=r["reconstruction_error"],anomaly_threshold=r["anomaly_threshold"],
                is_anomaly=r["is_anomaly"],true_label=tl,verdict=r["verdict"],severity=r["severity"]))
            counts[r["verdict"]]+=1
        created=Detection.objects.bulk_create(dets,batch_size=1000)
        Alert.objects.bulk_create([Alert(detection=d) for d in created if d.verdict!="BENIGN"],batch_size=1000)
        batch.row_count=len(created); batch.benign_count=counts["BENIGN"]
        batch.known_attack_count=counts["KNOWN_ATTACK"]; batch.zero_day_count=counts["ZERO_DAY"]
        batch.confirmed_attack_count=counts["CONFIRMED_ATTACK"]
        batch.processing_ms=ms; batch.status="DONE"; batch.save()
        messages.success(request,f"Analysed {batch.row_count} rows: {batch.benign_count} benign, {batch.malicious_count} malicious in {ms:.1f} ms.")
        return redirect("dashboard:upload_result",batch_id=batch.id)
    return render(request,"dashboard/upload.html",{"recent_batches":UploadBatch.objects.all()[:10]})

@login_required
def upload_result(request,batch_id):
    batch=get_object_or_404(UploadBatch,id=batch_id)
    return render(request,"dashboard/upload_result.html",{"batch":batch,"detections":batch.detections.all()[:500]})

# ALERTS
@login_required
def alerts_view(request):
    sf=request.GET.get("status","ACTIVE")
    qs=Alert.objects.select_related("detection")
    if sf!="ALL": qs=qs.filter(status=sf)
    return render(request,"dashboard/alerts.html",{
        "alerts":qs[:200],
        "status_filter":sf,
        "is_admin": request.user.is_staff,
    })

@login_required
@require_POST
def acknowledge_alert(request,alert_id):
    a=get_object_or_404(Alert,id=alert_id); a.status="ACKNOWLEDGED"
    a.handled_by=request.user; a.handled_at=timezone.now(); a.save()
    messages.success(request,f"Alert #{alert_id} acknowledged."); return redirect("dashboard:alerts")

@login_required
@require_POST
def resolve_alert(request,alert_id):
    a=get_object_or_404(Alert,id=alert_id); a.status="RESOLVED"
    a.handled_by=request.user; a.handled_at=timezone.now(); a.save()
    messages.success(request,f"Alert #{alert_id} resolved."); return redirect("dashboard:alerts")

# REPORTS
@login_required
def reports(request):
    return render(request,"dashboard/reports.html",
        {"batches":UploadBatch.objects.all(),"metrics":EvaluationMetric.objects.order_by("model_name")})

@login_required
def export_csv(request):
    bid=request.GET.get("batch")
    qs=Detection.objects.select_related("batch").order_by("-timestamp")
    if bid: qs=qs.filter(batch_id=bid)
    resp=HttpResponse(content_type="text/csv")
    resp["Content-Disposition"]='attachment; filename="detections.csv"'
    w=csv.writer(resp)
    w.writerow(["timestamp","source_ip","destination_ip","verdict","severity","rf_confidence","reconstruction_error"])
    for d in qs.iterator():
        w.writerow([d.timestamp.isoformat(),d.source_ip,d.destination_ip,d.get_verdict_display(),
                    d.severity,f"{d.rf_confidence:.4f}",f"{d.reconstruction_error:.4f}"])
    return resp

@login_required
def export_pdf(request):
    from reportlab.lib import colors; from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm; from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate,Table,TableStyle,Paragraph,Spacer
    buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,topMargin=20*mm,bottomMargin=20*mm)
    styles=getSampleStyleSheet()
    elems=[Paragraph("Zero Day Hunter — Report",styles["Title"]),
           Paragraph(f"Generated {timezone.now():%Y-%m-%d %H:%M}",styles["Normal"]),
           Spacer(1,8*mm)]
    rows=[["Model","Accuracy","Precision","Recall","F1","FPR","FNR"]]
    for m in EvaluationMetric.objects.all():
        rows.append([m.model_name,f"{m.accuracy:.2%}",f"{m.precision:.2%}",
                     f"{m.recall:.2%}",f"{m.f1_score:.3f}",f"{m.false_positive_rate:.2%}",f"{m.false_negative_rate:.2%}"])
    t=Table(rows,hAlign="LEFT"); t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0F1829")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTSIZE",(0,0),(-1,-1),8),
        ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#CCCCCC"))]))
    elems.append(t); doc.build(elems); buf.seek(0)
    return HttpResponse(buf.getvalue(),content_type="application/pdf",
        headers={"Content-Disposition":'attachment; filename="report.pdf"'})

# ACCESS CONTROL
@login_required
def access_control(request):
    return render(request,"dashboard/access_control.html",{
        "blocked":BlockedIP.objects.filter(active=True),
        "lifted":BlockedIP.objects.filter(active=False)[:20],
        "is_admin":is_admin(request.user)})

@login_required
@user_passes_test(is_admin)
@require_POST
def block_ip(request):
    ip=request.POST.get("ip_address","").strip(); reason=request.POST.get("reason","").strip()
    if not ip: messages.error(request,"IP required."); return redirect("dashboard:access_control")
    BlockedIP.objects.update_or_create(ip_address=ip,defaults={"reason":reason,
        "blocked_by":request.user,"active":True,"blocked_at":timezone.now()})
    messages.success(request,f"{ip} blocked."); return redirect("dashboard:access_control")

@login_required
@user_passes_test(is_admin)
@require_POST
def unblock_ip(request,block_id):
    b=get_object_or_404(BlockedIP,id=block_id); b.active=False; b.save()
    messages.success(request,f"{b.ip_address} unblocked."); return redirect("dashboard:access_control")
