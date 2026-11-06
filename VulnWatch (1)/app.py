"""VulnWatch Application Entrypoint and Route Definitions."""
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from config import Config
from db import get_db, close_db, init_db
from services.vulnerability_service import VulnerabilityService
from services.notification_service import NotificationService
from services.dataset_importer import DatasetImporter
from services.refresh_service import RefreshService
from services.ml_service import MLService

csrf = CSRFProtect()

def create_app(test_config=None):
    """Application factory pattern."""
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    app.config.from_object(Config)
    if test_config is not None:
        app.config.update(test_config)

    Config.ensure_directories()

    # Logging setup: logs written to instance/logs/
    log_file = app.config.get("LOGS_DIR", Config.LOGS_DIR) / "vulnwatch.log"
    handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Initialize extensions
    csrf.init_app(app)
    app.teardown_appcontext(close_db)

    # Security Headers Hook
    @app.after_request
    def set_security_headers(response):
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Global Template Context
    @app.context_processor
    def inject_global_data():
        try:
            conn = get_db()
            freshness = RefreshService.get_data_freshness(conn, app.config.get("STALE_AFTER_HOURS", 24))
            unread = NotificationService.count_unread(conn)
            return {"freshness": freshness, "unread_notifs_count": unread}
        except Exception:
            return {"freshness": None, "unread_notifs_count": 0}

    # Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return render_template("error.html", code=400, name="Bad Request", description="The request was invalid or malformed."), 400

    @app.errorhandler(403)
    def handle_forbidden(e):
        return render_template("error.html", code=403, name="Forbidden", description="Access denied. CSRF validation failed or unauthorized access."), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        return render_template("error.html", code=404, name="Page Not Found", description="The requested vulnerability resource or page does not exist."), 404

    @app.errorhandler(413)
    def handle_file_too_large(e):
        return render_template("error.html", code=413, name="File Too Large", description="The uploaded dataset file exceeds the 150 MB size limit."), 413

    @app.errorhandler(500)
    def handle_server_error(e):
        app.logger.exception("Internal Server Error: %s", e)
        return render_template("error.html", code=500, name="Server Error", description="An unexpected error occurred. Details have been safely logged."), 500

    # CLI Command to init DB
    @app.cli.command("init-db")
    def init_db_command():
        init_db(app.config["DATABASE_PATH"])
        print("Initialized database schema.")

    # ------------------ Routes ------------------

    @app.route("/")
    def dashboard():
        conn = get_db()
        stats = VulnerabilityService.get_dashboard_stats(conn, app.config.get("RECENT_DAYS", 30))
        return render_template("dashboard.html", stats=stats)

    @app.route("/api/dashboard-stats")
    def api_dashboard_stats():
        conn = get_db()
        stats = VulnerabilityService.get_dashboard_stats(conn, app.config.get("RECENT_DAYS", 30))
        return jsonify(stats)

    @app.route("/vulnerabilities")
    def vulnerabilities_page():
        conn = get_db()
        q = request.args.get("q", "").strip()
        severity = request.args.get("severity", "ALL")
        product = request.args.get("product", "")
        sort = request.args.get("sort", "published_date")
        order = request.args.get("order", "desc")
        page = request.args.get("page", 1, type=int)

        results = VulnerabilityService.query_vulnerabilities(
            conn, q=q, severity=severity, product=product,
            sort=sort, order=order, page=page, per_page=25
        )
        products_list = VulnerabilityService.get_distinct_products(conn, limit=100)

        return render_template(
            "vulnerabilities.html",
            results=results,
            filters={"q": q, "severity": severity, "product": product, "sort": sort, "order": order},
            products_list=products_list
        )

    @app.route("/api/vulnerabilities")
    def api_vulnerabilities():
        conn = get_db()
        q = request.args.get("q", "").strip()
        severity = request.args.get("severity", "ALL")
        product = request.args.get("product", "")
        sort = request.args.get("sort", "published_date")
        order = request.args.get("order", "desc")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 25, type=int)

        data = VulnerabilityService.query_vulnerabilities(
            conn, q=q, severity=severity, product=product,
            sort=sort, order=order, page=page, per_page=per_page
        )
        return jsonify(data)

    @app.route("/vulnerabilities/<int:vuln_id>")
    def vulnerability_detail(vuln_id):
        conn = get_db()
        vuln = VulnerabilityService.get_by_id(conn, vuln_id)
        if not vuln:
            return render_template("error.html", code=404, name="Not Found", description=f"Vulnerability ID #{vuln_id} not found."), 404

        history = VulnerabilityService.get_change_history(conn, vuln_id=vuln_id)
        products = VulnerabilityService.get_products_for_vuln(conn, vuln_id)
        return render_template("vulnerability_detail.html", vuln=vuln, history=history, products=products)

    @app.route("/history")
    def history_page():
        conn = get_db()
        history = VulnerabilityService.get_change_history(conn, limit=100)
        return render_template("history.html", history=history)

    @app.route("/import", methods=["GET"])
    def import_page():
        conn = get_db()
        data_dir = app.config.get("DATA_DIR", Config.DATA_DIR)
        data_files = [f.name for f in data_dir.glob("*.csv")] if data_dir.exists() else []

        imports = conn.execute("SELECT * FROM import_history ORDER BY started_at DESC LIMIT 20").fetchall()
        return render_template("import.html", data_files=data_files, imports=[dict(i) for i in imports])

    @app.route("/import/from-data", methods=["POST"])
    def import_from_data():
        selected = request.form.get("selected_file")
        data_dir = app.config.get("DATA_DIR", Config.DATA_DIR)
        allowed_files = [f.name for f in data_dir.glob("*.csv")] if data_dir.exists() else []

        if selected not in allowed_files:
            flash("Invalid file selection. Only verified files in data/ can be imported.", "error")
            return redirect(url_for("import_page"))

        target_file = data_dir / selected
        conn = get_db()
        importer = DatasetImporter(conn, chunk_size=app.config.get("CHUNK_SIZE", 5000))

        try:
            stats = importer.import_file(target_file)
            flash(f"Import completed successfully! {stats['new_count']} new, {stats['updated_count']} updated, {stats['unchanged_count']} unchanged.", "success")
        except Exception as e:
            app.logger.exception("Import error: %s", e)
            flash(f"Import failed: {str(e)}", "error")

        return redirect(url_for("import_page"))

    @app.route("/import/upload", methods=["POST"])
    def import_upload():
        if "dataset_file" not in request.files:
            flash("No file was uploaded.", "error")
            return redirect(url_for("import_page"))

        file = request.files["dataset_file"]
        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("import_page"))

        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext != "csv":
            flash("Only CSV files are supported for import.", "error")
            return redirect(url_for("import_page"))

        uploads_dir = app.config.get("UPLOADS_DIR", Config.UPLOADS_DIR)
        temp_filename = f"{uuid.uuid4().hex}_{filename}"
        temp_path = uploads_dir / temp_filename

        try:
            file.save(temp_path)
            conn = get_db()
            importer = DatasetImporter(conn, chunk_size=app.config.get("CHUNK_SIZE", 5000))
            stats = importer.import_file(temp_path)
            flash(f"Dataset '{filename}' successfully ingested! {stats['new_count']} new records.", "success")
        except Exception as e:
            app.logger.exception("Upload import error: %s", e)
            flash(f"Import failed: {str(e)}", "error")
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

        return redirect(url_for("import_page"))

    @app.route("/status")
    def status_page():
        conn = get_db()
        freshness = RefreshService.get_data_freshness(conn, app.config.get("STALE_AFTER_HOURS", 24))
        is_refreshing = RefreshService.is_refresh_running()
        refreshes = conn.execute("SELECT * FROM refresh_history ORDER BY started_at DESC LIMIT 20").fetchall()
        has_key = bool(app.config.get("NVD_API_KEY"))

        return render_template(
            "system_status.html",
            freshness=freshness,
            is_refreshing=is_refreshing,
            refreshes=[dict(r) for r in refreshes],
            api_key_configured=has_key
        )

    @app.route("/api/refresh/status")
    def api_refresh_status():
        is_refreshing = RefreshService.is_refresh_running()
        conn = get_db()
        freshness = RefreshService.get_data_freshness(conn, app.config.get("STALE_AFTER_HOURS", 24))
        return jsonify({
            "is_refreshing": is_refreshing,
            "freshness": freshness
        })

    @app.route("/refresh", methods=["POST"])
    def trigger_refresh():
        if RefreshService.is_refresh_running():
            flash("An NVD refresh operation is already running.", "warning")
            return redirect(url_for("status_page"))

        try:
            RefreshService.start_background_refresh(
                app, lookback_days=app.config.get("NVD_INITIAL_LOOKBACK_DAYS", 1)
            )
            flash("NVD Synchronization initiated in the background.", "info")
        except Exception as e:
            flash(f"Could not start refresh: {str(e)}", "error")

        return redirect(url_for("status_page"))

    @app.route("/notifications")
    def notifications_page():
        conn = get_db()
        notifs = NotificationService.get_notifications(conn, limit=50)
        return render_template("notifications.html", notifications=[dict(n) for n in notifs])

    @app.route("/notifications/<int:notif_id>/read", methods=["POST"])
    def notification_read(notif_id):
        conn = get_db()
        NotificationService.mark_read(conn, notif_id)
        return redirect(url_for("notifications_page"))

    @app.route("/notifications/read-all", methods=["POST"])
    def notifications_read_all():
        conn = get_db()
        NotificationService.mark_all_read(conn)
        return redirect(url_for("notifications_page"))

    @app.route("/ml")
    def ml_page():
        is_avail = MLService.is_model_available()
        metrics = None
        if is_avail:
            _, metrics = MLService.load_model()
        return render_template(
            "ml_classification.html",
            is_available=is_avail,
            metrics=metrics,
            prediction=None,
            input_text=""
        )

    @app.route("/ml/predict", methods=["POST"])
    def ml_predict():
        desc = request.form.get("description", "").strip()
        is_avail = MLService.is_model_available()
        metrics = None
        prediction = None

        if is_avail:
            _, metrics = MLService.load_model()
            try:
                prediction = MLService.predict(desc)
            except Exception as e:
                flash(f"Prediction failed: {str(e)}", "error")

        return render_template(
            "ml_classification.html",
            is_available=is_avail,
            metrics=metrics,
            prediction=prediction,
            input_text=desc
        )

    return app

if __name__ == "__main__":
    app = create_app()
    # Bind to 127.0.0.1 for secure local execution
    app.run(host="127.0.0.1", port=5000, debug=True)
