"""AdaptShield native Windows desktop application.

Embeds the original static_app interface in Qt WebEngine and calls the existing
server.py security functions directly through Qt WebChannel. No HTTP server or
localhost port is started by this desktop application.
"""

import base64
import binascii
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QVBoxLayout,
)
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView

APP_NAME = "AdaptShield"
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)).resolve()
# Several existing defense modules may resolve the bundled MiniLM model from a
# relative ./models path. Set the app base before importing the backend.
os.chdir(BASE_DIR)

import server as core

MAX_MESSAGE_CHARS = getattr(core, "MAX_MESSAGE_CHARS", 4000)
MAX_UPLOAD_BYTES = getattr(core, "MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".html", ".htm", ".eml", ".txt"}
STATIC_APP_DIR = BASE_DIR / "static_app"


class ApiKeyDialog(QDialog):
    """Native API-key dialog. The key is saved in the per-user app-data folder."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AdaptShield — Groq API Configuration")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        note = QLabel(
            "Enter your Groq API key. It will be stored locally for your Windows "
            "user account and sent only to the official Groq API."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        form = QFormLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText("gsk_... (enter a key to save or replace)")
        form.addRow("Groq API key:", self.key_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def key_value(self):
        return self.key_edit.text().strip()


class ModelWorker(QThread):
    resultReady = Signal(str)

    def run(self):
        try:
            models = core.get_available_models()
            result = {
                "models": models,
                "groq_key_set": bool(core.load_groq_key()),
                "error": getattr(core, "_models_cache", {}).get("error"),
            }
        except Exception:
            result = {
                "models": [],
                "groq_key_set": bool(core.load_groq_key()),
                "error": "provider_error",
            }
        self.resultReady.emit(json.dumps(result))


class ChatWorker(QThread):
    resultReady = Signal(str)

    def __init__(self, payload):
        super().__init__()
        self.payload = payload

    def _error(self, message):
        return {"error": message}

    def run(self):
        file_path = None
        try:
            message = str(self.payload.get("message", ""))
            model = str(self.payload.get("model", ""))
            if len(message) > MAX_MESSAGE_CHARS:
                self.resultReady.emit(json.dumps(self._error("Message is too long.")))
                return

            available_models = core.get_available_models()
            if available_models and model not in available_models:
                self.resultReady.emit(json.dumps(self._error("Unknown model.")))
                return

            raw_history = self.payload.get("history", [])
            if not isinstance(raw_history, list):
                raw_history = []
            history = [
                {"role": item["role"], "content": str(item.get("content", ""))[:4000]}
                for item in raw_history
                if isinstance(item, dict)
                and item.get("role") in ("user", "assistant")
            ][-8:]
            context_history = list(history)
            model_history = list(history)

            attachment = self.payload.get("file")
            if attachment:
                filename = Path(str(attachment.get("name", "document.txt"))).name
                suffix = Path(filename).suffix.lower()
                if suffix not in ALLOWED_EXTENSIONS:
                    self.resultReady.emit(json.dumps(self._error("Unsupported document type.")))
                    return
                encoded = str(attachment.get("data", ""))
                if len(encoded) > ((MAX_UPLOAD_BYTES + 2) // 3) * 4 + 8:
                    self.resultReady.emit(json.dumps(self._error("File is too large (10 MB max).")))
                    return
                try:
                    file_bytes = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    self.resultReady.emit(json.dumps(self._error("The uploaded document could not be read.")))
                    return
                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    self.resultReady.emit(json.dumps(self._error("File is too large (10 MB max).")))
                    return
                upload_dir = Path(core.UPLOAD_DIR)
                upload_dir.mkdir(parents=True, exist_ok=True)
                handle = tempfile.NamedTemporaryFile(
                    mode="wb", suffix=suffix, prefix="desktop_upload_",
                    dir=str(upload_dir), delete=False,
                )
                file_path = handle.name
                with handle:
                    handle.write(file_bytes)
                # Match the existing FastAPI route: attachments are scanned with
                # prior context, but prior chat messages are not sent to the LLM.
                model_history = []

            start = __import__("time").perf_counter()
            scores = core.run_defense_pipeline(message, file_path, context_history)
            defense_elapsed = __import__("time").perf_counter() - start
            doc_text = scores.pop("doc_text", "")

            # Stage 1: input/document defense. BLOCK never reaches the model.
            if scores.get("decision") == "BLOCK":
                blocked_by, reason = core.explain_block(scores, file_path)
                self.resultReady.emit(json.dumps({
                    "blocked": True,
                    "blocked_by": blocked_by,
                    "reason": reason,
                    "reply": None,
                    "scores": scores,
                }))
                return

            warning = None
            if scores.get("decision") == "WARN":
                warning = (
                    "⚠️ Warning: this message looks suspicious, so only a safe, "
                    "limited answer is given."
                )
            elif scores.get("decision") != "SAFE":
                blocked_by, _ = core.explain_block(scores, file_path)
                self.resultReady.emit(json.dumps({
                    "blocked": True,
                    "blocked_by": blocked_by,
                    "reason": "This request could not be verified as safe, so it was not sent to the model.",
                    "reply": None,
                    "scores": scores,
                }))
                return

            if file_path and not doc_text.strip():
                scores["decision"] = "BLOCK"
                scores["flags"] = scores.get("flags", []) + ["document_empty_after_cleaning"]
                self.resultReady.emit(json.dumps({
                    "blocked": True,
                    "blocked_by": "document",
                    "reason": "The document has no readable visible text. It may contain only hidden content.",
                    "reply": None,
                    "scores": scores,
                }))
                return

            model_prompt = message
            if doc_text.strip():
                model_prompt = f"{message}\n\n<<<DOCUMENT\n{doc_text}\nDOCUMENT>>>"

            # Stage 2: WARN is passed to the model with safe_mode=True.
            model_start = __import__("time").perf_counter()
            model_ok, reply = core.call_model(
                model, model_prompt, model_history, safe_mode=bool(warning)
            )
            model_elapsed = __import__("time").perf_counter() - model_start
            print(
                f"desktop defense: {defense_elapsed:.2f}s | model: {model_elapsed:.2f}s",
                flush=True,
            )

            if not model_ok:
                self.resultReady.emit(json.dumps({
                    "blocked": False,
                    "reply": reply,
                    "model_error": True,
                    "scores": scores,
                }))
                return

            # Stage 3: output defense. Unsafe replies are never displayed.
            unsafe, output_reason = core.check_reply(reply)
            if unsafe:
                scores["decision"] = "BLOCK"
                scores["final_score"] = max(float(scores.get("final_score", 0)), 0.9)
                scores["flags"] = scores.get("flags", []) + ["output_guard_triggered"]
                self.resultReady.emit(json.dumps({
                    "blocked": True,
                    "blocked_by": "output",
                    "reason": output_reason,
                    "reply": None,
                    "scores": scores,
                }))
                return

            if warning:
                reply = f"{warning}\n\n{reply}"
            self.resultReady.emit(json.dumps({
                "blocked": False,
                "reply": reply,
                "scores": scores,
            }))

        except Exception:
            traceback.print_exc()
            self.resultReady.emit(json.dumps({"error": "Internal desktop error. Check the application log."}))
        finally:
            if file_path:
                try:
                    os.remove(file_path)
                except OSError:
                    pass


class DesktopBridge(QObject):
    modelsReady = Signal(str)
    chatFinished = Signal(str)
    openSettingsRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._model_worker = None
        self._chat_worker = None

    @Slot()
    def requestModels(self):
        if self._model_worker is not None and self._model_worker.isRunning():
            return
        self._model_worker = ModelWorker(self)
        worker = self._model_worker
        worker.resultReady.connect(self.modelsReady.emit)
        worker.finished.connect(self._clear_model_worker)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    @Slot()
    def _clear_model_worker(self):
        self._model_worker = None

    @Slot()
    def _clear_chat_worker(self):
        self._chat_worker = None

    @Slot(result=str)
    def getStatusJson(self):
        return json.dumps(getattr(core, "_mods", {}))

    @Slot(str)
    def sendChat(self, payload_json):
        if self._chat_worker is not None and self._chat_worker.isRunning():
            self.chatFinished.emit(json.dumps({"error": "A scan is already running."}))
            return
        try:
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                raise ValueError("Invalid request")
        except (TypeError, ValueError, json.JSONDecodeError):
            self.chatFinished.emit(json.dumps({"error": "Invalid chat request."}))
            return
        self._chat_worker = ChatWorker(payload)
        worker = self._chat_worker
        worker.resultReady.connect(self.chatFinished.emit)
        worker.finished.connect(self._clear_chat_worker)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    @Slot()
    def openApiSettings(self):
        self.openSettingsRequested.emit()

    @Slot(str)
    def openExternalUrl(self, url):
        if url.startswith("https://"):
            QDesktopServices.openUrl(QUrl(url))


class AdaptShieldPage(QWebEnginePage):

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        print(
            f"[WEBENGINE] {source_id}:{line_number} - {message}",
            flush=True
        )

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        if url.scheme() in ("http", "https"):
            QDesktopServices.openUrl(url)
            return False
        return super().acceptNavigationRequest(
            url, navigation_type, is_main_frame
        )

class AdaptShieldWindow(QMainWindow):
    def check_frontend(self, success):
        print("\n========== FRONTEND DIAGNOSTICS ==========", flush=True)
        print("HTML loaded:", success, flush=True)

        script = """
    (() => {
    const styles = [...document.styleSheets].map((s, i) => {
        let rules = "inaccessible";
        try {
            rules = s.cssRules.length;
        } catch(e) {
            rules = e.name + ": " + e.message;
        }
        return {
            index: i,
            href: s.href,
            disabled: s.disabled,
            rules: rules
        };
    });

    const scripts = [...document.scripts].map(s => ({
        src: s.src,
        loaded: s.readyState || "unknown"
    }));

    return JSON.stringify({
        stylesheets: styles,
        scripts: scripts,
        appJsResource: performance.getEntriesByType("resource")
            .filter(r => r.name.includes("app.js"))
            .map(r => r.name),
        qwebchannelResource: performance.getEntriesByType("resource")
            .filter(r => r.name.includes("qwebchannel"))
            .map(r => r.name),
        qWebChannelType: typeof QWebChannel,
        bridgePromise: typeof window.adaptShieldBridgeReady,
        bridgeObject: typeof window.adaptShieldBridge
    });
})()
"""

        self.view.page().runJavaScript(
         script,
            lambda result: print("FRONTEND STATUS:", result, flush=True)
)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdaptShield — Interactive Security Console")
        self.resize(1280, 820)
        self.setMinimumSize(900, 620)

        self.view = QWebEngineView(self)
        self.page = AdaptShieldPage(self.view)
        self.view.setPage(self.page)
        self.setCentralWidget(self.view)

        settings = self.page.settings()

        settings.setAttribute(
    QWebEngineSettings.LocalContentCanAccessFileUrls, True
)
        settings.setAttribute(
    QWebEngineSettings.LocalContentCanAccessRemoteUrls, True
)
        settings.setAttribute(
    QWebEngineSettings.JavascriptEnabled, True
)
        self.channel = QWebChannel(self.page)
        self.bridge = DesktopBridge(self)
        self.channel.registerObject("adaptShield", self.bridge)
        self.page.setWebChannel(self.channel)
        self.bridge.openSettingsRequested.connect(self.configure_api)

        index_file = STATIC_APP_DIR / "index.html"
        if not index_file.is_file():
            QMessageBox.critical(
                self, "AdaptShield files missing",
                f"Could not find the original interface:\n{index_file}\n\n"
                "Ensure static_app is included in the application build.",
            )
            raise FileNotFoundError(index_file)
        self.view.load(QUrl.fromLocalFile(str(index_file)))
        html = index_file.read_text(encoding="utf-8")

        base_url = QUrl.fromLocalFile(str(STATIC_APP_DIR.resolve()) + os.sep
        )

        self.view.setHtml(html, base_url)
        self.view.loadFinished.connect(self.check_frontend)


    def configure_api(self):
        dialog = ApiKeyDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        key = dialog.key_value()
        if not key:
            QMessageBox.warning(self, "Missing key", "Enter a Groq API key to save it.")
            return
        if core.save_groq_key(key):
            QMessageBox.information(
                self, "AdaptShield", "API key saved locally. Checking available Groq models."
            )
            # Re-run the frontend loader so it subscribes to modelsReady before
            # requesting the refreshed model list from the background worker.
            self.view.page().runJavaScript("loadModels();")
        else:
            QMessageBox.critical(
                self, "Save failed",
                f"Could not save the key to the user data folder:\n{core.CONFIG_ENV_PATH}",
            )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("AdaptShield")
    window = AdaptShieldWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
