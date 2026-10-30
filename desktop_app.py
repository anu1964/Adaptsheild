"""
AdaptShield native Windows desktop application.
Uses the existing security pipeline and Groq integration from server.py.
This file does NOT start FastAPI/Uvicorn or open a localhost server.
"""

import os
import sys
import shutil
import tempfile
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QComboBox, QFileDialog, QMessageBox,
    QLineEdit, QDialog, QFormLayout, QDialogButtonBox, QFrame,
    QProgressBar, QSplitter
)

# Importing server.py loads the existing functions but does not run Uvicorn:
# its uvicorn.run(...) call is protected by if __name__ == "__main__".
import server as core


APP_NAME = "AdaptShield"
MAX_MESSAGE_CHARS = getattr(core, "MAX_MESSAGE_CHARS", 4000)
MAX_UPLOAD_BYTES = getattr(core, "MAX_UPLOAD_BYTES", 10 * 1024 * 1024)


class ApiKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AdaptShield – API Configuration")
        self.setMinimumWidth(430)
        layout = QVBoxLayout(self)
        info = QLabel(
            "Enter your Groq API key. It will be saved in config.env "
            "beside the application executable."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        form = QFormLayout()
        self.key_edit = QLineEdit(core.load_groq_key())
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText("gsk_...")
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


class TaskWorker(QObject):
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, prompt, model, history, attachment_path):
        super().__init__()
        self.prompt = prompt
        self.model = model
        self.history = list(history)
        self.attachment_path = attachment_path

    def run(self):
        temp_path = None
        try:
            if self.attachment_path:
                suffix = Path(self.attachment_path).suffix
                temp_dir = Path(tempfile.gettempdir()) / "AdaptShield"
                temp_dir.mkdir(parents=True, exist_ok=True)
                temp_path = str(temp_dir / ("uploaded_document" + suffix))
                shutil.copy2(self.attachment_path, temp_path)
                if Path(temp_path).stat().st_size > MAX_UPLOAD_BYTES:
                    self.finished.emit({
                        "kind": "error",
                        "message": "File is too large. Maximum supported size is 10 MB."
                    })
                    return

            # Match the web workflow: prior history is used for contextual risk.
            context_history = list(self.history)
            model_history = [] if temp_path else list(self.history)

            scores = core.run_defense_pipeline(
                self.prompt, temp_path, context_history
            )
            doc_text = scores.pop("doc_text", "")

            if scores.get("decision") == "BLOCK":
                blocked_by, reason = core.explain_block(scores, temp_path)
                self.finished.emit({
                    "kind": "blocked",
                    "blocked_by": blocked_by,
                    "reason": reason,
                    "scores": scores,
                })
                return

            if scores.get("decision") == "WARN":
                warning = (
                    "Warning: this message looks suspicious. "
                    "A restricted safe-mode response will be used."
                )
            elif scores.get("decision") == "SAFE":
                warning = None
            else:
                self.finished.emit({
                    "kind": "blocked",
                    "blocked_by": "verification",
                    "reason": "The request could not be verified as safe.",
                    "scores": scores,
                })
                return

            if temp_path and not doc_text.strip():
                scores["decision"] = "BLOCK"
                scores["flags"] = scores.get("flags", []) + [
                    "document_empty_after_cleaning"
                ]
                self.finished.emit({
                    "kind": "blocked",
                    "blocked_by": "document",
                    "reason": (
                        "The document has no readable visible text. "
                        "It may contain only hidden content."
                    ),
                    "scores": scores,
                })
                return

            model_prompt = self.prompt
            if doc_text.strip():
                model_prompt += (
                    "\n\n<<<DOCUMENT\n" + doc_text + "\nDOCUMENT>>>"
                )

            ok, reply = core.call_model(
                self.model,
                model_prompt,
                model_history,
                safe_mode=bool(warning),
            )
            if not ok:
                self.finished.emit({
                    "kind": "model_error",
                    "message": reply,
                    "scores": scores,
                })
                return

            unsafe, out_reason = core.check_reply(reply)
            if unsafe:
                scores["decision"] = "BLOCK"
                scores["final_score"] = max(
                    float(scores.get("final_score", 0)), 0.9
                )
                scores["flags"] = scores.get("flags", []) + [
                    "output_guard_triggered"
                ]
                self.finished.emit({
                    "kind": "blocked",
                    "blocked_by": "output",
                    "reason": out_reason,
                    "scores": scores,
                })
                return

            if warning:
                reply = warning + "\n\n" + reply

            self.finished.emit({
                "kind": "success",
                "reply": reply,
                "scores": scores,
            })

        except Exception:
            self.failed.emit(traceback.format_exc())
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass


class ModelWorker(QObject):
    finished = Signal(list)

    def run(self):
        try:
            self.finished.emit(core.get_available_models())
        except Exception:
            self.finished.emit([])


class AdaptShieldWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdaptShield")
        self.resize(1050, 760)
        self.setMinimumSize(800, 600)

        self.history = []
        self.attachment_path = None
        self.task_thread = None
        self.model_thread = None

        self.setStyleSheet("""
            QMainWindow, QWidget { background: #0b1220; color: #e5e7eb; }
            QLabel#heading { font-size: 25px; font-weight: 700; color: #f8fafc; }
            QLabel#muted { color: #9ca3af; }
            QTextEdit, QLineEdit, QComboBox {
                background: #111c2e; color: #f8fafc;
                border: 1px solid #334155; border-radius: 8px;
                padding: 9px; selection-background-color: #2563eb;
            }
            QPushButton {
                background: #263449; color: white; border: 0;
                border-radius: 8px; padding: 10px 15px; font-weight: 600;
            }
            QPushButton:hover { background: #354862; }
            QPushButton:disabled { color: #64748b; background: #1e293b; }
            QPushButton#primary { background: #b93832; }
            QPushButton#primary:hover { background: #d0443c; }
            QFrame#panel { background: #111c2e; border: 1px solid #263449; border-radius: 12px; }
            QProgressBar { border: 0; background: #263449; border-radius: 4px; height: 7px; }
            QProgressBar::chunk { background: #b93832; border-radius: 4px; }
        """)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(14)

        header = QHBoxLayout()
        title_col = QVBoxLayout()
        heading = QLabel("AdaptShield")
        heading.setObjectName("heading")
        subtitle = QLabel("Adaptive Semantic Defense for LLM Prompt Injection Attacks")
        subtitle.setObjectName("muted")
        title_col.addWidget(heading)
        title_col.addWidget(subtitle)
        header.addLayout(title_col)
        header.addStretch()

        self.model_combo = QComboBox()
        self.model_combo.setMinimumWidth(220)
        self.model_combo.addItem("Load models…")
        header.addWidget(QLabel("Model"))
        header.addWidget(self.model_combo)

        settings_btn = QPushButton("API Settings")
        settings_btn.clicked.connect(self.configure_api)
        header.addWidget(settings_btn)
        outer.addLayout(header)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("muted")
        outer.addWidget(self.status_label)

        splitter = QSplitter(Qt.Vertical)

        chat_panel = QFrame()
        chat_panel.setObjectName("panel")
        chat_layout = QVBoxLayout(chat_panel)
        chat_layout.setContentsMargins(16, 14, 16, 14)
        chat_layout.addWidget(QLabel("Conversation"))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(
            "Your conversation and AdaptShield security results will appear here."
        )
        chat_layout.addWidget(self.output)
        splitter.addWidget(chat_panel)

        input_panel = QFrame()
        input_panel.setObjectName("panel")
        input_layout = QVBoxLayout(input_panel)
        input_layout.setContentsMargins(16, 14, 16, 14)
        input_layout.addWidget(QLabel("Your prompt"))
        self.prompt_edit = QTextEdit()
        self.prompt_edit.setFixedHeight(115)
        self.prompt_edit.setPlaceholderText(
            "Enter a prompt to analyze securely…"
        )
        input_layout.addWidget(self.prompt_edit)

        controls = QHBoxLayout()
        self.file_label = QLabel("No document attached")
        self.file_label.setObjectName("muted")
        attach_btn = QPushButton("Attach document")
        attach_btn.clicked.connect(self.attach_document)
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self.remove_document)
        controls.addWidget(attach_btn)
        controls.addWidget(remove_btn)
        controls.addWidget(self.file_label, 1)

        self.send_btn = QPushButton("Analyze & Send")
        self.send_btn.setObjectName("primary")
        self.send_btn.clicked.connect(self.send_prompt)
        controls.addWidget(self.send_btn)
        input_layout.addLayout(controls)
        splitter.addWidget(input_panel)
        splitter.setSizes([430, 250])
        outer.addWidget(splitter, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        outer.addWidget(self.progress)

        footer = QLabel(
            "SAFE: normal processing   •   WARN: restricted safe mode   •   "
            "BLOCK: request is not sent to the model"
        )
        footer.setObjectName("muted")
        outer.addWidget(footer)

        self.refresh_models()

    def append_text(self, text):
        self.output.append(text)

    def refresh_models(self):
        if not core.load_groq_key():
            self.model_combo.clear()
            self.model_combo.addItem("Configure API key first")
            return
        self.model_combo.clear()
        self.model_combo.addItem("Loading models…")
        self.model_thread = QThread()
        self.model_worker = ModelWorker()
        self.model_worker.moveToThread(self.model_thread)
        self.model_thread.started.connect(self.model_worker.run)
        self.model_worker.finished.connect(self.models_loaded)
        self.model_worker.finished.connect(self.model_thread.quit)
        self.model_thread.finished.connect(self.model_worker.deleteLater)
        self.model_thread.finished.connect(self.model_thread.deleteLater)
        self.model_thread.start()

    def models_loaded(self, models):
        self.model_combo.clear()
        if models:
            self.model_combo.addItems(models)
            self.status_label.setText(
                f"Ready • {len(models)} Groq models available"
            )
        else:
            self.model_combo.addItem("No models available")
            self.status_label.setText(
                "No models loaded. Check the API key and internet connection."
            )

    def configure_api(self):
        dialog = ApiKeyDialog(self)
        if dialog.exec() == QDialog.Accepted:
            key = dialog.key_value()
            if not key:
                QMessageBox.warning(self, "Missing key", "Enter a Groq API key.")
                return
            if core.save_groq_key(key):
                QMessageBox.information(
                    self, "Saved", "API key saved. Loading available models."
                )
                self.refresh_models()
            else:
                QMessageBox.critical(
                    self, "Save failed", "Could not save config.env."
                )

    def attach_document(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a document",
            "",
            "Supported documents (*.pdf *.docx *.txt *.html *.htm *.eml);;All files (*.*)"
        )
        if path:
            if Path(path).stat().st_size > MAX_UPLOAD_BYTES:
                QMessageBox.warning(
                    self, "File too large", "Maximum document size is 10 MB."
                )
                return
            self.attachment_path = path
            self.file_label.setText(Path(path).name)

    def remove_document(self):
        self.attachment_path = None
        self.file_label.setText("No document attached")

    def send_prompt(self):
        prompt = self.prompt_edit.toPlainText().strip()
        if not prompt:
            QMessageBox.information(self, "Prompt required", "Enter a prompt first.")
            return
        if len(prompt) > MAX_MESSAGE_CHARS:
            QMessageBox.warning(
                self, "Prompt too long",
                f"Maximum prompt length is {MAX_MESSAGE_CHARS} characters."
            )
            return
        if self.model_combo.count() == 0 or self.model_combo.currentText() in (
            "Configure API key first", "Loading models…", "No models available"
        ):
            QMessageBox.warning(
                self, "Model unavailable",
                "Configure a valid Groq API key and select an available model."
            )
            return

        model = self.model_combo.currentText()
        self.append_text(f"<b style='color:#93c5fd'>YOU</b><br>{self._html(prompt)}")
        if self.attachment_path:
            self.append_text(
                f"<span style='color:#9ca3af'>Attached: "
                f"{self._html(Path(self.attachment_path).name)}</span>"
            )

        self.send_btn.setEnabled(False)
        self.progress.show()
        self.status_label.setText("Analyzing prompt and document…")

        self.task_thread = QThread()
        self.task_worker = TaskWorker(
            prompt, model, self.history, self.attachment_path
        )
        self.task_worker.moveToThread(self.task_thread)
        self.task_thread.started.connect(self.task_worker.run)
        self.task_worker.finished.connect(self.task_finished)
        self.task_worker.failed.connect(self.task_failed)
        self.task_worker.finished.connect(self.task_thread.quit)
        self.task_worker.failed.connect(self.task_thread.quit)
        self.task_thread.finished.connect(self.task_worker.deleteLater)
        self.task_thread.finished.connect(self.task_thread.deleteLater)
        self.task_thread.start()

        self.history.append({"role": "user", "content": prompt})
        self.prompt_edit.clear()
        self.remove_document()

    @staticmethod
    def _html(value):
        return (
            str(value).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;")
            .replace("\n", "<br>")
        )

    def task_finished(self, result):
        self.send_btn.setEnabled(True)
        self.progress.hide()
        kind = result.get("kind")
        scores = result.get("scores", {})

        if kind == "error":
            self.append_text(
                f"<span style='color:#fca5a5'>ERROR: "
                f"{self._html(result.get('message'))}</span>"
            )
            self.status_label.setText("Ready")
            return

        if scores:
            decision = scores.get("decision", "UNKNOWN")
            score = float(scores.get("final_score", 0))
            color = {
                "SAFE": "#34d399", "WARN": "#fbbf24",
                "BLOCK": "#f87171"
            }.get(decision, "#e5e7eb")
            details = (
                f"<br><br><b>AdaptShield result:</b> "
                f"<span style='color:{color}'>{self._html(decision)}</span>"
                f"<br>Final risk score: {score:.3f}"
                f"<br>Input risk (R1): {float(scores.get('r1', 0)):.3f}"
                f"<br>Document risk (R2): {float(scores.get('r2', 0)):.3f}"
                f"<br>Divergence: {float(scores.get('divergence', 0)):.3f}"
                f"<br>Flags: {self._html(', '.join(scores.get('flags', [])) or 'None')}"
                f"<br>Matched keywords: "
                f"{self._html(', '.join(scores.get('keywords', [])) or 'None')}"
            )
            self.append_text(details)

        if kind == "blocked":
            self.append_text(
                f"<br><b style='color:#f87171'>BLOCKED</b> "
                f"({self._html(result.get('blocked_by', 'security'))})"
                f"<br>{self._html(result.get('reason', 'Request blocked.'))}"
            )
            self.status_label.setText("Request blocked by AdaptShield")
        elif kind == "model_error":
            self.append_text(
                f"<br><b style='color:#fbbf24'>MODEL ERROR</b><br>"
                f"{self._html(result.get('message', 'Model unavailable.'))}"
            )
            self.status_label.setText("Security scan completed; model unavailable")
        elif kind == "success":
            reply = result.get("reply", "")
            self.append_text(
                f"<br><b style='color:#86efac'>ADAPTSHIELD ASSISTANT</b><br>"
                f"{self._html(reply)}<br>"
            )
            self.history.append({"role": "assistant", "content": reply})
            self.status_label.setText("Ready")
        else:
            self.status_label.setText("Completed")

    def task_failed(self, error):
        self.send_btn.setEnabled(True)
        self.progress.hide()
        self.status_label.setText("An error occurred")
        QMessageBox.critical(
            self, "AdaptShield error",
            "The security pipeline encountered an unexpected error:\n\n" + error
        )

    def closeEvent(self, event):
        # Avoid destroying active worker threads while a task is running.
        if self.task_thread and self.task_thread.isRunning():
            QMessageBox.warning(
                self, "Task running",
                "Please wait for the current security scan to finish before closing."
            )
            event.ignore()
            return
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = AdaptShieldWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
