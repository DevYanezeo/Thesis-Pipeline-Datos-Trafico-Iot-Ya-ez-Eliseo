"""Aplicación Textual del pipeline."""
from __future__ import annotations

from pathlib import Path

from textual.app import App

from pipeline.ui.screens.form_convert import FormConvertScreen
from pipeline.ui.screens.form_preprocess import FormPreprocessScreen
from pipeline.ui.screens.form_run import FormRunScreen
from pipeline.ui.screens.home import HomeScreen


class PipelineUiApp(App):
    TITLE = "Pipeline IoT"
    CSS_PATH = Path(__file__).with_name("tui.css")

    def on_mount(self) -> None:
        self.install_screen(HomeScreen(), name="home")
        self.install_screen(FormRunScreen(), name="form_run")
        self.install_screen(FormPreprocessScreen(), name="form_preprocess")
        self.install_screen(FormConvertScreen(), name="form_convert")
        self.push_screen("home")


def run_ui() -> int:
    """Arranca la consola. Devuelve 0 si la app terminó sin error de arranque."""
    try:
        PipelineUiApp().run()
    except KeyboardInterrupt:
        return 130
    return 0