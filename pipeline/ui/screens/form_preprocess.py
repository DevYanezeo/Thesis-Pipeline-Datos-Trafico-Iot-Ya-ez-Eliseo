"""Formulario para `preprocess-ml`."""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static


class FormPreprocessScreen(Screen):
    BINDINGS = [("escape", "back", "Volver")]

    def compose(self) -> ComposeResult:
        yield Static("Handoff ML — preprocess-ml", id="title")
        with VerticalScroll():
            yield Label("flows.parquet de entrada *")
            yield Input(placeholder="output/run01/flows.parquet", id="input")
            yield Label("Directorio de salida *")
            yield Input(placeholder="output/run01/ml-handoff/", id="output")
            yield Label("test-size (0.2 = 80/20)")
            yield Input(value="0.2", id="test_size")
            yield Label("split-by")
            yield Select(
                (("episode", "episode"), ("temporal", "temporal"), ("flow", "flow")),
                value="episode",
                id="split_by",
            )
            yield Checkbox("Estratificar clases", value=True, id="stratify")
            yield Label("seed")
            yield Input(value="42", id="seed")
            yield Label("classes")
            yield Select(
                (
                    ("three-class", "three-class"),
                    ("attack-benign", "attack-benign"),
                    ("attack-vs-all", "attack-vs-all"),
                ),
                value="three-class",
                id="classes",
            )
            yield Label("scaler")
            yield Select((("robust", "robust"), ("standard", "standard")), value="robust", id="scaler")
            yield Checkbox("Benchmark QA (--benchmark)", id="benchmark")
            yield Checkbox("Log verbose (-v)", id="verbose")
        yield Button("Ejecutar ⏎", id="submit", variant="success")
        yield Static("esc · volver al menú", id="hint")

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "submit":
            return
        inp = self.query_one("#input", Input).value.strip()
        out = self.query_one("#output", Input).value.strip()
        if not inp or not out:
            self.notify("input y output son obligatorios", severity="error")
            return
        opts = {
            "input": inp,
            "output": out,
            "test_size": float(self.query_one("#test_size", Input).value.strip() or "0.2"),
            "split_by": str(self.query_one("#split_by", Select).value),
            "stratify": self.query_one("#stratify", Checkbox).value,
            "seed": int(self.query_one("#seed", Input).value.strip() or "42"),
            "classes": str(self.query_one("#classes", Select).value),
            "scaler": str(self.query_one("#scaler", Select).value),
            "benchmark": self.query_one("#benchmark", Checkbox).value,
        }
        verbose = self.query_one("#verbose", Checkbox).value
        from pipeline.ui.screens.console import ConsoleScreen

        self.app.push_screen(
            ConsoleScreen(
                mode="preprocess",
                verbose=verbose,
                run_opts=opts,
                output_dir=Path(out),
            )
        )