"""Formulario para `convert-metadata`."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, Static


class FormConvertScreen(Screen):
    BINDINGS = [("escape", "back", "Volver")]

    def compose(self) -> ComposeResult:
        yield Static("Convertir metadatos JSON → CSV auxiliar", id="title")
        with VerticalScroll():
            yield Label("JSON upstream *")
            yield Input(placeholder="fixtures/.../metadata.json", id="json")
            yield Label("PCAP asociado *")
            yield Input(placeholder="fixtures/.../capture.pcap", id="pcap")
            yield Label("Salida .csv *")
            yield Input(placeholder="output/events.csv", id="output")
            yield Checkbox("Log verbose (-v)", id="verbose")
        yield Button("Ejecutar ⏎", id="submit", variant="success")
        yield Static("esc · volver al menú", id="hint")

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "submit":
            return
        opts = {
            "json": self.query_one("#json", Input).value.strip(),
            "pcap": self.query_one("#pcap", Input).value.strip(),
            "output": self.query_one("#output", Input).value.strip(),
        }
        if not all(opts.values()):
            self.notify("Todos los campos son obligatorios", severity="error")
            return
        verbose = self.query_one("#verbose", Checkbox).value
        from pathlib import Path

        from pipeline.ui.screens.console import ConsoleScreen

        self.app.push_screen(
            ConsoleScreen(
                mode="convert",
                verbose=verbose,
                run_opts=opts,
                output_dir=Path(opts["output"]).parent,
            )
        )