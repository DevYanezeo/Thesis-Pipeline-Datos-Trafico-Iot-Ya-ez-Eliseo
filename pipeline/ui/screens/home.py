"""Pantalla de inicio: elegir comando."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Static


class HomeScreen(Screen):
    BINDINGS = [
        ("1", "pick_run", "Run"),
        ("2", "pick_preprocess", "Preprocess"),
        ("3", "pick_convert", "Convert"),
        ("q", "quit", "Salir"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("Pipeline IoT — consola", id="title")
        yield Vertical(
            Button("1 · Ejecutar pipeline (run)", id="btn-run", classes="menu-button", variant="primary"),
            Button("2 · Handoff ML (preprocess-ml)", id="btn-preprocess", classes="menu-button"),
            Button("3 · Convertir JSON → CSV", id="btn-convert", classes="menu-button"),
            id="menu",
        )
        yield Static(
            "Mismos parámetros y lógica que `python -m pipeline`.  q · salir",
            id="hint",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "btn-run":
            self.app.push_screen("form_run")
        elif bid == "btn-preprocess":
            self.app.push_screen("form_preprocess")
        elif bid == "btn-convert":
            self.app.push_screen("form_convert")

    def action_pick_run(self) -> None:
        self.app.push_screen("form_run")

    def action_pick_preprocess(self) -> None:
        self.app.push_screen("form_preprocess")

    def action_pick_convert(self) -> None:
        self.app.push_screen("form_convert")

    def action_quit(self) -> None:
        self.app.exit()