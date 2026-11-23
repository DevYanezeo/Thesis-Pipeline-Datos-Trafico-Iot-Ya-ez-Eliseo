"""Formulario para `pipeline run`."""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from pipeline.extract import (
    DEFAULT_ACTIVE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_N_DISSECTIONS,
)


class FormRunScreen(Screen):
    BINDINGS = [("escape", "back", "Volver")]

    def compose(self) -> ComposeResult:
        yield Static("Ejecutar pipeline — parámetros", id="title")
        with VerticalScroll():
            yield Label("Ruta PCAP (vacío si usa directorio artifacts)")
            yield Input(placeholder="fixtures/.../capture.pcap", id="pcap")
            yield Label("Directorio PCAP multi-segmento (--artifact-pcap-dir)")
            yield Input(placeholder="", id="artifact_pcap_dir")
            yield Label("Metadatos JSON o CSV *")
            yield Input(
                placeholder="fixtures/upstream-run-00/metadata.json",
                id="metadata",
            )
            yield Label("Directorio de salida *")
            yield Input(placeholder="output/run01/", id="output")
            yield Label("Horizontes N (coma, ej. 5,10,20)")
            yield Input(placeholder="", id="packet_horizons")
            yield Label("Un solo horizonte N")
            yield Input(placeholder="", id="packet_horizon")
            yield Checkbox("Incluir full_flow (--full)", id="full")
            yield Checkbox("Métricas I/O (--evaluate)", id="evaluate")
            yield Checkbox("Análisis estadístico NFStream", value=True, id="statistical_analysis")
            yield Label("Privacidad IP")
            yield Select(
                (("none", "none"), ("pseudonymize", "pseudonymize"), ("anonymize", "anonymize")),
                value="none",
                id="privacy",
            )
            yield Label(f"idle-timeout (default {DEFAULT_IDLE_TIMEOUT})")
            yield Input(value=str(DEFAULT_IDLE_TIMEOUT), id="idle_timeout")
            yield Label(f"active-timeout (default {DEFAULT_ACTIVE_TIMEOUT})")
            yield Input(value=str(DEFAULT_ACTIVE_TIMEOUT), id="active_timeout")
            yield Label(f"n-dissections (default {DEFAULT_N_DISSECTIONS})")
            yield Input(value=str(DEFAULT_N_DISSECTIONS), id="n_dissections")
            yield Checkbox("Log verbose (-v)", id="verbose")
        yield Button("Ejecutar ⏎", id="submit", variant="success")
        yield Static("esc · volver al menú", id="hint")

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "submit":
            return
        metadata = self.query_one("#metadata", Input).value.strip()
        output = self.query_one("#output", Input).value.strip()
        pcap = self.query_one("#pcap", Input).value.strip()
        artifact_dir = self.query_one("#artifact_pcap_dir", Input).value.strip()
        if not metadata or not output:
            self.notify("metadata y output son obligatorios", severity="error")
            return
        if not pcap and not artifact_dir:
            self.notify("Indique PCAP o artifact-pcap-dir", severity="error")
            return
        if pcap and not Path(pcap).exists():
            self.notify(f"PCAP no encontrado: {pcap}", severity="warning")
        if metadata and not Path(metadata).exists():
            self.notify(f"Metadatos no encontrados: {metadata}", severity="warning")

        ph = self.query_one("#packet_horizon", Input).value.strip()
        phs = self.query_one("#packet_horizons", Input).value.strip()
        opts = {
            "pcap": pcap or None,
            "artifact_pcap_dir": artifact_dir or None,
            "metadata": metadata,
            "output": output,
            "packet_horizon": int(ph) if ph else None,
            "packet_horizons": phs or None,
            "include_full": self.query_one("#full", Checkbox).value,
            "evaluate": self.query_one("#evaluate", Checkbox).value,
            "statistical_analysis": self.query_one("#statistical_analysis", Checkbox).value,
            "privacy_mode": str(self.query_one("#privacy", Select).value),
            "idle_timeout": int(self.query_one("#idle_timeout", Input).value.strip() or DEFAULT_IDLE_TIMEOUT),
            "active_timeout": int(self.query_one("#active_timeout", Input).value.strip() or DEFAULT_ACTIVE_TIMEOUT),
            "n_dissections": int(self.query_one("#n_dissections", Input).value.strip() or DEFAULT_N_DISSECTIONS),
        }
        verbose = self.query_one("#verbose", Checkbox).value
        from pipeline.ui.screens.console import ConsoleScreen

        self.app.push_screen(
            ConsoleScreen(
                mode="run",
                verbose=verbose,
                run_opts=opts,
                output_dir=Path(output),
            )
        )