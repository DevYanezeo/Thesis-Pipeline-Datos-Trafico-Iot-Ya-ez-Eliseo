"""Consola en vivo: etapas, logs filtrables y ejecución en segundo plano."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widgets import Input, RichLog, Static

from pipeline.ui.logs import (
    CONVERT_STAGES,
    PREPROCESS_STAGES,
    RUN_STAGES,
    LogBuffer,
    LogFilter,
    StageTracker,
    UiLogLevel,
    cycle_level_filter,
    default_stages_on,
    filtered_lines,
    level_filter_label,
)
from pipeline.ui.runner import list_output_artifacts, run_convert, run_full_pipeline, run_preprocess

Mode = Literal["run", "preprocess", "convert"]


class RunFinished(Message):
    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code
        super().__init__()


class HelpOverlay(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cerrar"), ("question_mark", "dismiss", "Cerrar")]

    def compose(self) -> ComposeResult:
        yield Static(
            "\n".join(
                [
                    "ETAPAS",
                    "  ↑ ↓ · seleccionar etapa",
                    "  ␣ · mostrar/ocultar logs de la etapa",
                    "  a · todas / ninguna",
                    "  ⏎ · solo esta etapa (⏎ otra vez restaura)",
                    "",
                    "LOGS",
                    "  l · nivel: ALL → ERR → ERR+WRN",
                    "  / · buscar (esc limpia)",
                    "  PgUp/PgDn · historial",
                    "  End · modo LIVE",
                    "",
                    "  ? · esta ayuda",
                    "  q · menú (corrida terminada)",
                ]
            ),
            id="help_overlay",
        )

    def action_dismiss(self) -> None:
        self.dismiss()


class ConsoleScreen(Screen):
    BINDINGS = [
        ("question_mark", "help", "Ayuda"),
        ("q", "go_home", "Menú"),
        ("l", "cycle_level", "Nivel"),
        ("slash", "search", "Buscar"),
        ("up", "stage_up", "Etapa arriba"),
        ("down", "stage_down", "Etapa abajo"),
        ("space", "toggle_stage", "Etapa on/off"),
        ("a", "toggle_all_stages", "Todas/ninguna"),
        ("enter", "solo_stage", "Solo etapa"),
        ("pageup", "scroll_up", "Subir"),
        ("pagedown", "scroll_down", "Bajar"),
        ("end", "scroll_live", "LIVE"),
        ("escape", "escape_key", "Esc"),
    ]

    def __init__(
        self,
        *,
        mode: Mode,
        verbose: bool,
        run_opts: dict[str, Any],
        output_dir: Path,
    ) -> None:
        super().__init__()
        self.mode = mode
        self.verbose = verbose
        self.run_opts = run_opts
        self.output_dir = output_dir
        self.buffer = LogBuffer()
        stage_order = {
            "run": RUN_STAGES,
            "preprocess": PREPROCESS_STAGES,
            "convert": CONVERT_STAGES,
        }[mode]
        self.stage_tracker = StageTracker(stage_order)
        self.log_filter = LogFilter(stages_on=default_stages_on(stage_order))
        self.stage_names = list(stage_order)
        self.selected_stage = 0
        self.log_scroll = 0
        self.searching = False
        self.running = True
        self.exit_code: int | None = None
        self._last_rendered = -1

    def compose(self) -> ComposeResult:
        yield Static("", id="stages")
        yield Horizontal(
            Vertical(
                RichLog(id="log_view", highlight=False, markup=True, auto_scroll=False),
                id="log_col",
            ),
            id="body",
        )
        yield Input(placeholder="buscar…", id="search_input")
        yield Static("", id="status_bar")

    def on_mount(self) -> None:
        self.query_one("#search_input", Input).display = False
        self._run_job()
        self.set_interval(0.15, self._tick)

    @work(thread=True, exclusive=True)
    def _run_job(self) -> None:
        if self.mode == "run":
            code = run_full_pipeline(self.buffer, verbose=self.verbose, **self.run_opts)
        elif self.mode == "preprocess":
            code = run_preprocess(self.buffer, verbose=self.verbose, **self.run_opts)
        else:
            code = run_convert(self.buffer, verbose=self.verbose, **self.run_opts)
        self.app.call_from_thread(self._post_finished, code)

    def _post_finished(self, code: int) -> None:
        self.running = False
        self.exit_code = code
        if code != 0:
            err_stage = None
            for line in reversed(self.buffer.lines):
                if line.level == UiLogLevel.ERROR:
                    err_stage = line.stage
                    break
            self.stage_tracker.mark_complete(error_stage=err_stage)
        else:
            self.stage_tracker.mark_complete()
        self.post_message(RunFinished(code))

    @on(RunFinished)
    def _on_run_finished(self, _event: RunFinished) -> None:
        self._refresh_all()

    def _tick(self) -> None:
        if not self.running and self._last_rendered == len(self.buffer.lines):
            return
        for line in self.buffer.lines[self._last_rendered :]:
            self.stage_tracker.observe(line)
        self._last_rendered = len(self.buffer.lines)
        self._refresh_all()

    def _visible_lines(self) -> list:
        return filtered_lines(self.buffer.lines, self.log_filter)

    def _refresh_all(self) -> None:
        self._refresh_stages()
        self._refresh_log()
        self._refresh_status()

    def _stage_line(self, name: str) -> str:
        st = self.stage_tracker.status(name)
        on = "✓" if self.log_filter.stages_on.get(name, True) else "·"
        sel = "›" if self.stage_names[self.selected_stage] == name else " "
        sym = {"pending": "○", "running": "◉", "done": "✓", "error": "✗"}[st]
        return f"{sel}{sym}{on} {name}"

    def _refresh_stages(self) -> None:
        parts = [self._stage_line(n) for n in self.stage_names]
        extra = ""
        if self.log_filter.solo_stage:
            extra = f"  | SOLO: {self.log_filter.solo_stage}"
        self.query_one("#stages", Static).update("  ".join(parts) + extra)

    def _refresh_log(self) -> None:
        visible = self._visible_lines()
        log = self.query_one("#log_view", RichLog)
        log.clear()
        rows = max(len(visible) - self.log_scroll, 0)
        start = max(0, len(visible) - rows - 40)
        window = visible[start:]
        for line in window:
            if line.level == UiLogLevel.ERROR:
                log.write(f"[red]{line.raw}[/red]")
            elif line.level == UiLogLevel.WARNING:
                log.write(f"[yellow]{line.raw}[/yellow]")
            else:
                log.write(line.raw)
        if not self.buffer.paused and self.log_scroll == 0:
            log.scroll_end(animate=False)

    def _refresh_status(self) -> None:
        visible = len(self._visible_lines())
        live = "● LIVE" if self.log_scroll == 0 and not self.buffer.paused else f"↑ HISTORY −{self.log_scroll}"
        level = level_filter_label(self.log_filter.level_mode)
        query = f" · «{self.log_filter.query}»" if self.log_filter.query else ""
        run_state = "en curso…" if self.running else f"terminado (código {self.exit_code})"
        artifacts = ""
        if not self.running and self.exit_code == 0:
            names = list_output_artifacts(self.output_dir)
            if names:
                artifacts = " · " + ", ".join(names[:8])
                if len(names) > 8:
                    artifacts += f" (+{len(names) - 8})"
        self.query_one("#status_bar", Static).update(
            f"{run_state} · {visible} líneas · nivel {level}{query} · {live}{artifacts}"
        )

    def action_help(self) -> None:
        self.app.push_screen(HelpOverlay())

    def action_go_home(self) -> None:
        if self.running:
            self.notify("La corrida sigue en curso; q solo al terminar", severity="warning")
            return
        while len(self.app.screen_stack) > 1:
            self.app.pop_screen()

    def action_escape_key(self) -> None:
        if self.searching:
            self.log_filter.query = ""
            self.searching = False
            inp = self.query_one("#search_input", Input)
            inp.value = ""
            inp.display = False
            self._refresh_all()
            return
        if not self.running:
            self.action_go_home()

    def action_cycle_level(self) -> None:
        if self.searching:
            return
        self.log_filter.level_mode = cycle_level_filter(self.log_filter.level_mode)
        self._refresh_all()

    def action_search(self) -> None:
        inp = self.query_one("#search_input", Input)
        inp.display = True
        self.searching = True
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "search_input":
            return
        self.log_filter.query = event.value.strip()
        self.searching = False
        event.input.display = False
        self._refresh_all()

    def on_key(self, event) -> None:
        if self.searching and event.key == "escape":
            self.log_filter.query = ""
            self.searching = False
            inp = self.query_one("#search_input", Input)
            inp.value = ""
            inp.display = False
            self._refresh_all()
            event.prevent_default()
            event.stop()

    def action_stage_up(self) -> None:
        if self.selected_stage > 0:
            self.selected_stage -= 1
            self._refresh_stages()

    def action_stage_down(self) -> None:
        if self.selected_stage < len(self.stage_names) - 1:
            self.selected_stage += 1
            self._refresh_stages()

    def action_toggle_stage(self) -> None:
        name = self.stage_names[self.selected_stage]
        cur = self.log_filter.stages_on.get(name, True)
        self.log_filter.stages_on[name] = not cur
        self._refresh_all()

    def action_toggle_all_stages(self) -> None:
        any_off = any(not v for v in self.log_filter.stages_on.values())
        for name in self.stage_names:
            self.log_filter.stages_on[name] = any_off
        self._refresh_all()

    def action_solo_stage(self) -> None:
        name = self.stage_names[self.selected_stage]
        if self.log_filter.solo_stage == name:
            self.log_filter.solo_stage = None
        else:
            self.log_filter.solo_stage = name
        self._refresh_all()

    def action_scroll_up(self) -> None:
        self.buffer.pause()
        self.log_scroll += 5
        self._refresh_all()

    def action_scroll_down(self) -> None:
        self.log_scroll = max(0, self.log_scroll - 5)
        if self.log_scroll == 0:
            self.buffer.resume()
        self._refresh_all()

    def action_scroll_live(self) -> None:
        self.log_scroll = 0
        self.buffer.resume()
        self._refresh_all()