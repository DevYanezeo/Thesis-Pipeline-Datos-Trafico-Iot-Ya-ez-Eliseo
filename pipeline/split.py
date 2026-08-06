"""Split train/test sin fuga de datos.

Dos perillas, con impacto muy distinto:

- Proporcion (``test_size``): 0.2 = 80/20, 0.3 = 70/30. Impacto bajo.
- Unidad (``split_by``): decide si hay o no fuga. Impacto alto.

    - ``episode``  (default): agrupa por ``event_id`` para que los flujos de un mismo
      ataque/episodio no se repartan entre train y test (fuga tipica en trafico de red).
      El trafico ``background`` no pertenece a ningun episodio, asi que cada flujo se trata
      como grupo propio y puede repartirse libremente.
    - ``temporal`` : primeros (1-test_size) por tiempo = train; el resto = test.
    - ``flow``     : split aleatorio por flujo. Solo diagnostico/comparacion; NO recomendado
      porque reparte episodios y produce metricas optimistas.

La estratificacion (por defecto activa) preserva la proporcion de clases y protege a las
minoritarias (``benign`` es escaso). Con ``episode`` se usa ``StratifiedGroupKFold`` para
combinar agrupacion + estratificacion.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    GroupShuffleSplit,
    StratifiedGroupKFold,
    train_test_split,
)

from pipeline.dataset_spec import FLOW_ID_COL, GROUP_COL, TIME_COL

SPLIT_MODES = ("episode", "temporal", "flow")

_EMPTY_GROUP_TOKENS = {"", "nan", "none", "null"}


def _build_group_keys(df: pd.DataFrame) -> np.ndarray:
    """Clave de grupo por fila: ``event_id`` si existe, o un grupo unico por flujo background."""
    n = len(df)
    if GROUP_COL in df.columns:
        events = df[GROUP_COL].astype(str).to_numpy()
    else:
        events = np.array([""] * n)

    if FLOW_ID_COL in df.columns:
        flow_ids = df[FLOW_ID_COL].astype(str).to_numpy()
    else:
        flow_ids = np.array([str(i) for i in range(n)])

    keys = np.empty(n, dtype=object)
    for i in range(n):
        ev = events[i]
        if ev.strip().lower() in _EMPTY_GROUP_TOKENS:
            keys[i] = f"__bg__{flow_ids[i]}"
        else:
            keys[i] = f"__ev__{ev}"
    return keys


def _temporal_split(df: pd.DataFrame, test_size: float) -> tuple[np.ndarray, np.ndarray]:
    if TIME_COL not in df.columns:
        raise ValueError(
            f"split_by='temporal' requiere la columna '{TIME_COL}' en el dataset"
        )
    ts = pd.to_numeric(df[TIME_COL], errors="coerce").to_numpy()
    # NaN al final para que no contaminen el train temprano.
    order = np.argsort(np.where(np.isnan(ts), np.inf, ts), kind="stable")
    cut = int(round(len(order) * (1.0 - test_size)))
    cut = max(1, min(cut, len(order) - 1))
    return order[:cut], order[cut:]


def _stratified_group_split(
    y: np.ndarray,
    groups: np.ndarray,
    test_size: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    n_splits = max(2, round(1.0 / test_size))
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    train_idx, test_idx = next(sgkf.split(np.zeros(len(y)), y, groups))
    return train_idx, test_idx


def _group_shuffle_split(
    y: np.ndarray,
    groups: np.ndarray,
    test_size: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(gss.split(np.zeros(len(y)), y, groups))
    return train_idx, test_idx


def _split_meta(
    y: pd.Series,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    groups: np.ndarray | None,
    *,
    split_by: str,
    test_size: float,
    stratify: bool,
    seed: int,
) -> dict:
    y_arr = pd.Series(np.asarray(y))
    train_counts = y_arr.iloc[train_idx].value_counts().to_dict()
    test_counts = y_arr.iloc[test_idx].value_counts().to_dict()
    total = len(train_idx) + len(test_idx)

    warnings: list[str] = []
    for cls in y_arr.unique():
        if int(test_counts.get(cls, 0)) == 0:
            warnings.append(f"clase '{cls}' sin muestras en test")
        if int(train_counts.get(cls, 0)) == 0:
            warnings.append(f"clase '{cls}' sin muestras en train")

    meta = {
        "split_by": split_by,
        "test_size_requested": test_size,
        "achieved_test_fraction": round(len(test_idx) / total, 4) if total else 0.0,
        "stratify": stratify,
        "seed": seed,
        "n_train": int(len(train_idx)),
        "n_test": int(len(test_idx)),
        "train_class_counts": {str(k): int(v) for k, v in train_counts.items()},
        "test_class_counts": {str(k): int(v) for k, v in test_counts.items()},
        "warnings": warnings,
    }
    if groups is not None:
        train_groups = set(groups[train_idx].tolist())
        test_groups = set(groups[test_idx].tolist())
        meta["n_groups"] = int(len(set(groups.tolist())))
        meta["group_overlap"] = int(len(train_groups & test_groups))
    return meta


def split_dataset(
    df: pd.DataFrame,
    y: pd.Series,
    *,
    test_size: float = 0.2,
    split_by: str = "episode",
    stratify: bool = True,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Divide ``df`` en (train, test) segun la unidad indicada, devolviendo metadatos.

    ``y`` es el target ya resuelto (mismo largo/orden que ``df``) y se usa para
    estratificar y para reportar la distribucion de clases.
    """
    if split_by not in SPLIT_MODES:
        raise ValueError(f"split_by invalido: {split_by!r}. Use uno de {SPLIT_MODES}")
    if not 0.0 < test_size < 1.0:
        raise ValueError(f"test_size debe estar en (0,1); recibido {test_size}")
    if len(df) != len(y):
        raise ValueError("df e y deben tener el mismo largo")
    if len(df) < 2:
        raise ValueError("Se requieren al menos 2 flujos para dividir")

    y_arr = np.asarray(y)
    groups: np.ndarray | None = None

    if split_by == "temporal":
        train_idx, test_idx = _temporal_split(df, test_size)
    elif split_by == "flow":
        strat = y_arr if stratify else None
        train_idx, test_idx = train_test_split(
            np.arange(len(df)),
            test_size=test_size,
            random_state=seed,
            stratify=strat,
        )
    else:  # episode
        groups = _build_group_keys(df)
        if stratify:
            train_idx, test_idx = _stratified_group_split(y_arr, groups, test_size, seed)
        else:
            train_idx, test_idx = _group_shuffle_split(y_arr, groups, test_size, seed)

    train_idx = np.asarray(train_idx)
    test_idx = np.asarray(test_idx)

    train = df.iloc[train_idx].reset_index(drop=True)
    test = df.iloc[test_idx].reset_index(drop=True)
    meta = _split_meta(
        y,
        train_idx,
        test_idx,
        groups,
        split_by=split_by,
        test_size=test_size,
        stratify=stratify,
        seed=seed,
    )
    return train, test, meta
