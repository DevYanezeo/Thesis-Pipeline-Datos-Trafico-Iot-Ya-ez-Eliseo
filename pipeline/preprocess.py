"""Preprocesamiento ML sin fuga de datos (handoff procesado).

Regla de oro (taller "Del Papel al Pipeline"): el ``ColumnTransformer`` se AJUSTA
exclusivamente con el train (``fit_transform(train)``) y el test solo se ``transform``.
Asi ninguna estadistica (mediana de imputacion, mediana/IQR del scaler, categorias del
One-Hot) se contamina con informacion del test.

Produce el paquete que consume el tesista de IDS:
    - ``train_processed.parquet`` / ``test_processed.parquet``
    - ``preprocessing_pipeline.joblib`` (el transformador ajustado, reutilizable)
    - ``feature_manifest.json`` (esquema, exclusiones, parametros -> trazabilidad)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler, StandardScaler

from pipeline import __version__
from pipeline.dataset_spec import (
    LABEL_COL,
    SPEC_VERSION,
    resolve_feature_columns,
    resolve_target,
    spec_summary,
)
from pipeline.split import split_dataset

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False

SCALERS = ("robust", "standard")


@dataclass
class PreprocessResult:
    train_processed: pd.DataFrame
    test_processed: pd.DataFrame
    pipeline: ColumnTransformer
    feature_manifest: dict
    split_meta: dict
    numerical_cols: list[str] = field(default_factory=list)
    categorical_cols: list[str] = field(default_factory=list)
    feature_names_out: list[str] = field(default_factory=list)


def _make_scaler(scaler: str):
    if scaler == "robust":
        # Robusto a outliers (features de red con colas pesadas: bytes, PIAT, ps).
        return RobustScaler()
    if scaler == "standard":
        return StandardScaler()
    raise ValueError(f"scaler invalido: {scaler!r}. Use uno de {SCALERS}")


def build_preprocessor(
    numerical: list[str],
    categorical: list[str],
    *,
    scaler: str = "robust",
) -> ColumnTransformer:
    """ColumnTransformer con imputacion + escalado (numericas) y One-Hot (categoricas)."""
    transformers = []
    if numerical:
        transformers.append((
            "num",
            Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", _make_scaler(scaler)),
            ]),
            numerical,
        ))
    if categorical:
        transformers.append((
            "cat",
            Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("ohe", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
            ]),
            categorical,
        ))
    if not transformers:
        raise ValueError("No hay columnas de features utilizables en el dataset")
    return ColumnTransformer(transformers=transformers, remainder="drop")


def _to_frame(matrix, columns: list[str], target: pd.Series) -> pd.DataFrame:
    df = pd.DataFrame(matrix, columns=columns)
    df[LABEL_COL] = pd.Series(target).to_numpy()
    return df


def preprocess_dataset(
    df: pd.DataFrame,
    *,
    test_size: float = 0.2,
    split_by: str = "episode",
    stratify: bool = True,
    seed: int = 42,
    classes: str = "three-class",
    scaler: str = "robust",
    source: str | None = None,
) -> PreprocessResult:
    """Orquesta target -> split (sin fuga) -> fit-solo-train -> transform test."""
    if scaler not in SCALERS:
        raise ValueError(f"scaler invalido: {scaler!r}. Use uno de {SCALERS}")

    filtered, y, class_names = resolve_target(df, classes)
    numerical, categorical = resolve_feature_columns(filtered)

    train_df, test_df, split_meta = split_dataset(
        filtered,
        y,
        test_size=test_size,
        split_by=split_by,
        stratify=stratify,
        seed=seed,
    )

    # Reconstruimos el target por particion re-resolviendolo sobre cada frame (robusto
    # a cualquier reordenamiento interno del split y coherente con el modo de clases).
    _, y_train, _ = resolve_target(train_df, classes)
    _, y_test, _ = resolve_target(test_df, classes)

    ct = build_preprocessor(numerical, categorical, scaler=scaler)
    x_train = ct.fit_transform(train_df)   # <-- fit SOLO en train
    x_test = ct.transform(test_df)          # <-- test solo transform

    feature_names_out = [str(c) for c in ct.get_feature_names_out()]
    train_processed = _to_frame(x_train, feature_names_out, y_train)
    test_processed = _to_frame(x_test, feature_names_out, y_test)

    feature_manifest = {
        "pipeline_version": __version__,
        "spec_version": SPEC_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "classes_mode": classes,
        "class_names": class_names,
        "scaler": scaler,
        "split": split_meta,
        "schema": spec_summary(numerical, categorical),
        "feature_names_out": feature_names_out,
        "n_features_out": len(feature_names_out),
    }

    return PreprocessResult(
        train_processed=train_processed,
        test_processed=test_processed,
        pipeline=ct,
        feature_manifest=feature_manifest,
        split_meta=split_meta,
        numerical_cols=numerical,
        categorical_cols=categorical,
        feature_names_out=feature_names_out,
    )


def _write_parquet(df: pd.DataFrame, path: Path) -> None:
    if HAS_POLARS:
        pl.from_pandas(df).write_parquet(path, compression="snappy")
    else:
        df.to_parquet(path, index=False, compression="snappy")


def write_outputs(result: PreprocessResult, output_dir: str | Path) -> dict[str, Path]:
    """Escribe el paquete handoff en disco y devuelve las rutas."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {
        "train": out / "train_processed.parquet",
        "test": out / "test_processed.parquet",
        "pipeline": out / "preprocessing_pipeline.joblib",
        "feature_manifest": out / "feature_manifest.json",
    }

    _write_parquet(result.train_processed, paths["train"])
    _write_parquet(result.test_processed, paths["test"])
    joblib.dump(result.pipeline, paths["pipeline"])
    paths["feature_manifest"].write_text(
        json.dumps(result.feature_manifest, indent=2),
        encoding="utf-8",
    )
    return paths
