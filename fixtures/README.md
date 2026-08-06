# Fixtures

| Directorio | Contenido versionado | Uso |
|------------|----------------------|-----|
| `upstream-run-00/` | `metadata.json` | Contrato de ejemplo (corrida piloto). Colocar `capture.pcap` localmente. |
| `upstream-run-01/` | `metadata.json` | Fixture de esquema / adaptador (tests). |

Los archivos `.pcap` **no** se versionan (tamaño). Copiar capturas locales a:

```text
fixtures/upstream-run-00/capture.pcap
```

antes de una corrida end-to-end.
