# vision/ — the package

Everything Vision is. No runtime dependencies outside the standard library.

| Folder | What lives here |
| :-- | :-- |
| `core/` | The engine: scanning stages, scope enforcement, safety, state, the interactive console |
| `analysis/` | Everything that *reasons about* findings after they exist — correlation, frameworks, remediation, exploit advisory |
| `report/` | Turning findings into a deliverable |
| `tools/` | Standalone converters usable outside the pipeline |

The split is deliberate: `core/` produces findings, `analysis/` interprets them,
`report/` presents them. A change to how something is *found* belongs in `core/`;
a change to what a finding *means* belongs in `analysis/`.
