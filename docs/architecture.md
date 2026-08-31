# Arquitectura — xfrm-watch

## Flujo

```
/proc/net/xfrm_stat  ──►  load_snapshot()  ──►  Snapshot{ts, counters[28]}
                                                   │
                        ┌──────────────────────────┼──────────────────────────┐
                        ▼                          ▼                          ▼
                 render_snapshot()          render_delta()             render_json()
                 (tabla + histograma)       (watch: solo cambios)     (summary + counters)
```

## Estructura de datos

- `Counter { name, value }` — un contador XFRM; `dir()` deriva la dirección
  del prefijo del nombre (`XfrmIn`/`XfrmOut`/`XfrmFwd`/`XfrmAcq`).
- `Snapshot` — vector de 28 contadores + agregados (`dir_total`, `total`,
  `nonzero_count`) y lookup por nombre (`find`) para los deltas del watch.
- `Filters { dir, key, nonzero, top }` — los 4 criterios de filtrado,
  evaluados por `passes()` sobre cada contador.

## Parsing

Cada línea del fichero: `Nombre<sep>valor<newline>` donde `<sep>` es
tab o 2+ espacios. El parser tolera:

- comentarios `#` hasta fin de línea (dumps anotados),
- filas malformadas (se saltan),
- espacios en blanco alrededor del nombre (dumps editados a mano),
- CR de Windows.

El valor se parsea con `std::from_chars` tras recortar espacios/tabs
iniciales (from_chars NO salta whitespace — pitfall conocido).

## Renderizado

- Histograma: 0 → `.`, 1-999 → `#` azul, 1K-999K → `##` amarillo,
  ≥1M → `###` rojo.
- Tags semánticos solo para los contadores informativos (`state-lookup`,
  `policy-block`, `replay`, `expired`, `acquire`).
- Paleta ANSI **mutable** global — `--no-color` la vacía de verdad
  (verificado en selftest: 0 códigos `\x1b[` en la salida).

## Decisiones

- **C++23 stdlib-only**: cero dependencias externas; compilación directa
  con g++ (patrón estándar de la serie de watchers /proc).
- **`std::println` con format string literal**: la paleta mutable se pasa
  como argumento (`{}`), nunca concatenada en el format string
  (consteval requirement).
- **Demo vs real**: `--demo` genera un gateway VPN sintético con 19
  contadores no-cero para que la herramienta muestre su valor en un host
  sin tráfico IPsec; `--file` permite reproducir dumps anotados.