# xfrm-watch

Monitor de estadísticas **XFRM (IPsec) del kernel Linux** en C++23, zero deps.

Lee `/proc/net/xfrm_stat` (exportado por `net/xfrm/xfrm_proc.c`, función
`xfrm_statistics_seq_show`) y muestra los **28 contadores** del subsistema
XFRM: errores de entrada/salida, fallos de lookup de SA, bloqueos de política,
antireplay, expiración de SAs y más — clasificados por dirección
(`in` / `out` / `fwd` / `acq`) con histograma de severidad.

## Features

- **Fuente única**: `/proc/net/xfrm_stat` — los 28 contadores `Xfrm*` del kernel
- **Clasificación por dirección**: `in` (14), `out` (12), `fwd` (1), `acq` (1)
- **Semántica de contadores**: tags well-known — `state-lookup` (SA no
  encontrada), `policy-lookup`, `policy-block`, `replay` (antireplay),
  `expired` (lifetime), `acquire`
- **Histograma de severidad**: `#` por magnitud — verde/azul/amarillo/rojo
  según el valor (rojo ≥ 1M, amarillo ≥ 1K, azul > 0)
- **Resumen agregado**: total, totales por dirección y contadores no-cero
- **Modo watch (`--watch N`)**: refresh periódico con deltas
  (+/- por contador que cambió) y flush por frame en pipes
- **Salida JSON (`--json`)**: `summary` + array `counters` validable con
  `python -m json.tool`
- **Demo mode (`--demo`)**: gateway VPN sintético ocupado con 19 contadores
  no-cero (4217 SAs no encontradas inbound, 1340 sin política, replay 187…)
- **Filtros**: `--dir` (in|out|fwd|acq), `--key PREFIX` (p.ej. `XfrmIn`),
  `--nonzero`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#`, blancos y filas basura)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 36 checks (clasificación, parser, `--file` del workflow real,
  demo, filtros, JSON, `--no-color`, watch/deltas, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o xfrm-watch
```

## Usage

```bash
# Snapshot único (host real)
./xfrm-watch

# Solo contadores con valor > 0
./xfrm-watch --nonzero

# Solo inbound
./xfrm-watch --dir in

# Solo contadores cuyo nombre empiece por XfrmIn
./xfrm-watch --key XfrmIn

# Modo watch (cada 2s) con deltas
./xfrm-watch --watch 2

# JSON
./xfrm-watch --json

# Demo (gateway VPN sintético)
./xfrm-watch --demo

# Parsear un dump con comentarios
./xfrm-watch --file sample-xfrm.table --no-color

# Sin colores
./xfrm-watch --no-color

# Auto-tests
./xfrm-watch --selftest
```

## Formato de `/proc/net/xfrm_stat`

```
XfrmInError           	0
XfrmInBufferError     	0
...
XfrmAcquireError      	0
```

Cada línea: `Nombre<espacios/tab>valor`. Los contadores son
`LINUX_MIB_XFRM*` (enum `snmp_xfrm` en `include/uapi/linux/xfrm.h`, 28
entradas) y se incrementan desde `net/xfrm/xfrm_input.c`,
`net/xfrm/xfrm_output.c`, `net/xfrm/xfrm_policy.c` y `xfrm_state.c`.

## Selftest

```bash
./xfrm-watch --selftest
# selftest: 36 passed, 0 failed
```