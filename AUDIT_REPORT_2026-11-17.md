# Auditoría de seguridad — Vyper (lenguaje y toolchain completo)

**Fecha:** 2026-11-17 · **Rama:** `arena/c1595629-vyper` · **Commit auditado (master):** `098bf610c4f1e0136a61b2ec8327279bb6ff3814` (single squashed commit) · **Producción de referencia:** **v0.4.3** (stable, 2025-06-18, "Buttermilk Racer", commit `1794918494`)

---

## 1. Veredicto

**SÍ hay crítico en el lenguaje**: **GHSA-cw3h-xwxq-8cx2** (ternario que mezcla arrays anidados con cotas internas distintas) está **sin parchear en la versión de producción v0.4.3** y produce **corrupción silenciosa de valores y de longitudes** de arrays almacenados, lo que **permite a un atacante sin privilegios retirar más valor del que depositó a costa de otros usuarios** de un contrato que use el patrón (PoC end-to-end con drenaje real más abajo: paga 2 ETH, cobra 4 ETH).

Los otros cinco advisories públicos de octubre-2026 también están presentes en v0.4.3 y verificados aquí; ninguno alcanza por sí solo los 4 criterios de criticidad (detalle en §5). **No se ha encontrado ningún fallo nuevo no publicado** tras revisión de código y campañas diferenciales (§6).

---

## 2. Registro de auditoría (REQUISITO PREVIO: clones, sin RPC)

### 2.1 Repos clonados (todos los de la organización vyperlang accesibles)

| Repo | Commit / estado |
|---|---|
| `vyperlang/vyper` | target `098bf61` (rama `arena/c1595629-vyper`, master); **un único commit squash** → no hay merge-base para `1fb7dfe2` |
| `vyperlang/titanoboa` | `4094da1` — usado como EVM de ejecución local |
| `vyperlang/vvm` | clonado (contexto de versiones) |
| `vyperlang/vyper-builds` | clonado (builds por release) |
| `vyperlang/gaboon`, `mamushi`, `vyper-lsp`, `yul2venom`, `vyupgrade`, `audits` | clonados (contexto/fallback) |
| `snekmate` (pcaversaccio) | `601f0738` — framework "OpenZeppelin de Vyper" (fallback del brief) |
| v0.4.3 release | tarball codeload desempaquetado en `/home/user/repos/vyper-v0.4.3` |
| Advisory dump | `/home/user/repos/advisories.json` (endpoint repo-scoped) |

**Repos privados/bloqueados:** ninguno de los solicitados resultó inaccesible; no se listan bloqueos.

### 2.2 Versión/flag/target de producción (ground truth leída del repo)

- **Última estable = v0.4.3** (GitHub releases). No existe v0.4.4+; v0.5.0b2 es beta (2026-11-06). → **producción = v0.4.3**.
- **Optimización por defecto = `-O gas`** (`OptimizationLevel.GAS`); `-O codesize`; `-O none` solo explícito. `_OPT_GAS_LEVELS = (GAS, O2, O3)`.
- **Codegen por defecto = legacy**; `--experimental-codegen` (Venom) es opt-in → los fallos solo-Venom quedan **fuera** de producción.
- **`DEFAULT_EVM_VERSION = PRAGUE`**; `DEFAULT_ENABLE_DECIMALS = False`.
- Backends: EVM Cancun/Prague (transient storage en ≥ Cancun para el key de `@nonreentrant`).

### 2.3 Montaje local

- `/home/user/repos/venv_master` → **master `0.1+commit.098bf61`** (editable, `--no-deps`) + titanoboa 0.2.8 editable.
- `/home/user/repos/venv403` → deps de v0.4.3; compilador vía
  `PYTHONPATH=/home/user/repos/vyper-v0.4.3 /home/user/repos/venv403/bin/python -m vyper …`
  (el binario `venv403/bin/vyper` está roto: wheel parcial; **no usarlo**).

### 2.4 Ficheros inspeccionados (lectura dirigida a semántica de valor)

`vyper/ir/optimizer.py` (completo), `vyper/codegen/{expr,core,stmt,arithmetic,_convert,events,self_call,external_call,return_,abi_encoder,memory_allocator,ir_node}.py`, `vyper/semantics/analysis/{constant_folding,local,data_positions}.py`, `vyper/semantics/types/{primitives,subscriptable,base}.py`, `vyper/builtins/functions.py`, `vyper/builtins/stdlib/math.vy`, `vyper/abi_types.py`, `vyper/ast/parse.py`, `vyper/evm/{opcodes,address_space}.py`, `vyper/ir/compile_ir.py`, y el árbol Venom completo (`passes/*`, `analysis/*`, `sccp/eval.py`). Diff íntegro v0.4.3 ↔ master: `/home/user/repos/diff_403_vs_master.txt` (117 ficheros `.py/.vy`).

### 2.5 Pruebas y PoCs ejecutados (comandos reproducibles)

Todos en `/home/user/repos/pocs/`; runner único: `venv_master/bin/python evidence.py`.

| # | Qué | Resultado |
|---|---|---|
| 1 | `fuzzer2.py 0..32` (arith+ternarios, int128/uint256, 4 configs) | 0 divergencias |
| 2 | `fuzzer3.py 0..120` (ABI round-trip de tipos anidados, 6 configs: 403/master × none/gas/codesize/venom) | 0 divergencias |
| 3 | `arith_oracle.py` (91 vectores límite en 6 configs) | 0 divergencias |
| 4 | `semantic_oracle.py` (95 vectores vs modelo Python, **v0.4.3 -O gas**) | 0 divergencias reales (3 "mismatches" eran expectativas mías erróneas sobre `unsafe_*`) |
| 5 | `evidence.py` §1–§6 | ver §3–§5 |

---

## 3. CRÍTICO — GHSA-cw3h-xwxq-8cx2 en producción v0.4.3

### 3.1 Localización exacta

- **Repo/commit:** `vyperlang/vyper` **v0.4.3** (`1794918494`; tarball `/home/user/repos/vyper-v0.4.3`). Corregido solo en master por `1fb7dfe2` (#5236) — **v0.4.3 no lo contiene**.
- **Fichero:** `vyper/codegen/expr.py`
- **Función:** `Expr.parse_IfExp` — **líneas 781–802**; el defecto está en **785–786** (se toman los `ir_node` de ambas ramas **sin convertirlas al tipo resultado**) y en **801–802** (se etiqueta el `if` con `typ = self.expr._metadata["type"]`, es decir el tipo *ancho*, y `location = body.location`).
- **Consumidor del layout:** `vyper/codegen/core.py::_dynarray_make_setter` (287) y `make_setter` (1047) → `_get_element_ptr_array` (639) calcula el *stride* con `index_type.storage/memory size` del **tipo resultado**, no del tipo real de la rama.

Código vulnerable (v0.4.3):

```python
def parse_IfExp(self):
    test = Expr.parse_value_expr(self.expr.test, self.context)
    body = Expr(self.expr.body, self.context).ir_node      # 785  <- tipo DynArray[DynArray[uint256,2],4]
    orelse = Expr(self.expr.orelse, self.context).ir_node  # 786
    if body.location != orelse.location or body.value == "multi":
        body = ensure_in_memory(body, self.context)
        orelse = ensure_in_memory(orelse, self.context)
    typ = self.expr._metadata["type"]                      # 800  <- DynArray[DynArray[uint256,4],4]
    location = body.location
    return IRnode.from_list(["if", test, body, orelse], typ=typ, location=location)  # 802
```

### 3.2 Por qué falla (validación ausente / no sound)

1. El type-checker **permite** el ternario entre `DynArray[DynArray[uint256,2],4]` y `DynArray[DynArray[uint256,4],4]` (es un *widening* documentado y considerado seguro; con `SArray` interno lo rechaza, con contenedores dinámicos lo acepta).
2. `parse_IfExp` devuelve un **puntero a la rama tal cual**, pero **etiquetado con el tipo resultado**. Las ramas se quedaron con **su** layout: cada fila de la rama estrecha ocupa `32 + 2*32 = 96` bytes; el tipo resultado asume `32 + 4*32 = 160`.
3. Al leer/escribir después con el tipo resultado (`make_setter`/`_dynarray_make_setter`/`_get_element_ptr_array`), el *stride* es 160 en vez de 96 → **a partir de la segunda fila todo está desplazado 64 bytes**.
4. Consecuencia: la *longitud* de la fila `i>0` se lee del **valor** `narrow[i][1]` (atacante-controlado, sin clamp porque el setter de primitivas confía en el encoding interno) y los **valores** de esa fila se leen de la fila siguiente del propio array del atacante → **datos controlados por el atacante entran en el almacenamiento del contrato**.
5. Defensas que **no** lo frenan: `needs_clamp` no aplica (el tipo nominal es `uint256`); `potential_overlap` no dispara; `-O none` **también** corrompe (no es un bug del optimizador); el type-checker no emite aviso.

### 3.3 Condiciones de configuración

- **Compilador:** Vyper **0.3.8 … 0.5.0b1** (v0.4.3 = producción). **Flags:** todos (`-O none`, `-O gas` (default), `-O codesize`); también en Venom.
- **Target/backend:** EVM legacy codegen, cualquier EVM ≥ Shanghai (probetas en Prague).
- **Patrón que lo dispara (mínimo):** un ternario cuyo resultado se asigna a storage/memoria o se retorna, donde una rama tiene cotas internas **más pequeñas** que el tipo resultado, y las filas internas son `DynArray`/`Bytes` (contenedores dinámicos). Ej.: `self.x = narrow if flag else wide`.
- No requiere roles, ni flags raras, ni backend no-productivo. **Cualquier usuario** puede llamar la función pública y elegir `flag=True` + el contenido de `narrow`.

### 3.4 PoC de corrupción (mínimo, exacto)

`/home/user/repos/pocs/cw3h3.vy`:

```vyper
remaining: public(DynArray[DynArray[uint256, 4], 4])

@external
def set(flag: bool, narrow: DynArray[DynArray[uint256, 2], 4], wide: DynArray[DynArray[uint256, 4], 4]):
    self.remaining = narrow if flag else wide
```

Compilación y ejecución:
```
PYTHONPATH=/home/user/repos/vyper-v0.4.3 /home/user/repos/venv403/bin/python -m vyper -f combined_json -O gas cw3h3.vy
# deploy en titanoboa; set(True, [[6,4],[7,3]], [])
```
Resultado observado (`evidence.py` §3, ABI `set(bool,uint256[][],uint256[][])`):

```
v0.4.3          -O none   remaining = [[6, 4, OOB, OOB], [0, 0, 0, OOB]]   <- CORRUPTO
v0.4.3          -O gas    remaining = [[6, 4, OOB, OOB], [0, 0, 0, OOB]]   <- CORRUPTO
master (fixed)  -O none   remaining = [[6, 4, OOB, OOB], [7, 3, OOB, OOB]]
master (fixed)  -O gas    remaining = [[6, 4, OOB, OOB], [7, 3, OOB, OOB]]
```
Entrada `[[6,4],[7,3]]` → almacenado `[[6,4],[0,0,0]]` (la fila 1 se leyó con stride 160 y su "longitud" salió de `narrow[1][1]=3`).

### 3.5 PoC de ROBO (X in → Y > X out, a costa de terceros)

`/home/user/repos/pocs/cw3h_vault2.vy` — vault pro-rata ordinario:
`deposit()` cobra **1 unidad de precio por elemento declarado** (contado sobre el calldata, exacto) y guarda el array con el ternario; `withdraw()` quema el **número de elementos que el contrato cree tener** (`units_of`) y paga `balance * s / total_units`.

Ejecución (`evidence.py` §4, v0.4.3 default `-O gas`, víctima deposita 12 ETH):

```
v0.4.3          attacker paid= 2  vault believed= 4  payout=4.00 ETH  pool_left=10.00 ETH
v0.4.3          attacker paid= 4  vault believed= 6  payout=6.00 ETH  pool_left=10.00 ETH
master (fixed)  attacker paid= 2  vault believed= 2  payout=2.00 ETH  pool_left=12.00 ETH
master (fixed)  attacker paid= 4  vault believed= 4  payout=4.00 ETH  pool_left=12.00 ETH
```

- **Atacante:** llama `deposit(True, [[], [0,4]], [])` pagando **2 ETH** por 2 elementos reales.
- **Contrato cree** que tiene 4 elementos (la fila 1 lee longitud de `narrow[1][1]=4`), y `withdraw()` le paga **4 ETH**.
- **Beneficio neto = +2 ETH**; el pool baja de 12 → 10 ETH: **pérdida de la víctima**. En master el mismo ataque paga y cobra exactamente lo mismo (sin beneficio).
- **Generalización:** el beneficio máximo medido con esta forma es **2×** lo depositado (barrido exhaustivo de `{0,1,2,3,4,6}²` para 2 filas y `{0,2,4}³` para 3 filas: máximo `believed - paid = 2`). Es repetible por bucle y por múltiples cuentas; el límite práctico es el TVL del pool, por lo que el daño es **drenaje completo del pool** (en el PoC, todo el pool queda retirable por el atacante en el límite: `2×` sobre su capital permite absorber todo el ETH de la víctima cuando `2*atacante ≥ víctima`).
- La variante con memoria contigua (`wide`) permitió además **inyectar valores de 2·10^200** en filas corruptas, confirmando que el contenido del almacenamiento no está limitado al input legítimo (`/tmp/mat3.vy`, `narrow=[[1,2],[3,3],[10^40,10^40]]` → fila 1 leída como `[2, 10^40, 10^40]`).

### 3.6 Impacto (clases de contrato)

Contratos compilados con v0.4.3 (o 0.3.8–0.5.0b1) que **guarden o devuelvan** un ternario entre arrays anidados con cotas internas distintas: vaults de depósitos, pools, staking con posiciones por usuario, escrows, registros de lotes/órdenes, NFTs con arrays de atributos. El resultado es **valores y longitudes corrompidos de forma controlable por el llamante** → inflación de saldo/shares, elusión de límites, o **congelación** (si la longitud leída excede la cota, cualquier lectura hace revert y los fondos quedan bloqueados: se observó revert con `len=5`). Ambos efectos son **irreversibles** para la contabilidad almacenada.

---

## 4. Comprobaciones que NO dieron crítico (descartadas con evidencia)

| Advisory (v0.4.3) | Verificado | Por qué no es crítico |
|---|---|---|
| **GHSA-6j9c** (optimizer `msg.value\|K` → 1 en ternario) | IR + runtime en 0.4.3: `-O gas` da `f(True)=1` para value 0/1/4/100; `-O none` da 2/3/6/102 | Necesita que el **contrato** use `(msg.value \| K)` como rama de un ternario — patrón de contrato, no idiom documentado; corrompe valores pero no hay primitiva genérica de robo. **Medio**, no crítico por el criterio (1)+(4): el defecto es del compilador pero el daño exige un contrato que ya escribe ese patrón. |
| **GHSA-2489** (captura de constantes/defaults importados) | Runtime 0.4.3: `test(300) → (300,300)` (esperado `(0,0)`); también con `2^256-1` | Requiere **colisión de nombres entre módulos** escrita por el desarrollador; el atacante solo controla el valor cuando ese nombre ya es un parámetro público. No es permissionless genérico. |
| **GHSA-fxg7** (`create_from_blueprint` wraparound) | Runtime 0.4.3: `code_offset=2^256-1` **despliega contrato con runtime 0 bytes** en vez de revertir | El atacante debe **controlar `code_offset`**; el patrón común (`code_offset=3`) no se ve afectado. Impacto = DoS/local, no robo directo. **Bajo**. |
| **GHSA-r3c7 / GHSA-wvx7** (desplazamiento de literales por identificadores multibyte / separadores) | v0.4.3: `matches-substituted=True, differs-from-clean=True` en ambos | Requiere **capacidad de contribuir código fuente** al contrato víctima (supply-chain). No permissionless *on-chain*. **Bajos**. |
| `create_from_blueprint` empty-target check | Leído `functions.py` 1897–1935 | `sge(codesize,1)` es correcto y solo falla por wraparound (ya cubierto). |

---

## 5. Criterios de criticidad aplicados a GHSA-cw3h

1. **Bug concreto en el lenguaje/toolchain de producción:** sí — `parse_IfExp` (v0.4.3, expr.py 781–802) entrega punteros con layout incoherente con el tipo declarado; miscompilación determinista, reproducible en `-O none`.
2. **Permissionless:** sí — el ternario es sintaxis documentada; cualquier usuario llama la función pública y elige la rama estrecha y su contenido. No hay rol ni configuración especial (solo compilar con la estable).
3. **Call-graph y config reales:** sí — contrato público ordinario, compilado con v0.4.3 **default** (`-O gas`, legacy codegen, Prague); el patrón respeta tipos válidos, clamps y cotas del lenguaje.
4. **PoC local / matemática exacta:** sí — contratos mínimos + comando exacto de compilación + versión + flags + ejecución en EVM local mostrando **2 ETH in → 4 ETH out** a costa del pool/víctima, y corrupción de contabilidad contable (`believed=4` con `paid=2`).

Ninguna prohibición del brief aplica: no es UB teórico, no depende de flags no usadas, no es dust, no es self-grief, no está limitado por rol, no es DoS temporal (el robo es permanente).

---

## 6. Campañas diferenciales (búsqueda de fallos NO publicados)

- **`fuzzer2.py`**: expresiones aritméticas/bit a bit + ternarios, `int128`/`uint256`, 4 configuraciones (403/master × none/gas/codesize/venom). 32 semillas × 24 llamadas → **0 divergencias**.
- **`fuzzer3.py`**: round-trip ABI de tipos anidados generados aleatoriamente (DynArray, SArray, Bytes, structs, tuplas; hasta 3 niveles), por 3 rutas (`return`, memoria, ternario), 6 configuraciones. 120 semillas × ~5 vectores → **0 divergencias**.
- **`arith_oracle.py`**: 91 vectores límite (MIN/-1, shifts ≥256, `pow_mod256`, `unsafe_*`, conversiones con clamp, add/sub/mul con overflow) en 6 configuraciones → **0 divergencias**.
- **`semantic_oracle.py`**: 95 vectores contra un **modelo Python independiente** en v0.4.3 `-O gas` → 0 discrepancias reales (los 3 reportados eran errores de mi oráculo sobre la semántica *unsafe* documentada).
- **Snekmate** (framework de referencia, `601f0738`): ninguna ocurrencia de ternarios con arrays anidados ni de `(msg.value | K)`; no se ve afectado por los advisories anteriores.

**Conclusión de la campaña:** no se ha identificado ningún defecto *nuevo* en el lenguaje que cumpla los 4 criterios; el crítico reportado es GHSA-cw3h, no parcheado en la versión de producción.

---

## 7. Entregables

Todos en `/home/user/repos/pocs/`:
- `evidence.py` — runner único con las 6 evidencias (§3–§5). Ejecutar: `venv_master/bin/python evidence.py`.
- `cw3h3.vy` (corrupción mínima), `cw3h_vault2.vy` (robo end-to-end), `ghsa_6j9c_shapes.vy`, `fxg7_factory.vy` + `blueprt.vy`, `v403/{lib,main}.vy`.
- `fuzzer2.py`, `fuzzer3.py`, `arith_oracle.py`, `semantic_oracle.py`, `verify_403_advisories.py`.
- `poc_6j9c_runtime.py`, `poc_fxg7_runtime.py`, `poc_cw3h_runtime.py`.

### Reproducción exacta del crítico
```bash
# 1) compilar con la estable
PYTHONPATH=/home/user/repos/vyper-v0.4.3 /home/user/repos/venv403/bin/python -m vyper \
    -f combined_json -O gas /home/user/repos/pocs/cw3h_vault2.vy
# 2) desplegar y ejecutar el escenario (víctima 12 ETH, atacante 2 ETH)
cd /home/user/repos/pocs && /home/user/repos/venv_master/bin/python evidence.py   # sección 4
```

**Limitaciones declaradas:** no se usó RPC (por diseño del brief); la exposición en mainnet no se cuantifica, pero conforme a la REGLA DE ORO se reporta la vulnerabilidad porque el código vulnerable está en la versión de producción y la ruta es activa con flags por defecto. La atribución de commit del fix (`1fb7dfe2`) se toma del advisory y del diff de código; el clon local tiene un único commit squash, por lo que la ascendencia git no es verificable localmente.
