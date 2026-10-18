# Validação local

Ambiente: Windows x64, Rust/Cargo 1.98.1, OXC 0.154.0, Chrome 155.0.8059.84, CDP 1.3.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passou |
| `cargo test --locked --workspace` | 19 testes passaram; 3 testes com browser são executados separadamente |
| Testes reais de browser com `--ignored --test-threads=1` | 3 testes passaram |
| Gate de repetição de captura | 20 execuções consecutivas, verificando scripts por URL/contexto e ausência de cobertura parcial |
| Login e map protegido | Cookie emitido pelo login, map obtido pelo contexto autenticado e fonte exportada |
| Sessão | Cookies e localStorage salvos/restaurados |
| CDP remoto | HTTP discovery e WebSocket direto; navegador externo preservado e contexto de captura descartado |
| `cargo build --locked --release -p r3kj4-cli` | Executável Windows gerado |
| `r3kj4 doctor --browser` no executável release | Passou |
| Scan release das fixtures offline | 4 artefatos, 2 fontes, 2 endpoints, 2 achados, cobertura completa |
| Dependências PE do executável release | Apenas DLLs do Windows; CRT estático, sem `VCRUNTIME140.dll` ou OpenSSL |

Os testes de runtime verificam carregamento inicial, import dinâmico, eval, blob worker, dedicated worker, service worker, iframe, navegação adicional, fetch, XHR e respostas JSON com segredos sintéticos. As verificações de fontes exigem artefatos `runtime_script` no contexto/URL correspondente, evitando contar apenas strings presentes no bundle principal.

Os testes de core cobrem byte a byte de fontes vazias/Unicode, maps indexados e inline, caminhos conflitantes/traversal, import maps simples, resolução local com origem HTTP, preservação de query, zero tráfego offline, isolamento de credenciais, fallback de parsing, limites e cancelamento. Os testes CLI verificam JSON em stdout, configuração TOML, exit code parcial e preservação dos arquivos de entrada.

Docker/Podman não estão disponíveis no ambiente de execução. O Dockerfile e os jobs de container foram preparados, mas não executados aqui. Builds e testes macOS/Linux também dependem da execução da matriz de CI; este registro não atesta resultados desses jobs.
