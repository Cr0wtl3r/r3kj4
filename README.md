# r3kj4

CLI em Rust para descobrir JavaScript/TypeScript, recuperar fontes de source maps e analisar endpoints, URLs, comentários e possíveis segredos com OXC. A captura opcional por Chrome DevTools Protocol inclui scripts dinâmicos, XHR/fetch, frames e workers.

## Compilar e experimentar

Instale Rust com rustup. O repositório fixa a versão do toolchain e as dependências em `Cargo.lock`.

```sh
cargo build --locked --release -p r3kj4-cli
```

O executável fica em `target/release/r3kj4` (`r3kj4.exe` no Windows). A análise local/HTTP não requer Node, Python ou Chrome. Para runtime, instale Chrome/Chromium, defina `CHROME_PATH`, use `--chrome` ou conecte um navegador remoto com `--cdp-url`.

```sh
r3kj4 scan fixtures/offline --offline --out resultado
r3kj4 scan https://app.example --out coleta
r3kj4 scan https://app.example --runtime --out runtime
r3kj4 scan ./assets --base-url https://app.example/assets/ --out recuperado
r3kj4 analyze ./src --only secrets,endpoints,urls,comments --out analise
r3kj4 beautify app.min.js --out app.pretty.js
r3kj4 doctor --browser
```

Use `cargo run -p r3kj4-cli -- ...` durante o desenvolvimento. Escolha um diretório de saída novo a cada execução; a ferramenta recusa diretórios existentes e não modifica os arquivos de entrada. `beautify` sem `--out` imprime o código. Para diretórios, `beautify` exige `--out` e grava em `formatted/`.

## Autenticação e fluxos

```sh
r3kj4 scan https://app.example \
  --runtime --flow examples/login.toml \
  --save-session login.session.json --out autenticado

r3kj4 scan https://app.example \
  --runtime --session login.session.json --out segunda-coleta

r3kj4 scan https://app.example \
  -H 'Authorization: Bearer TOKEN' --cookie 'session=VALUE' --out api
```

O fluxo começa depois da navegação ao alvo. Veja [examples/login.toml](examples/login.toml): `goto`, `fill`, `click`, `press`, `wait_for` e `wait` são sequenciais. `fill` aceita exatamente um de `value` ou `env`; `wait_for`, exatamente um de `selector` ou `url` (URL completa, igualdade exata). Um passo obrigatório que falha encerra o fluxo e conserva o resultado parcial. Não há login manual/MFA interativo nesta versão.

Sessões usam JSON com `schema_version = 1`, cookies CDP e `origins: [{origin, local_storage}]`. Cookies e localStorage são restaurados no contexto isolado. `--save-session` exige um arquivo novo.

Headers e o Cookie configurado são restritos à origem do alvo/base. `--credential-origin https://api.example` estende essa lista. `--allow-origin` amplia a navegação, sem ampliar automaticamente o escopo de credenciais. Assets externos referenciados podem ser coletados; endpoints encontrados pela análise não são requisitados automaticamente.

## Configuração e resultados

[examples/config.toml](examples/config.toml) documenta os defaults. A configuração tem versão 1 e rejeita campos desconhecidos. Argumentos explícitos da CLI sobrescrevem valores equivalentes; flags booleanas habilitam opções e listas de origens são adicionadas às configuradas.

```sh
r3kj4 --config examples/config.toml scan https://app.example --out coleta
r3kj4 scan ./assets --offline --format json --out coleta
```

`--format json` reserva stdout para o relatório; progresso e diagnósticos usam stderr. Os valores encontrados são completos no terminal, JSON, Markdown e fontes exportadas.

```text
coleta/
  manifest.json   # artefatos, hashes, relações, fontes recuperadas e cobertura
  report.json     # relatório completo, schema_version 1
  report.md       # relatório legível
  raw/           # bytes originais, identificados por SHA-256
  sources/       # fontes recuperadas organizadas por map
  formatted/     # código impresso pelo OXC
```

O relatório distingue fontes `embedded`, `external` e `unavailable`, endpoints inferidos/observados e evidências AST/textuais. Confiança e severidade são campos separados. Uma correspondência de URL/método com uma requisição observada não prova que uma linha específica originou aquela requisição; o initiator CDP permanece no inventário para inspeção.

| Exit code | Significado |
|---|---|
| 0 | Execução concluída |
| 1 | Falha de execução/configuração |
| 2 | Erro de sintaxe nos argumentos da CLI |
| 3 | Resultado parcial: falha em runtime/parsing, cancelamento ou limites |

Map ausente/404 é registrado como indisponibilidade normal. `--offline` impede rede em todo o pipeline. Referências locais precisam permanecer na raiz de entrada; fontes fora dela são diagnosticadas. Para uma entrada local, `--base-url` associa a raiz do diretório a um prefixo HTTP, incluindo a barra final, e permite buscar referências ausentes.

Os limites são configuráveis: 8 downloads, até 4 tarefas CPU, profundidade 2, 25 páginas, 10000 artefatos, 50 MiB por JS/map, 2 MiB por corpo textual de runtime e 1 GiB adquirido. `--timeout` controla HTTP/CDP; `--page-timeout` limita navegação/passos; `--settle-ms` controla o período de observação após navegar. Veja `scan --help` para todas as opções.

`--proxy` suporta proxy HTTP(S). No browser, o proxy é aplicado ao contexto criado pela ferramenta. `--ca-cert` adiciona uma CA ao cliente Rust; o navegador usa seu próprio armazenamento de confiança. Para CAs privadas em runtime, configure também a confiança do Chrome utilizado. `--insecure` desabilita a validação explicitamente nos dois caminhos. Argumentos adicionais de Chrome local usam `--browser-arg=...`.

## Docker e CDP remoto

```sh
docker build -t r3kj4 .
docker run --rm --shm-size=1g \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  r3kj4 doctor --browser
```

A imagem inclui Chromium e roda como UID 10001. Dê permissão de escrita a esse usuário no volume de saída. O Chrome mantém seu sandbox habilitado; as opções acima permitem seus namespaces em hosts Docker que os restringem. A política do host ainda precisa permitir user namespaces. Um ambiente que exija `--no-sandbox` deve passá-lo explicitamente por `--browser-arg=--no-sandbox`.

```sh
docker run --rm --shm-size=1g \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v /caminho/gravavel:/data r3kj4 \
  scan https://app.example --runtime --out /data/coleta

docker run --rm -v /caminho/gravavel:/data r3kj4 \
  scan https://app.example --runtime \
  --cdp-url ws://browser:9222/devtools/browser/ID --out /data/remoto
```

CLI e browser remoto precisam alcançar o alvo; a CLI também precisa alcançar o endereço WebSocket. Um endpoint HTTP pode anunciar `127.0.0.1`, inacessível de outro container. Nesse caso forneça o `ws://` completo com hostname alcançável. Em Linux, acesso ao host pode exigir `--add-host=host.docker.internal:host-gateway`. A ferramenta cria e descarta seu contexto e preserva o navegador remoto e suas outras abas.

## Validação e distribuição

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked -p r3kj4-browser --test runtime -- --ignored --nocapture --test-threads=1
```

Os testes de browser exigem Chrome e estão marcados como `ignored` para a suíte offline. Incluem 20 repetições de captura, login, map autenticado, restauração de sessão, conexão HTTP/WebSocket remota e preservação do browser remoto. A CI também prepara binários Windows x64, macOS x64/ARM64, Linux musl x64/ARM64 e testes em container.

Para reproduzir o protótipo da dependência inicial:

```sh
cargo run -p r3kj4-browser --features chromiumoxide-probe \
  --example chromiumoxide_probe -- /caminho/do/chrome
```

Veja [docs/architecture.md](docs/architecture.md) para a decisão sobre CDP e os limites de análise, e [docs/validation.md](docs/validation.md) para os resultados verificados localmente. `old/` foi preservado como referência.
