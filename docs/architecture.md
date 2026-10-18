# Arquitetura e limites da primeira versão

## Componentes

`r3kj4-cli` combina argumentos e TOML versionado. `r3kj4-browser` captura execução e retorna `RuntimeCapture`. `r3kj4-core` recebe esse inventário junto com o alvo, resolve arquivos/maps, analisa artefatos e exporta o relatório. O browser depende dos modelos do core; o core não depende de Chrome.

A aquisição HTTP usa concorrência limitada e redirects manuais para reavaliar credenciais. Cookies recebidos pelo cliente HTTP ficam em um jar consultado somente nas origens de credenciais. A análise CPU usa um pool Rayon; cada tarefa possui seu allocator, AST e semântica OXC, retornando dados próprios. O grafo preserva ocorrências mesmo quando os bytes brutos compartilham um hash.

As regras usam AST e referências resolvidas para identificar clientes e valores. Regex continua útil para formatos conhecidos de tokens e para fallback textual. Nenhum segredo é validado contra serviços externos. Configurações públicas de cliente, JWTs e chaves de API não constituem automaticamente uma vulnerabilidade; as regras mantêm severidade e confiança separadas.

## ADR: captura CDP com sessões explícitas

**Decisão:** usar `tokio-tungstenite` e mensagens CDP diretamente no adaptador de browser. `chromiumoxide` permanece opcional para reproduzir o protótipo.

No protótipo Windows/Chrome, o worker executou e respondeu à página, mas o listener `page.event_listener::<EventScriptParsed>()` recebeu dois scripts da página e nenhum script do worker. O modelo de assinatura da página não atende sozinho à captura entre targets. A implementação usa `sessionId` em cada comando/evento, autoattach de frames/workers e associação explícita das requisições a cada sessão. Isso mantém o núcleo independente das APIs de alto nível da biblioteca.

Eventos que precisam buscar fontes/corpos são processados em tarefas separadas. Isso impede que um `fetch` de map bloqueie o mesmo consumidor responsável por liberar a requisição interceptada. Service workers podem pausar antes de buscar seu script: o adaptador libera o bootstrap e usa `Debugger.enable` para enumerar os scripts já analisados pelo browser.

O transporte tem fila limitada, timeout por comando, diagnóstico de overflow e cancelamento. A execução usa um contexto isolado. Apenas Chrome local iniciado pela ferramenta recebe `Browser.close`; CDP remoto mantém o processo e seus outros contextos.

## Recuperação e evidências

Source maps são validados pela crate `sourcemap`. Maps regulares, indexados, data URLs e sections externas alimentam a mesma fila de aquisição. `sourcesContent` é preservado byte a byte, inclusive vazio. Paths virtuais são mantidos como nomes lógicos. Exportações normalizam nomes, separam maps e evitam colisões de caixa e nomes reservados do Windows.

O parser trabalha com offsets de bytes UTF-8; o relatório usa linha e coluna UTF-16, iniciando em 1. A tradução para mappings usa linha e coluna iniciando em 0. Arquivos brutos permanecem disponíveis mesmo quando parsing ou impressão falham. A análise usa o conteúdo original, antes do codegen.

O avaliador é limitado ao arquivo: literais, concatenações, templates, objetos, destructuring, aliases e alternativas simples. Escritas em bindings e propriedades invalidam inferências conservadoramente. Valores dinâmicos continuam como templates desconhecidos. Uma chamada `.get()` em um objeto sem identificação de cliente HTTP não é classificada como axios.

## Limites e evolução

- A captura descreve os fluxos percorridos; rotas não visitadas e comportamentos não acionados podem permanecer desconhecidos.
- Sem `sourcesContent` ou fonte externa acessível, não há recuperação integral do original. Beautification conserva os identificadores disponíveis e não desfaz otimizações arbitrárias do bundler.
- O codegen pode alterar a apresentação ou omitir alguns comentários na versão legível; `raw/`, `sources/` e o inventário de comentários preservam a evidência original.
- A primeira versão não faz type checking TypeScript, resolução semântica entre módulos, interpretação geral de JavaScript, extração de SFC Vue/Svelte ou decompilação de WASM.
- Wrappers arbitrários de clientes, import maps com `scopes`, loaders proprietários e obfuscação que depende de execução exigem análise adicional. Referências não resolvidas e cobertura parcial permanecem visíveis.
- A confiança de um segredo depende do formato/contexto, não de sua validade ou privilégio reais. Entropia isolada não gera achado.

Próximas extensões: summaries de imports/exports, propagação entre módulos e wrappers, fluxo de tokens, parâmetros de routers, feature flags e rotas administrativas, novas regras e TUI sobre o relatório versionado.
