# Benchmark de Desempenho: AES (128/256) vs DES em CBC

Este projeto implementa um sistema comparativo de desempenho entre AES (128 e 256 bits) e DES utilizando o modo CBC com padding PKCS7. Ele:

- Cifra e decifra arquivos de diferentes tamanhos (1KB, 1MB, 10MB)
- Mede tempo médio de processamento (média de 10 execuções por teste)
- Calcula throughput (MiB/s) para operações de cifra e decifra
- Gera relatório comparativo em CSV e TXT
- Plota gráficos de desempenho com matplotlib

## Requisitos Técnicos

- Modos: `AES.MODE_CBC` e `DES.MODE_CBC`
- Padding: PKCS7 (implementado manualmente)
- IV: aleatório a cada operação
- Amostragem: média de 10 execuções por combinação algoritmo × arquivo × operação

## Stack

- Python 3.8+
- [PyCryptodome](https://pycryptodome.readthedocs.io/) (AES/DES)
- [pandas](https://pandas.pydata.org/) (relatórios)
- [matplotlib](https://matplotlib.org/) (gráficos)

## Estrutura do Projeto

```
BenchAESDES/
├─ bench.py                 # Script principal do benchmark
├─ requirements.txt         # Dependências
├─ data/                    # Arquivos de teste (gerados automaticamente)
│  ├─ 1KB.bin
│  ├─ 1MB.bin
│  └─ 10MB.bin
└─ results/                 # Saídas do benchmark
   ├─ benchmark_results.csv
   ├─ benchmark_summary.txt
   ├─ throughput_encrypt.png
   └─ throughput_decrypt.png
```

## Instalação

1) Crie e ative um ambiente virtual (opcional):

```
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows (PowerShell)
```

2) Instale as dependências:

```
pip install -r requirements.txt
```

## Execução

```
python bench.py
```

O script irá:
- Gerar arquivos aleatórios em `data/` (1KB, 1MB, 10MB), caso não existam
- Executar os testes para AES-128, AES-256 e DES
- Salvar resultados e gráficos em `results/`
- Exibir no console uma tabela-resumo de throughput (MiB/s)

## Metodologia de Medição

Para cada arquivo de entrada:
- É feito um aquecimento (rodada seca) para descobrir o tamanho do ciphertext (pós-padding) e não contaminar as médias
- Para cada uma das 10 execuções por algoritmo:
  - Gera-se uma chave e um IV aleatórios
  - Aplica-se PKCS7 ao plaintext e cifra-se com CBC
  - Mede-se o tempo de cifra
  - Decifra-se o ciphertext com a mesma chave/IV e remove-se o padding
  - Mede-se o tempo de decifra e valida-se que o plaintext recuperado é idêntico ao original

Cálculo de throughput (MiB/s):
- Cifra: (bytes do plaintext / 2^20) / tempo_médio_cifra
- Decifra: (bytes do ciphertext / 2^20) / tempo_médio_decifra

Observação: usa-se MiB (2^20) para consistência com os tamanhos 1MB = 1.048.576 bytes.

## Configuração

Edite os parâmetros em `bench.py`:

- `RUNS_PER_TEST`: número de execuções por teste (padrão: 10)
- `SIZES`: lista de tamanhos e rótulos dos arquivos de entrada
- `MB_DIVISOR`: divisor para converter bytes em MiB; altere para `1_000_000` se preferir MB decimal

## Resultados de Exemplo (MiB/s)

Abaixo um exemplo de resumo impresso (valores variam por hardware/OS):

```
algorithm       AES-128  AES-256    DES
file operation                          
10MB decrypt     308.61   229.17  88.56
     encrypt     266.00   206.98  71.85
1KB  decrypt      89.66    90.51  42.11
     encrypt      61.34    67.19  29.57
1MB  decrypt     268.52   231.13  89.47
     encrypt     239.20   205.26  71.04
```

Os arquivos completos estão em:
- `results/benchmark_results.csv` (linha a linha)
- `results/benchmark_summary.txt` (tabela pivot por operação)
- `results/throughput_encrypt.png` e `results/throughput_decrypt.png` (gráficos)

## Considerações

- AES-128 tende a ser mais rápido que AES-256; ambos superam DES de forma consistente
- Em arquivos pequenos (1KB), a sobrecarga fixa (alocação, I/O, criação de objetos) domina
- O modo CBC não é paralelizável por bloco; resultados podem diferir em implementações/CPUs distintas
- Este benchmark usa PyCryptodome em Python; aceleração por hardware (ex.: AES-NI) pode não ser plenamente explorada

## Reprodutibilidade

Os arquivos de teste são gerados com bytes aleatórios. Pequenas variações de tempo são esperadas. Para comparações justas, execute várias vezes e considere pinos de afinidade/isolamento de carga no sistema.

## Licença

Este projeto é destinado a fins acadêmicos e educacionais.
