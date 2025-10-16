import os
import time
import secrets
from dataclasses import dataclass
from typing import List, Dict, Tuple

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from Crypto.Cipher import AES, DES


# ---------------------------- Configurações ---------------------------- #
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
RUNS_PER_TEST = 10

SIZES = [
    ("1KB", 1 * 1024),
    ("1MB", 1 * 1024 * 1024),
    ("10MB", 10 * 1024 * 1024),
]

MB_DIVISOR = 1024 * 1024  # Usar MiB/s para consistência com tamanhos acima


@dataclass(frozen=True)
class AlgoSpec:
    name: str
    key_size: int
    block_size: int
    cipher_cls: object  # AES ou DES


ALGORITHMS: List[AlgoSpec] = [
    AlgoSpec("AES-128", 16, 16, AES),
    AlgoSpec("AES-256", 32, 16, AES),
    AlgoSpec("DES", 8, 8, DES),
]


# ---------------------------- Utilitários ---------------------------- #

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int) -> bytes:
    if not padded or (len(padded) % block_size) != 0:
        raise ValueError("Dados com padding inválido (tamanho)")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Dados com padding inválido (comprimento)")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Dados com padding inválido (assinatura)")
    return padded[:-pad_len]


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)


def ensure_data_files():
    ensure_dirs()
    for label, size in SIZES:
        path = os.path.join(DATA_DIR, f"{label}.bin")
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(secrets.token_bytes(size))


def load_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ---------------------------- Criptografia ---------------------------- #

def new_cbc_cipher(spec: AlgoSpec, key: bytes, iv: bytes):
    return spec.cipher_cls.new(key, spec.cipher_cls.MODE_CBC, iv)


def encrypt_cbc(spec: AlgoSpec, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    # Gera key e IV aleatórios por operação
    key = secrets.token_bytes(spec.key_size)
    iv = secrets.token_bytes(spec.block_size)

    # Padding + cifra
    padded = pkcs7_pad(plaintext, spec.block_size)
    cipher = new_cbc_cipher(spec, key, iv)
    ciphertext = cipher.encrypt(padded)
    return key, iv, ciphertext


def decrypt_cbc(spec: AlgoSpec, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = new_cbc_cipher(spec, key, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded, spec.block_size)


# ---------------------------- Benchmark ---------------------------- #

def benchmark_file(spec: AlgoSpec, file_path: str, runs: int = RUNS_PER_TEST) -> Dict[str, float]:
    data = load_bytes(file_path)
    plaintext_len = len(data)

    enc_times: List[float] = []
    dec_times: List[float] = []

    # Determinar tamanho do ciphertext (apenas para throughput de decifra)
    # Faz uma rodada seca (sem contar no tempo) para obter o comprimento com padding
    _key0, _iv0, _ct0 = encrypt_cbc(spec, data)
    ciphertext_len = len(_ct0)

    # Executa as rodadas cronometradas
    for _ in range(runs):
        t0 = time.perf_counter()
        key, iv, ciphertext = encrypt_cbc(spec, data)
        t1 = time.perf_counter()
        enc_times.append(t1 - t0)

        t2 = time.perf_counter()
        plaintext_out = decrypt_cbc(spec, key, iv, ciphertext)
        t3 = time.perf_counter()
        dec_times.append(t3 - t2)

        # Sanidade
        if plaintext_out != data:
            raise AssertionError("Decifração não corresponde ao plaintext original!")

    enc_avg = sum(enc_times) / runs
    dec_avg = sum(dec_times) / runs

    enc_throughput = (plaintext_len / MB_DIVISOR) / enc_avg  # MiB/s
    dec_throughput = (ciphertext_len / MB_DIVISOR) / dec_avg  # MiB/s

    return {
        "enc_time_s": enc_avg,
        "dec_time_s": dec_avg,
        "enc_throughput_mib_s": enc_throughput,
        "dec_throughput_mib_s": dec_throughput,
        "plaintext_len_bytes": plaintext_len,
        "ciphertext_len_bytes": ciphertext_len,
    }


def run_all_tests() -> pd.DataFrame:
    ensure_data_files()

    rows: List[Dict] = []
    for label, _ in SIZES:
        fpath = os.path.join(DATA_DIR, f"{label}.bin")
        print(f"Benchmarking {label}...")
        for spec in ALGORITHMS:
            print(f"  - {spec.name} ({RUNS_PER_TEST} execuções)")
            res = benchmark_file(spec, fpath, runs=RUNS_PER_TEST)
            rows.append({
                "file": label,
                "algorithm": spec.name,
                "operation": "encrypt",
                "avg_time_s": res["enc_time_s"],
                "throughput_mib_s": res["enc_throughput_mib_s"],
                "input_bytes": res["plaintext_len_bytes"],
            })
            rows.append({
                "file": label,
                "algorithm": spec.name,
                "operation": "decrypt",
                "avg_time_s": res["dec_time_s"],
                "throughput_mib_s": res["dec_throughput_mib_s"],
                "input_bytes": res["ciphertext_len_bytes"],
            })

    df = pd.DataFrame(rows)
    return df


# ---------------------------- Relatórios e Gráficos ---------------------------- #

def save_table(df: pd.DataFrame):
    ensure_dirs()
    csv_path = os.path.join(RESULTS_DIR, "benchmark_results.csv")
    df.to_csv(csv_path, index=False)

    # Também salva uma tabela pivot por operação para leitura rápida
    pivot_enc = df[df.operation == "encrypt"].pivot(index="file", columns="algorithm", values="throughput_mib_s")
    pivot_dec = df[df.operation == "decrypt"].pivot(index="file", columns="algorithm", values="throughput_mib_s")
    with open(os.path.join(RESULTS_DIR, "benchmark_summary.txt"), "w") as f:
        f.write("Throughput (MiB/s) - Encrypt\n")
        f.write(pivot_enc.round(2).to_string())
        f.write("\n\nThroughput (MiB/s) - Decrypt\n")
        f.write(pivot_dec.round(2).to_string())


def plot_throughput(df: pd.DataFrame):
    ensure_dirs()

    def _plot(op: str, out_name: str):
        d = df[df.operation == op]
        algorithms = [a.name for a in ALGORITHMS]
        files = [label for label, _ in SIZES]

        # Matriz de valores (linhas=files, cols=algorithms)
        values = []
        for fl in files:
            row = []
            for alg in algorithms:
                v = d[(d["file"] == fl) & (d["algorithm"] == alg)]["throughput_mib_s"].values
                row.append(v[0] if len(v) else 0.0)
            values.append(row)

        # Plot de barras agrupadas
        fig, ax = plt.subplots(figsize=(8, 5))
        import numpy as np
        x = np.arange(len(files))
        width = 0.25

        for i, alg in enumerate(algorithms):
            ax.bar(x + i * width - width, [v[i] for v in values], width, label=alg)

        ax.set_title(f"Throughput {op.capitalize()} (MiB/s)")
        ax.set_xticks(x)
        ax.set_xticklabels(files)
        ax.set_ylabel("MiB/s")
        ax.legend()
        ax.grid(axis="y", linestyle=":", alpha=0.6)
        plt.tight_layout()
        out_path = os.path.join(RESULTS_DIR, out_name)
        plt.savefig(out_path, dpi=150)
        plt.close(fig)

    _plot("encrypt", "throughput_encrypt.png")
    _plot("decrypt", "throughput_decrypt.png")


def main():
    df = run_all_tests()
    save_table(df)
    plot_throughput(df)

    # Exibir resumo no console
    print("\nResultados salvos em:")
    print(f"- {os.path.join(RESULTS_DIR, 'benchmark_results.csv')}")
    print(f"- {os.path.join(RESULTS_DIR, 'benchmark_summary.txt')}")
    print(f"- {os.path.join(RESULTS_DIR, 'throughput_encrypt.png')}")
    print(f"- {os.path.join(RESULTS_DIR, 'throughput_decrypt.png')}")

    # Mostrar tabela resumida no stdout
    pivot = df.pivot_table(index=["file", "operation"], columns="algorithm", values="throughput_mib_s")
    print("\nThroughput (MiB/s) - resumo:\n")
    print(pivot.round(2).to_string())


if __name__ == "__main__":
    main()
