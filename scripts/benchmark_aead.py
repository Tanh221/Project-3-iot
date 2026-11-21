import os
import time
import tracemalloc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import ascon  # Ref: NIST SP 800-232 / ascon PyPI package

# Configuration Parameters
NUM_ITERATIONS = 5000       
PAYLOAD_SIZES = [64, 256, 1024, 4096] 

def benchmark_ascon(data: bytes, iterations: int):
    key = os.urandom(16)   # 128-bit key
    nonce = os.urandom(16) # 128-bit nonce
    associated_data = b"HEADER_AAD_DATA"

    # Start memory tracing
    tracemalloc.start()
    
    # 1. Measure Encryption
    start_enc = time.perf_counter()
    for _ in range(iterations):
        ct = ascon.encrypt(key, nonce, associated_data, data, variant="Ascon-128")
    end_enc = time.perf_counter()

    # 2. Measure Decryption
    start_dec = time.perf_counter()
    for _ in range(iterations):
        pt = ascon.decrypt(key, nonce, associated_data, ct, variant="Ascon-128")
    end_dec = time.perf_counter()

    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    enc_time = (end_enc - start_enc) / iterations
    dec_time = (end_dec - start_dec) / iterations
    overhead = len(ct) - len(data)

    return enc_time, dec_time, overhead, peak_mem / 1024

def benchmark_aes_gcm(data: bytes, iterations: int):
    key = AESGCM.generate_key(bit_length=128) # 128-bit key
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # 96-bit standard nonce cho AES-GCM
    associated_data = b"HEADER_AAD_DATA"

    tracemalloc.start()

    # 1. Measure Encryption
    start_enc = time.perf_counter()
    for _ in range(iterations):
        ct = aesgcm.encrypt(nonce, data, associated_data)
    end_enc = time.perf_counter()

    # 2. Measure Decryption
    start_dec = time.perf_counter()
    for _ in range(iterations):
        pt = aesgcm.decrypt(nonce, ct, associated_data)
    end_dec = time.perf_counter()

    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    enc_time = (end_enc - start_enc) / iterations
    dec_time = (end_dec - start_dec) / iterations
    overhead = len(ct) - len(data)

    return enc_time, dec_time, overhead, peak_mem / 1024

def benchmark_chacha20_poly1305(data: bytes, iterations: int):
    key = ChaCha20Poly1305.generate_key() # 256-bit key
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)                 # 96-bit nonce
    associated_data = b"HEADER_AAD_DATA"

    tracemalloc.start()

    # 1. Measure Encryption
    start_enc = time.perf_counter()
    for _ in range(iterations):
        ct = chacha.encrypt(nonce, data, associated_data)
    end_enc = time.perf_counter()

    # 2. Measure Decryption
    start_dec = time.perf_counter()
    for _ in range(iterations):
        pt = chacha.decrypt(nonce, ct, associated_data)
    end_dec = time.perf_counter()

    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    enc_time = (end_enc - start_enc) / iterations
    dec_time = (end_dec - start_dec) / iterations
    overhead = len(ct) - len(data)

    return enc_time, dec_time, overhead, peak_mem / 1024

def run_benchmarks():
    print("=" * 80)
    print(f"AEAD BENCHMARK SUITE (Iterations per test: {NUM_ITERATIONS})")
    print("=" * 80)

    for size in PAYLOAD_SIZES:
        payload = os.urandom(size)
        print(f"\n--- Payload Size: {size} Bytes ---")
        print(f"{'Algorithm':<20} | {'Enc Time (us)':<14} | {'Dec Time (us)':<14} | {'Throughput (MB/s)':<18} | {'Tag Overhead':<12} | {'Peak RAM (KB)'}")
        print("-" * 105)

        algorithms = [
            ("ASCON-128", benchmark_ascon),
            ("AES-128-GCM", benchmark_aes_gcm),
            ("ChaCha20-Poly1305", benchmark_chacha20_poly1305)
        ]

        for name, bench_fn in algorithms:
            enc_t, dec_t, overhead, peak_ram = bench_fn(payload, NUM_ITERATIONS)
            # Ep Us (microseconds)
            enc_us = enc_t * 1e6
            dec_us = dec_t * 1e6
            # MB/s Throughput
            throughput = (size / (1024 * 1024)) / enc_t if enc_t > 0 else 0

            print(f"{name:<20} | {enc_us:<14.2f} | {dec_us:<14.2f} | {throughput:<18.2f} | {overhead:<12} | {peak_ram:.2f}")

if __name__ == "__main__":
    run_benchmarks()