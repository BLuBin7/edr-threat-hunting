#!/usr/bin/env python3
"""
Export trained Isolation Forest model to ONNX format for Go inference
Includes quantization (Float32 -> Int8) for smaller model size
"""

import argparse
import os
import pickle

import numpy as np
import onnx
from onnx import numpy_helper
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as ort


def export_to_onnx(model, output_path, quantize=True):
    """Export sklearn model to ONNX format"""

    print(f"Exporting model to ONNX format...")

    # Define input shape (batch_size=None for dynamic, 15 features)
    initial_type = [('float_input', FloatTensorType([None, 15]))]

    # Convert to ONNX
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=12
    )

    # Save unquantized model
    temp_path = output_path.replace('.onnx', '_float32.onnx')
    with open(temp_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"✅ Float32 model saved: {temp_path}")
    print(f"   Size: {os.path.getsize(temp_path) / 1024:.2f} KB")

    if quantize:
        print("\nQuantizing model (Float32 -> Int8)...")
        try:
            from onnxruntime.quantization import quantize_dynamic, QuantType

            quantize_dynamic(
                temp_path,
                output_path,
                weight_type=QuantType.QInt8
            )

            print(f"✅ Quantized model saved: {output_path}")
            print(f"   Size: {os.path.getsize(output_path) / 1024:.2f} KB")

            # Calculate compression ratio
            original_size = os.path.getsize(temp_path)
            quantized_size = os.path.getsize(output_path)
            ratio = original_size / quantized_size
            print(f"   Compression ratio: {ratio:.2f}x")

        except ImportError:
            print("⚠️  Quantization not available, using Float32 model")
            os.rename(temp_path, output_path)
    else:
        os.rename(temp_path, output_path)

    return output_path


def verify_onnx_model(onnx_path, sklearn_model):
    """Verify ONNX model produces same results as sklearn model"""

    print("\nVerifying ONNX model...")

    # Load ONNX model
    ort_session = ort.InferenceSession(onnx_path)

    # Generate test input
    test_input = np.random.randn(5, 15).astype(np.float32)

    # Sklearn prediction
    sklearn_pred = sklearn_model.predict(test_input)

    # ONNX prediction
    ort_inputs = {ort_session.get_inputs()[0].name: test_input}
    ort_outputs = ort_session.run(None, ort_inputs)
    onnx_pred = ort_outputs[0]

    # Compare
    matches = np.allclose(sklearn_pred, onnx_pred, rtol=1e-3, atol=1e-3)

    if matches:
        print("✅ ONNX model verification passed!")
        print(f"   Sample predictions match sklearn model")
    else:
        print("⚠️  ONNX model verification failed!")
        print(f"   Sklearn: {sklearn_pred[:3]}")
        print(f"   ONNX:    {onnx_pred[:3]}")

    return matches


def benchmark_inference(onnx_path, n_samples=1000):
    """Benchmark ONNX model inference latency"""

    print(f"\nBenchmarking inference latency ({n_samples} samples)...")

    import time

    # Load model
    ort_session = ort.InferenceSession(onnx_path)

    # Generate test data
    test_data = np.random.randn(n_samples, 15).astype(np.float32)

    # Warmup
    for _ in range(10):
        ort_inputs = {ort_session.get_inputs()[0].name: test_data[:1]}
        _ = ort_session.run(None, ort_inputs)

    # Benchmark
    latencies = []
    for i in range(n_samples):
        sample = test_data[i:i+1]
        ort_inputs = {ort_session.get_inputs()[0].name: sample}

        start = time.time()
        _ = ort_session.run(None, ort_inputs)
        end = time.time()

        latencies.append((end - start) * 1000)  # Convert to ms

    # Statistics
    latencies = np.array(latencies)
    print(f"✅ Inference latency statistics:")
    print(f"   Mean:   {np.mean(latencies):.2f} ms")
    print(f"   Median: {np.median(latencies):.2f} ms")
    print(f"   P95:    {np.percentile(latencies, 95):.2f} ms")
    print(f"   P99:    {np.percentile(latencies, 99):.2f} ms")
    print(f"   Min:    {np.min(latencies):.2f} ms")
    print(f"   Max:    {np.max(latencies):.2f} ms")


def main():
    parser = argparse.ArgumentParser(description='Export sklearn model to ONNX format')
    parser.add_argument('--model', type=str, required=True, help='Path to sklearn model (.pkl)')
    parser.add_argument('--output', type=str, required=True, help='Output ONNX model path')
    parser.add_argument('--quantize', action='store_true', default=True, help='Quantize model (Float32->Int8)')
    parser.add_argument('--no-quantize', action='store_false', dest='quantize', help='Disable quantization')
    parser.add_argument('--benchmark', action='store_true', help='Run inference benchmark')

    args = parser.parse_args()

    # Load sklearn model
    print(f"Loading sklearn model: {args.model}")
    with open(args.model, 'rb') as f:
        sklearn_model = pickle.load(f)

    print(f"✅ Model loaded successfully")

    # Export to ONNX
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    onnx_path = export_to_onnx(sklearn_model, args.output, quantize=args.quantize)

    # Verify
    verify_onnx_model(onnx_path, sklearn_model)

    # Benchmark
    if args.benchmark:
        benchmark_inference(onnx_path)

    print(f"\n✅ Export completed successfully!")
    print(f"   ONNX model ready for deployment: {onnx_path}")


if __name__ == '__main__':
    main()
