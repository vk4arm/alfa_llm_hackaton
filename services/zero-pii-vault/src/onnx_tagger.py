from config_loader import load_vault_config
"""
ONNX Runtime Acceleration Engine for Natasha Slovnet NER (Step В).
Replaces the pure-Python NumPy loops of Slovnet CNN with high-performance C++ AVX2/NEON SIMD execution.
"""

import os

try:
    import onnx
    from onnx import helper, TensorProto
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


def build_slovnet_onnx_model(slovnet_model, output_path: str):
    """
    Constructs an ONNX computational graph directly from Slovnet's trained weights.
    Architecture:
    3x [Conv1d(k=3, pad=1) -> ReLU -> BatchNorm1d(eps=1e-5)] -> Transpose -> MatMul + Add (Linear Proj)
    """
    nodes = []
    initializers = []

    cur_input = 'input'
    for i, l in enumerate(slovnet_model.encoder.layers):
        w_conv = l.conv.weight.array
        b_conv = l.conv.bias.array
        w_name = f'w_conv_{i}'
        b_name = f'b_conv_{i}'
        initializers.append(helper.make_tensor(w_name, TensorProto.FLOAT, w_conv.shape, w_conv.flatten().tolist()))
        initializers.append(helper.make_tensor(b_name, TensorProto.FLOAT, b_conv.shape, b_conv.flatten().tolist()))
        
        out_conv = f'out_conv_{i}'
        nodes.append(helper.make_node('Conv', inputs=[cur_input, w_name, b_name], outputs=[out_conv], kernel_shape=[3], pads=[1, 1]))
        out_relu = f'out_relu_{i}'
        nodes.append(helper.make_node('Relu', inputs=[out_conv], outputs=[out_relu]))
        
        scale = l.norm.weight.array
        bias = l.norm.bias.array
        mean = l.norm.mean.array
        var = l.norm.std.array ** 2 - 1e-5
        
        s_name, bi_name, m_name, v_name = f'bn_scale_{i}', f'bn_bias_{i}', f'bn_mean_{i}', f'bn_var_{i}'
        initializers.append(helper.make_tensor(s_name, TensorProto.FLOAT, scale.shape, scale.flatten().tolist()))
        initializers.append(helper.make_tensor(bi_name, TensorProto.FLOAT, bias.shape, bias.flatten().tolist()))
        initializers.append(helper.make_tensor(m_name, TensorProto.FLOAT, mean.shape, mean.flatten().tolist()))
        initializers.append(helper.make_tensor(v_name, TensorProto.FLOAT, var.shape, var.flatten().tolist()))
        
        out_bn = f'out_bn_{i}'
        nodes.append(helper.make_node('BatchNormalization', inputs=[out_relu, s_name, bi_name, m_name, v_name], outputs=[out_bn], epsilon=1e-5))
        cur_input = out_bn

    nodes.append(helper.make_node('Transpose', inputs=[cur_input], outputs=['transposed'], perm=[0, 2, 1]))

    w_proj = slovnet_model.head.proj.weight.array
    b_proj = slovnet_model.head.proj.bias.array
    initializers.append(helper.make_tensor('w_proj', TensorProto.FLOAT, w_proj.shape, w_proj.flatten().tolist()))
    initializers.append(helper.make_tensor('b_proj', TensorProto.FLOAT, b_proj.shape, b_proj.flatten().tolist()))

    nodes.append(helper.make_node('MatMul', inputs=['transposed', 'w_proj'], outputs=['matmul_out']))
    nodes.append(helper.make_node('Add', inputs=['matmul_out', 'b_proj'], outputs=['output']))

    inputs = [helper.make_tensor_value_info('input', TensorProto.FLOAT, ['batch', 330, 'seq'])]
    outputs = [helper.make_tensor_value_info('output', TensorProto.FLOAT, ['batch', 'seq', 8])]

    graph = helper.make_graph(nodes, 'SlovnetCNN', inputs, outputs, initializers)
    model_proto = helper.make_model(graph, producer_name='alfa_vault', opset_imports=[helper.make_opsetid('', 14)], ir_version=9)
    onnx.checker.check_model(model_proto)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    onnx.save(model_proto, output_path)


class ONNXFastProcess:
    """Replaces Slovnet's inner loop with ONNX Runtime inference."""
    def __init__(self, tagger, onnx_model_path: str):
        self.tagger = tagger
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.sess = ort.InferenceSession(onnx_model_path, sess_options=opts, providers=['CPUExecutionProvider'])

    def process(self, inputs):
        for input in inputs:
            # 1. Fast embedding lookup in Navec (NumPy)
            x = self.tagger.infer.model.emb(input.word_id, input.shape_id)
            # x is [batch, seq, 330] -> swapaxes to [batch, 330, seq]
            x_in = x.swapaxes(1, 2)
            # 2. C++ ONNX Runtime SIMD execution
            pred = self.sess.run(None, {'input': x_in})[0]
            # 3. CRF decode
            yield from self.tagger.infer.model.head.crf.decode(pred, ~input.pad_mask)


def apply_onnx_acceleration(tagger) -> bool:
    """
    Applies ONNX acceleration to an instance of NewsNERTagger.
    Returns True if successfully accelerated, False otherwise.
    """
    if not ONNX_AVAILABLE:
        return False

    try:
        model_path = os.getenv("SLOVNET_ONNX_PATH", os.path.join(__import__("tempfile").gettempdir(), "slovnet_cnn.onnx"))
        if not os.path.exists(model_path):
            build_slovnet_onnx_model(tagger.infer.model, model_path)

        fast_proc = ONNXFastProcess(tagger, model_path)
        tagger.infer.process = fast_proc.process
        return True
    except Exception as e:
        # Fallback to standard Slovnet if any issue occurs
        import logging
        logging.error("ONNX fallback", exc_info=e)
        return False
