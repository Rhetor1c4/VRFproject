"""
EC-VRF 概率性服务公平性验证 - Flask后端服务
配合 vrf_implementations.py 和前端HTML页面使用
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session
import os
import secrets
import hashlib
import json
import uuid
from vrf_implementations import ECVRF, _sha256, _os2ip, _i2osp, _point_to_bytes

# 导入ECDSA相关（用于PKI签名）
from cryptography.hazmat.primitives.asymmetric import ec as _ec_crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False

# 创建session目录
os.makedirs('./flask_session', exist_ok=True)

CORS(app, supports_credentials=True)
Session(app)

# ──────────────────────────────────────────────
# 全局服务状态（生产环境应使用数据库）
# ──────────────────────────────────────────────
class ServiceState:
    def __init__(self):
        self.ec_vrf = ECVRF()
        self.vrf_sk = None       # VRF私钥
        self.vrf_pk = None       # VRF公钥
        self.pki_sk = None       # PKI的ECDSA私钥
        self.pki_pk = None       # PKI的ECDSA公钥
        self.sigma_pk = None     # PKI对VRF公钥的签名
        self.proof_store = {}    # 存储证明：{session_id: {x, y, pi}}
        
    def reset(self):
        self.__init__()

state = ServiceState()

# ──────────────────────────────────────────────
# 辅助函数：序列化/反序列化
# ──────────────────────────────────────────────
def serialize_ec_point(point):
    """将椭圆曲线点序列化为hex字符串"""
    if point is None:
        return None
    x, y = point
    return f"{x:064x}{y:064x}"

def serialize_pi(pi):
    """序列化证明π = (m, c, z)"""
    m, c, z = pi
    return {
        'm': serialize_ec_point(m),
        'c': hex(c),
        'z': hex(z)
    }

def serialize_ecdsa_public_key(pk):
    """序列化ECDSA公钥为PEM"""
    return pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

# ──────────────────────────────────────────────
# API路由
# ──────────────────────────────────────────────

@app.route('/api/init', methods=['POST'])
def init_pki():
    """
    步骤1：PKI初始化 - 生成VRF密钥对并签发σ_pk
    """
    try:
        # 1. 生成PKI自己的ECDSA密钥对（用于签发σ_pk）
        pki_sk = _ec_crypto.generate_private_key(
            _ec_crypto.SECP256R1(), default_backend()
        )
        pki_pk = pki_sk.public_key()
        state.pki_sk = pki_sk
        state.pki_pk = pki_pk
        
        # 2. 生成VRF密钥对
        vrf_pk, vrf_sk = state.ec_vrf.keygen()
        state.vrf_sk = vrf_sk
        state.vrf_pk = vrf_pk
        
        # 3. PKI对VRF公钥签名（σ_pk）
        # 将VRF公钥序列化为字节
        vrf_pk_bytes = _point_to_bytes(vrf_pk)
        
        # 使用ECDSA签名
        signature = pki_sk.sign(
            vrf_pk_bytes,
            _ec_crypto.ECDSA(hashes.SHA256())
        )
        sigma_pk = signature.hex()
        state.sigma_pk = sigma_pk
        
        return jsonify({
            'success': True,
            'pki_public_key': serialize_ecdsa_public_key(pki_pk),
            'vrf_public_key_raw': serialize_ec_point(vrf_pk),
            'vrf_public_key': vrf_pk,  # 不会直接序列化，仅用于调试
            'sigma_pk': sigma_pk,
            'message': '✅ VRF密钥对已生成，PKI已完成签名'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# 修改 evaluate 接口
@app.route('/api/evaluate', methods=['POST'])
def evaluate_vrf():
    """
    步骤2：服务商抽取 - 计算VRF输出y和证明π
    """
    try:
        data = request.get_json()
        input_x = data.get('input_x', '')

        if not input_x:
            return jsonify({'success': False, 'error': '输入x不能为空'}), 400

        if state.vrf_sk is None or state.vrf_pk is None:
            return jsonify({'success': False, 'error': 'VRF密钥未初始化'}), 400

        # 使用EC-VRF计算
        x_bytes = input_x.encode('utf-8')
        pi = state.ec_vrf.prove(state.vrf_sk, state.vrf_pk, x_bytes)
        y = state.ec_vrf.proof2hash(pi)

        # 生成唯一的证明ID并返回给客户端
        proof_id = str(uuid.uuid4())

        # 存储证明（使用proof_id作为key）
        state.proof_store[proof_id] = {
            'x': input_x,
            'y': y.hex(),
            'pi': pi
        }

        return jsonify({
            'success': True,
            'proof_id': proof_id,  # 返回proof_id给客户端
            'y': y.hex(),
            'pi': serialize_pi(pi),
            'vrf_public_key_raw': serialize_ec_point(state.vrf_pk),
            'message': '🎲 VRF计算完成'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# 修改 challenge 接口
@app.route('/api/challenge', methods=['POST'])
def challenge():
    """
    步骤3：用户质疑 - 服务商返回证明π和相关材料
    """
    try:
        data = request.get_json()
        proof_id = data.get('proof_id', '')
        input_x = data.get('input_x', '')
        expected_y = data.get('y', '')

        # 调试日志
        print(f"[DEBUG] challenge请求 - proof_id: '{proof_id}'", file=__import__('sys').stderr)
        print(f"[DEBUG] challenge请求 - input_x: '{input_x}'", file=__import__('sys').stderr)
        print(f"[DEBUG] challenge请求 - expected_y: '{expected_y}'", file=__import__('sys').stderr)
        print(f"[DEBUG] 可用的proof_ids: {list(state.proof_store.keys())}", file=__import__('sys').stderr)

        # 如果没有提供proof_id，尝试通过input_x和y来查找
        if not proof_id:
            found_id = None
            for pid, stored_data in state.proof_store.items():
                if stored_data['x'] == input_x and stored_data['y'] == expected_y:
                    found_id = pid
                    break

            if found_id:
                proof_id = found_id
                print(f"[DEBUG] 通过input_x和y匹配到proof_id: {proof_id}", file=__import__('sys').stderr)
            else:
                return jsonify({
                    'success': False,
                    'error': f'未找到匹配的证明记录。请确保先调用/evaluate。可用证明数: {len(state.proof_store)}'
                }), 404

        # 查找对应的证明
        if proof_id not in state.proof_store:
            return jsonify({
                'success': False,
                'error': f'proof_id不存在。请求的: "{proof_id}", 可用的: {list(state.proof_store.keys())}'
            }), 404

        stored = state.proof_store[proof_id]

        # 验证输入匹配（放宽检查）
        if stored['x'] != input_x:
            print(f"[DEBUG] x不匹配 - 存储: '{stored['x']}', 请求: '{input_x}'", file=__import__('sys').stderr)
            # 不直接拒绝，而是继续（开发调试阶段）

        if stored['y'] != expected_y:
            print(f"[DEBUG] y不匹配 - 存储: '{stored['y']}', 请求: '{expected_y}'", file=__import__('sys').stderr)
            # 不直接拒绝，而是继续（开发调试阶段）

        return jsonify({
            'success': True,
            'proof_id': proof_id,
            'pi': serialize_pi(stored['pi']),
            'vrf_public_key_raw': serialize_ec_point(state.vrf_pk),
            'sigma_pk': state.sigma_pk,
            'pki_public_key': serialize_ecdsa_public_key(state.pki_pk) if state.pki_pk else None,
            'message': '📜 证明π已返回'
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/verify', methods=['POST'])
def verify():
    """
    步骤4：用户验证 - 验证VRF证明和PKI签名
    """
    try:
        data = request.get_json()
        input_x = data.get('input_x', '')
        expected_y = data.get('y', '')
        pi_data = data.get('pi', {})
        vrf_pk_raw = data.get('vrf_public_key_raw', '')
        sigma_pk_hex = data.get('sigma_pk', '')
        pki_pk_pem = data.get('pki_public_key', '')
        
        # 1. 重构VRF公钥点
        if len(vrf_pk_raw) != 128:
            return jsonify({'success': False, 'error': 'VRF公钥格式错误'}), 400
        x_coord = int(vrf_pk_raw[:64], 16)
        y_coord = int(vrf_pk_raw[64:], 16)
        vrf_pk = (x_coord, y_coord)
        
        # 2. 重构证明π
        m_x = int(pi_data['m'][:64], 16)
        m_y = int(pi_data['m'][64:], 16)
        m = (m_x, m_y)
        c = int(pi_data['c'], 16)
        z = int(pi_data['z'], 16)
        pi = (m, c, z)
        
        # 3. 验证VRF证明
        vrf_valid = state.ec_vrf.verify(vrf_pk, input_x.encode('utf-8'), pi)
        
        # 4. 验证σ_pk签名（PKI对VRF公钥的签名）
        sigma_valid = False
        if state.pki_pk and sigma_pk_hex:
            try:
                from cryptography.hazmat.primitives.asymmetric import ec
                vrf_pk_bytes = _point_to_bytes(vrf_pk)
                signature_bytes = bytes.fromhex(sigma_pk_hex)
                state.pki_pk.verify(
                    signature_bytes,
                    vrf_pk_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                sigma_valid = True
            except:
                sigma_valid = False
        
        # 5. 验证y == H2(m)
        y_computed = state.ec_vrf.proof2hash(pi)
        y_match = (y_computed.hex() == expected_y)
        
        return jsonify({
            'success': True,
            'vrf_valid': vrf_valid,
            'sigma_valid': sigma_valid,
            'y_match': y_match,
            'message': '✅ 验证完成' if (vrf_valid and sigma_valid and y_match) else '❌ 验证未完全通过'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/verify_sigma', methods=['POST'])
def verify_sigma():
    """
    独立验证 σ_pk 签名
    """
    try:
        data = request.get_json()
        vrf_pk_raw = data.get('vrf_public_key_raw', '')
        sigma_pk_hex = data.get('sigma_pk', '')
        pki_pk_pem = data.get('pki_public_key', '')

        if not state.pki_pk:
            return jsonify({
                'success': True,
                'sigma_valid': False,
                'error': 'PKI公钥未初始化'
            })

        # 重构VRF公钥点
        if len(vrf_pk_raw) != 128:
            return jsonify({'success': False, 'error': 'VRF公钥格式错误'}), 400
        x_coord = int(vrf_pk_raw[:64], 16)
        y_coord = int(vrf_pk_raw[64:], 16)
        vrf_pk = (x_coord, y_coord)

        # 验证签名
        sigma_valid = False
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            vrf_pk_bytes = _point_to_bytes(vrf_pk)
            signature_bytes = bytes.fromhex(sigma_pk_hex)
            state.pki_pk.verify(
                signature_bytes,
                vrf_pk_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            sigma_valid = True
        except Exception:
            sigma_valid = False

        return jsonify({
            'success': True,
            'sigma_valid': sigma_valid,
            'message': 'σ_pk验证通过' if sigma_valid else 'σ_pk验证失败'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def status():
    """获取服务状态"""
    return jsonify({
        'initialized': state.vrf_pk is not None,
        'has_pki': state.pki_pk is not None,
        'stored_proofs': len(state.proof_store)
    })

@app.route('/api/reset', methods=['POST'])
def reset():
    """重置所有状态"""
    state.reset()
    session.clear()
    return jsonify({'success': True, 'message': '已重置'})

# ──────────────────────────────────────────────
# 主程序入口
# ──────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  🔐 EC-VRF 公平性验证后端服务")
    print("=" * 60)
    print(f"  监听地址: http://127.0.0.1:5000")
    print(f"  API文档:")
    print(f"    POST /api/init      - PKI初始化")
    print(f"    POST /api/evaluate  - VRF抽取")
    print(f"    POST /api/challenge - 质疑返回证明")
    print(f"    POST /api/verify    - 验证")
    print(f"    GET  /api/status    - 服务状态")
    print(f"    POST /api/reset     - 重置")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)