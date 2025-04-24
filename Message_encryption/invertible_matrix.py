# matrix_utils.py
import numpy as np

def is_invertible_f2(matrix):
    try:
        _ = np.linalg.inv(matrix % 2)
        return True
    except np.linalg.LinAlgError:
        return False

def generate_cyclic_matrix(t):
    if t == 2:
        B = np.array([[0, 1],
                      [1, 0]], dtype=np.uint8)
    elif t == 3:
        B = np.array([[1, 1, 1],
                      [1, 1, 0],
                      [1, 0, 1]], dtype=np.uint8)
    elif t >= 4:
        gen = [0] * t
        gen[0] = 1
        if t > 2:
            gen[2] = 1
        gen[-1] = 1

        B = []
        for i in range(t):
            row = gen[-i:] + gen[:-i]
            B.append(row)
        B = np.array(B, dtype=np.uint8)
    else:
        raise ValueError("t must be ≥ 2")

    return B % 2

def generate_invertible_cyclic_matrix(t):
    B = generate_cyclic_matrix(t)
    if not is_invertible_f2(B):
        raise ValueError("Generated matrix is not invertible over F2.")
    return B
