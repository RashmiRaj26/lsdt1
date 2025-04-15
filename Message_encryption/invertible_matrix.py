import numpy as np

def is_invertible_f2(matrix):
    try:
        _ = np.linalg.inv(matrix % 2)
        return True
    except np.linalg.LinAlgError:
        return False

def generate_invertible_cyclic_matrix(t):
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

if __name__ == "__main__":
    t = int(input("Enter t (≥ 2): "))
    B = generate_invertible_cyclic_matrix(t)

    print("\nGenerated Matrix B over F2:")
    for row in B:
        print(" ".join(map(str, row)))

    try:
        inv = np.linalg.inv(B % 2)
        print("\n✅ Matrix is invertible over F2.")
    except np.linalg.LinAlgError:
        print("\n❌ Matrix is NOT invertible over F2.")
