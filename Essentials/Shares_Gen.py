import numpy as np
import math

# --- Step 1: Generate invertible cyclic matrix B on F2 ---
def generate_cyclic_matrix(t):
    if t == 2:
        B = np.array([[0,1],[1,1]], dtype=int)
    elif t == 3:
        B = np.array([[1,1,1],[1,1,0],[1,0,1]], dtype=int)
    else:
        gen = [1,0,1] + [0]*(t-4) + [1]
        B = np.zeros((t,t), dtype=int)
        B[0] = gen
        for i in range(1,t):
            B[i] = np.roll(B[i-1],1)
    return B

# --- Step 2: Split message into t blocks ---
def split_message(msg_bits, t):
    L = len(msg_bits)
    block_len = math.ceil(L / t)
    blocks = []
    for i in range(t):
        start = i * block_len
        end = start + block_len
        blk = msg_bits[start:end]
        if len(blk) < block_len:
            blk += [0] * (block_len - len(blk))  # pad last block
        blocks.append(np.array(blk, dtype=int))
    return blocks

# --- Step 3: Generate shares ---
def generate_shares(blocks, B):
    t = B.shape[0]
    # Add (t+1)-th row as XOR of all rows
    B_extended = np.vstack((B, np.bitwise_xor.reduce(B, axis=0)))

    print("\nExtended Matrix B_extended (used for shares):")
    print(B_extended)

    shares = []
    for row in B_extended:
        share = np.zeros_like(blocks[0])
        for i in range(t):
            share ^= row[i] * blocks[i]  # XOR over F2
        shares.append(share)
    return shares, B_extended

# --- GF2 matrix inverse ---
def gf2_inverse(A):
    n = A.shape[0]
    A = A.copy() % 2
    I = np.eye(n, dtype=int)

    for col in range(n):
        # Find pivot
        pivot = None
        for row in range(col, n):
            if A[row,col] == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is singular in GF2, cannot invert")
        # Swap rows
        if pivot != col:
            A[[col,pivot]] = A[[pivot,col]]
            I[[col,pivot]] = I[[pivot,col]]
        # Eliminate other rows
        for row in range(n):
            if row != col and A[row,col] == 1:
                A[row] = (A[row] + A[col]) % 2
                I[row] = (I[row] + I[col]) % 2
    return I

# --- Step 4: Reconstruction using selected shares ---
def reconstruct_blocks(selected_shares, selected_indices, B_extended, t):
    # Build B_sub using selected indices from B_extended
    B_sub = B_extended[selected_indices, :t]  # only first t columns
    print("\nB_sub matrix used for reconstruction:")
    print(B_sub)

    # Compute inverse over GF2
    B_inv = gf2_inverse(B_sub)
    print("\nInverse of B_sub over F2:")
    print(B_inv)

    block_len = len(selected_shares[0])

    # Reconstruct blocks
    blocks = []
    for bit_idx in range(block_len):
        s_col = np.array([selected_shares[i][bit_idx] for i in range(len(selected_shares))], dtype=int)
        blk_col = np.dot(B_inv, s_col) % 2
        blocks.append(blk_col)

    # Convert columns to rows (blocks)
    reconstructed_blocks = []
    for i in range(t):
        reconstructed_blocks.append(np.array([blocks[j][i] for j in range(block_len)], dtype=int))

    return reconstructed_blocks

# --- Main program ---
if __name__ == "__main__":
    msg_bits = list(map(int, input("Enter message bits (space separated 0/1): ").strip().split()))
    t = int(input("Enter number of shares t: "))

    # --- Split message into blocks ---
    blocks = split_message(msg_bits, t)
    print("\nMessage split into blocks:")
    for i,b in enumerate(blocks):
        print(f"Block {i}: {b}")

    # --- Generate cyclic matrix ---
    B = generate_cyclic_matrix(t)
    print("\nCyclic matrix B:\n", B)

    # --- Generate shares ---
    shares, B_extended = generate_shares(blocks, B)
    print("\nGenerated Shares:")
    for i, s in enumerate(shares):
        print(f"Share {i}: {s}")

    # --- Input which shares to use for reconstruction ---
    selected_indices = list(map(int, input(f"\nEnter {t} share indices to reconstruct (0 to {len(shares)-1}): ").strip().split()))
    selected_shares_input = [shares[i] for i in selected_indices]

    # --- Reconstruct message ---
    reconstructed_blocks = reconstruct_blocks(selected_shares_input, selected_indices, B_extended, t)
    reconstructed_msg = np.concatenate(reconstructed_blocks)[:len(msg_bits)]

    print("\nReconstructed Message Bits:")
    print(reconstructed_msg)
