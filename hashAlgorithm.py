def calc_hash(data: str) -> int:
    """
    FNV-1a hash algorithm implementation in Python.
    Equivalent to the C function:
    
    unsigned int calcHash(const char *data) {
        unsigned int hash = 0x811C9DC5;
        while (*data) {
            hash ^= (unsigned char)(*data);
            hash *= 0x01000193;
            data++;
        }
        return hash;
    }
    """
    if not isinstance(data, str):
        raise TypeError("Input must be a string")
    
    hash_value = 0x811C9DC5  # FNV-1a initial value (32-bit)
    fnv_prime = 0x01000193   # FNV-1a prime (32-bit)
    
    for char in data:
        # Convert character to its ASCII value (0-255)
        byte = ord(char)
        # XOR with the current byte
        hash_value ^= byte
        # Multiply by FNV prime
        hash_value *= fnv_prime
        # Keep it 32-bit (simulate unsigned int overflow)
        hash_value &= 0xFFFFFFFF
    
    return hash_value

if __name__ == "__main__":
    test_strings = [
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateThread",
        "Hello, World!"
    ]
    
    for s in test_strings:
        print(f"'{s}': 0x{calc_hash(s):08X}")