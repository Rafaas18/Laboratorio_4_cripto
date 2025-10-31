try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import base64
    import sys
except ImportError:
    print("Error: Se requiere la librería 'pycryptodome'.")
    print("Por favor, instálala ejecutando: pip install pycryptodome")
    sys.exit()

# --- Constantes de color (opcional, para mejor lectura) ---
VERDE = '\033[92m'
ROJO = '\033[91m'
AMARILLO = '\033[93m'
AZUL = '\033[94m'
RESET = '\033[0m'


def solicitar_datos():
    print("=== Laboratorio 4: Cifrado Simétrico ===\n")

    texto = input("Ingrese el texto a cifrar (para los 3 algoritmos): ")

    print("\n--- Entradas para DES ---")
    key_des = input("Ingrese la clave para DES: ")
    iv_des = input("Ingrese el IV para DES: ")

    print("\n--- Entradas para 3DES ---")
    key_3des = input("Ingrese la clave para 3DES: ")
    iv_3des = input("Ingrese el IV para 3DES: ")

    print("\n--- Entradas para AES-256 ---")
    key_aes = input("Ingrese la clave para AES-256: ")
    iv_aes = input("Ingrese el IV para AES-256: ")

    print("\n--- Datos Ingresados (revisión) ---")
    print(f"Texto a cifrar: {texto}")
    print(f"Datos DES: Key='{key_des}', IV='{iv_des}'")
    print(f"Datos 3DES: Key='{key_3des}', IV='{iv_3des}'")
    print(f"Datos AES: Key='{key_aes}', IV='{iv_aes}'")

    return texto, key_des, iv_des, key_3des, iv_3des, key_aes, iv_aes


def ajustar_bytes(dato_str: str, longitud_deseada: int, tipo: str) -> bytes:
    try:
        datos_en_bytes = dato_str.encode('utf-8')
        largo_actual = len(datos_en_bytes)

        if largo_actual > longitud_deseada:
            print(f"  {AMARILLO}[Ajuste {tipo}]: Entrada larga, truncando a {longitud_deseada} bytes.{RESET}")
            return datos_en_bytes[:longitud_deseada]

        elif largo_actual < longitud_deseada:
            bytes_faltantes = longitud_deseada - largo_actual
            relleno = get_random_bytes(bytes_faltantes)
            print(f"  {AMARILLO}[Ajuste {tipo}]: Entrada corta, rellenando con {bytes_faltantes} bytes aleatorios.{RESET}")
            return datos_en_bytes + relleno

        else:
            print(f"  {VERDE}[Ajuste {tipo}]: Longitud correcta ({longitud_deseada} bytes).{RESET}")
            return datos_en_bytes

    except Exception as e:
        print(f"{ROJO}Error fatal al ajustar bytes: {e}{RESET}")
        sys.exit()


def procesar_cifrado_simetrico(nombre_algo: str, cipher_class, modo, mensaje_str: str, clave_bytes: bytes, iv_bytes: bytes):
    try:
        # --- Cifrado ---
        cipher_encrypt = cipher_class.new(clave_bytes, modo, iv_bytes)
        mensaje_bytes = mensaje_str.encode('utf-8')
        mensaje_padded = pad(mensaje_bytes, cipher_class.block_size)
        texto_cifrado_bytes = cipher_encrypt.encrypt(mensaje_padded)

        texto_cifrado_b64 = base64.b64encode(texto_cifrado_bytes).decode('utf-8')
        print(f"\n{AZUL}=== {nombre_algo} ==={RESET}")
        print(f"Texto Original:   {mensaje_str}")
        print(f"{AMARILLO}Texto Cifrado ({nombre_algo} en Base64): {texto_cifrado_b64}{RESET}")

        # --- Descifrado ---
        cipher_decrypt = cipher_class.new(clave_bytes, modo, iv_bytes)
        datos_descifrados_padded = cipher_decrypt.decrypt(texto_cifrado_bytes)
        datos_descifrados_bytes = unpad(datos_descifrados_padded, cipher_class.block_size)
        datos_descifrados_str = datos_descifrados_bytes.decode('utf-8')

        print(f"{VERDE}Texto Descifrado: {datos_descifrados_str}{RESET}")

    except Exception as e:
        print(f"{ROJO}Error en {nombre_algo}: {e}{RESET}")


if __name__ == "__main__":
    # --- Solicitar datos ---
    texto, k_des, i_des, k_3des, i_3des, k_aes, i_aes = solicitar_datos()

    # --- Ajustar claves e IVs ---
    clave_des_final = ajustar_bytes(k_des, 8, "Clave DES")
    iv_des_final = ajustar_bytes(i_des, 8, "IV DES")

    clave_3des_final = ajustar_bytes(k_3des, 24, "Clave 3DES")
    iv_3des_final = ajustar_bytes(i_3des, 8, "IV 3DES")

    clave_aes_final = ajustar_bytes(k_aes, 32, "Clave AES-256")
    iv_aes_final = ajustar_bytes(i_aes, 16, "IV AES-256")

    # --- Procesar cifrado y descifrado ---
    procesar_cifrado_simetrico("DES", DES, DES.MODE_CBC, texto, clave_des_final, iv_des_final)
    procesar_cifrado_simetrico("3DES", DES3, DES3.MODE_CBC, texto, clave_3des_final, iv_3des_final)
    procesar_cifrado_simetrico("AES-256", AES, AES.MODE_CBC, texto, clave_aes_final, iv_aes_final)
    
    print(f"\n{VERDE}¡Proceso completado exitosamente!{RESET}")
    sys.exit(0)  # Termina el programa después de completar todas las operaciones



#:D#


