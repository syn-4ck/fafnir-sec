
password = "ajklawejrkl42348swfgkg"

# Ejemplo de código con vulnerabilidades

# Vulnerabilidad 1: Inyección de SQL
def buscar_usuario(nombre):
    consulta = "SELECT * FROM usuarios WHERE nombre = '" + nombre + "';"
    # Realizar la consulta a la base de datos

# Vulnerabilidad 2: Cross-Site Scripting (XSS)
def mostrar_mensaje(mensaje):
    print("<div>" + mensaje + "</div>")

# Vulnerabilidad 3: Uso de contraseñas débiles
def autenticar_usuario(usuario, contrasena):
    if usuario == "admin" and contrasena == "123456":
        print("Acceso concedido")
    else:
        print("Credenciales incorrectas")

# Vulnerabilidad 4: No validar entrada del usuario
def calcular_suma():
    num1 = input("Ingrese el primer número: ")
    num2 = input("Ingrese el segundo número: ")
    suma = num1 + num2
    print("La suma es: " + suma)

# Vulnerabilidad 5: Uso de funciones desactualizadas
import md5  # md5 es considerado débil, se debería usar algo más seguro como hashlib

def hash_password(password):
    return md5.new(password).hexdigest()

# Puedes utilizar este código como ejemplo para probar tu aplicación SAST y asegurarte de que puede identificar estas vulnerabilidades comunes.
