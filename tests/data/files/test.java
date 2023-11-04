import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class EjemploVulnerabilidades {

    // Vulnerabilidad 1: Inyección de SQL
    public void buscarUsuario(String nombre) throws SQLException {
        String consulta = "SELECT * FROM usuarios WHERE nombre = '" + nombre + "';";
        // Realizar la consulta a la base de datos
    }

    // Vulnerabilidad 2: Cross-Site Scripting (XSS)
    public void mostrarMensaje(String mensaje) {
        System.out.println("<div>" + mensaje + "</div>");
    }

    // Vulnerabilidad 3: Uso de contraseñas débiles
    public void autenticarUsuario(String usuario, String contrasena) {
        if (usuario.equals("admin") && contrasena.equals("123456")) {
            System.out.println("Acceso concedido");
        } else {
            System.out.println("Credenciales incorrectas");
        }
    }

    // Vulnerabilidad 4: No validar entrada del usuario
    public void calcularSuma() {
        System.out.print("Ingrese el primer número: ");
        int num1 = Integer.parseInt(System.console().readLine());
        System.out.print("Ingrese el segundo número: ");
        int num2 = Integer.parseInt
