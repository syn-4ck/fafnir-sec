# Dockerfile vulnerable para propósitos educativos

# Vulnerabilidad 1: Uso de una imagen base obsoleta
FROM ubuntu:14.04

# Vulnerabilidad 2: Actualizaciones no realizadas
RUN apt-get update && apt-get install -y \
    software-properties-common

# Vulnerabilidad 3: Creación de usuario privilegiado
RUN useradd -m -s /bin/bash admin

# Vulnerabilidad 4: Exposición innecesaria de puertos
EXPOSE 21

# Vulnerabilidad 5: Copia de archivos sensibles directamente en la imagen
COPY secret-key.txt /home/admin/secret-key.txt

# Vulnerabilidad 6: Ejecución de comandos directamente en el Dockerfile
RUN echo "Clave secreta = mysecret" >> /home/admin/secrets.txt

# Comando de inicio de la aplicación
CMD ["./start.sh"]
