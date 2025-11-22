import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class SecureFileEncryptor extends JFrame {
    private JTextField passwordField;
    private JTextField fileField;
    private JButton chooseBtn, encryptBtn, decryptBtn;

    public SecureFileEncryptor() {
        super("Secure File Encryptor (AES-256)");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(600, 150);
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        fileField = new JTextField(35);
        chooseBtn = new JButton("Choose File");
        passwordField = new JPasswordField(30);
        encryptBtn = new JButton("Encrypt");
        decryptBtn = new JButton("Decrypt");

        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        add(new JLabel("File:"), c);
        c.gridy=1;
        add(fileField, c);
        c.gridx=2; c.gridwidth=1;
        add(chooseBtn, c);

        c.gridx=0; c.gridy=2; c.gridwidth=1;
        add(new JLabel("Password:"), c);
        c.gridx=1; c.gridwidth=2;
        add(passwordField, c);

        c.gridx=0; c.gridy=3;
        add(encryptBtn, c);
        c.gridx=1;
        add(decryptBtn, c);

        chooseBtn.addActionListener(e -> chooseFile());
        encryptBtn.addActionListener(e -> encryptAction());
        decryptBtn.addActionListener(e -> decryptAction());
    }

    private void chooseFile(){
        JFileChooser chooser = new JFileChooser();
        int ok = chooser.showOpenDialog(this);
        if(ok == JFileChooser.APPROVE_OPTION){
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void encryptAction(){
        String path = fileField.getText().trim();
        if(path.isEmpty()) { showErr("Select file."); return; }
        char[] pass = passwordField.getText().toCharArray();
        if(pass.length==0) { showErr("Enter password."); return; }
        try {
            byte[] input = Files.readAllBytes(Paths.get(path));
            byte[] out = encrypt(input, pass);
            Files.write(Paths.get(path + ".enc"), out);
            JOptionPane.showMessageDialog(this, "Encrypted to " + path + ".enc");
        } catch(Exception ex) { showErr(ex.getMessage()); ex.printStackTrace(); }
    }

    private void decryptAction(){
        String path = fileField.getText().trim();
        if(path.isEmpty()) { showErr("Select file."); return; }
        char[] pass = passwordField.getText().toCharArray();
        if(pass.length==0) { showErr("Enter password."); return; }
        try {
            byte[] input = Files.readAllBytes(Paths.get(path));
            byte[] out = decrypt(input, pass);
            String outPath = path.endsWith(".enc") ? path.substring(0, path.length()-4) + ".dec" : path + ".dec";
            Files.write(Paths.get(outPath), out);
            JOptionPane.showMessageDialog(this, "Decrypted to " + outPath);
        } catch(Exception ex) { showErr("Decryption failed: " + ex.getMessage()); ex.printStackTrace(); }
    }

    private void showErr(String msg){
        JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
    }

    // Format: [salt(16)][iv(16)][ciphertext]
    private static byte[] encrypt(byte[] plaintext, char[] password) throws Exception {
        byte[] salt = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);
        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(plaintext);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(salt);
        baos.write(iv);
        baos.write(ct);
        return baos.toByteArray();
    }

    private static byte[] decrypt(byte[] blob, char[] password) throws Exception {
        if(blob.length < 32) throw new IllegalArgumentException("Invalid file format.");
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        System.arraycopy(blob, 0, salt, 0, 16);
        System.arraycopy(blob, 16, iv, 0, 16);
        byte[] ct = new byte[blob.length - 32];
        System.arraycopy(blob, 32, ct, 0, ct.length);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ct);
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        int iter = 100_000;
        int keyLen = 256;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iter, keyLen);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static void main(String[] args){
        SwingUtilities.invokeLater(() -> {
            SecureFileEncryptor app = new SecureFileEncryptor();
            app.setVisible(true);
        });
    }
}
