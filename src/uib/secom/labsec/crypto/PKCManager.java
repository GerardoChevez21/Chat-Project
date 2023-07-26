/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uib.secom.labsec.crypto;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;





/**
 *
 * @author Gerard
 */
public class PKCManager {

    private String path;//Ruta del archivo PKCS12
    private char[] password;//Contraseña del contenedor PKCS12
   

    public PKCManager(String path, char[] password) {
        this.path = path;
        this.password = password;
    }
    
   //Obtener la clave privada asociada a una clave pública de un certificado 
    public PrivateKey get_private_key(){
        try{
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(path), password);
            Enumeration<String> aliases = keyStore.aliases();    
            String alias = (String) aliases.nextElement();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
            return privateKey;
        }catch(IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Obtención del certificado codificado en Base64
    public String get_certificate_Base64() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(path), password);
            Enumeration<String> aliases = keyStore.aliases();
            String alias = (String) aliases.nextElement();
            Certificate certificate = keyStore.getCertificate(alias);
            byte[] certificate_DER = certificate.getEncoded();
            String certificate_Base64 = Base64.getEncoder().encodeToString(certificate_DER);
            return certificate_Base64;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println(e);
        }
        return null;
    }
    
    //Obtención de un certificado en formato X509 a partir de un byte[]
    public X509Certificate get_certificate_X509(byte[] certificate_Base64) {
        
        try{
            byte[] certificate_DER = Base64.getDecoder().decode(certificate_Base64);
            InputStream in = new ByteArrayInputStream(certificate_DER);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate_X509 = (X509Certificate)certificateFactory.generateCertificate(in);
            return certificate_X509;
        }catch(CertificateException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Obtención de la clave pública de un certificado
    public PublicKey get_public_key(X509Certificate certificate){
        try{
            PublicKey publicKey=certificate.getPublicKey();
            return publicKey;
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    
    //Obtener un byte[] con la clave pública de la CA del certificado codificada en Base64
    public byte[] get_CA_pubKey(){
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(path), password);
            Enumeration<String> aliases=keyStore.aliases();
            Certificate[] certificateChain = keyStore.getCertificateChain((String) aliases.nextElement());
            PublicKey pubKey = certificateChain[1].getPublicKey();
            byte[] pubKey_Base64 = Base64.getEncoder().encode(pubKey.getEncoded());
            return pubKey_Base64;
        } catch (Exception e) {
            System.out.println(e);
        } 
        return null;
    }
    
    //Verificar el certificado
    public boolean certificate_valid(byte[] certificate_Base64,byte[] CApubKey, String CN) throws CertificateExpiredException, CertificateNotYetValidException{
        try {
            X509Certificate certificate= get_certificate_X509(certificate_Base64);
            certificate.checkValidity();//Verificación del periodo de validez
            boolean[] keyUsage = certificate.getKeyUsage();
            //Verificación del uso de la clave pública(firma digital y cifrado de claves simétricas)
            if(!(keyUsage[0]&&keyUsage[2])){
                System.out.println("Uso de clave no válido");
                return false;
            }
            //Verificación del campo CN
            if(!(certificate.getSubjectDN().getName().equals("CN="+CN))){
                System.out.println("Subject no válido");
                return false;
            }
            KeyFactory factory = KeyFactory.getInstance("RSA"); 
            PublicKey key = factory.generatePublic(new X509EncodedKeySpec(CApubKey));
            certificate.verify(key);//Verificación de la firma 
            return true;
        } catch (Exception e) {
            System.out.println(e);
        } 
        return false;
    }

}
