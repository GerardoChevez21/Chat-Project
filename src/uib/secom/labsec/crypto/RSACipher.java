/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uib.secom.labsec.crypto;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author Gerard
 */
public class RSACipher {
    
    private final String ALGORITHM_MODE;//Modo del algorítmo
    private KeyPair keyPair;//Par de claves asimmétricas
    
    public RSACipher(String Algorithm){
        this.ALGORITHM_MODE=Algorithm;
    }
    
    //Genera un par de claves asimétricas
    public void generateKeyPair(String algorithm){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSACipher.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    public PublicKey getPublicKey(){
        return  keyPair.getPublic();
    }
    
    public PrivateKey getPrivateKey(){
        return  keyPair.getPrivate();
    }
    
    //Cifrar datos con una clave pública
    public byte[] encrypt(Key key,byte[] data_to_be_encrypted){
        try{
        Cipher cipher=Cipher.getInstance(ALGORITHM_MODE);
        cipher.init(1,key);
        byte[] data_encrypted=cipher.doFinal(data_to_be_encrypted);
        return data_encrypted;
        }catch(InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Descifrar datos con una clave privada
    public byte[] decrypt(Key key,byte[] data_to_be_decrypted){
        try{
        Cipher cipher=Cipher.getInstance(ALGORITHM_MODE);
        cipher.init(2,key);
        byte[] data_decrypted=cipher.doFinal(data_to_be_decrypted);
        return data_decrypted;
        }catch(InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
            System.out.println(e);
        }
        return null;
    }   
}
