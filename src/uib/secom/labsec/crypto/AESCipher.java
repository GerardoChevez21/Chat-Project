/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uib.secom.labsec.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



/**
 *
 * @author Gerard
 */
public class AESCipher {
    
    protected static String ALGORITHM;//Algorítmo de cifrado
    private final String ALGORITHM_MODE="AES/CBC/PKCS5Padding";//Modo utilizado
    private final int keyLength;//Longitud de la clave
    private final int ivLength;//Longitud del IV
    private IvParameterSpec IVparameterSpec;//Parámetros del IV
    private SecretKeySpec aesKeySpec;//Parámetros de la clave
    private byte[] key;
    
    
    public AESCipher(String Algorithm,int keylength,int iv_length){
        ALGORITHM=Algorithm;
        this.keyLength=keylength;
        this.ivLength=iv_length;
        this.IVparameterSpec=null;
        this.aesKeySpec=null;
    }
    
    //Genera clave simétrica
    public byte[] generate_Key() {
        try{
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(keyLength, new SecureRandom());
            SecretKey aesKey = keyGen.generateKey();
            byte[] aesKeyBytes = aesKey.getEncoded();
            this.aesKeySpec = new SecretKeySpec(aesKeyBytes, 0,16 , "AES");
            key=aesKeyBytes;
            return aesKeyBytes;
        }catch(NoSuchAlgorithmException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Genera IV
    public byte[] generate_IV(){
        try{
            byte[] iv = SecureRandom.getSeed(ivLength);
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            this.IVparameterSpec=ivspec;
            return ivspec.getIV();
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    
    //Inicializa los parámetros de la clave e IV
    public void init_SecretKeySpec_IVparameterSpec(byte[] SecretKey,byte[] IV){
        this.aesKeySpec = new SecretKeySpec(SecretKey, 0,16 , "AES");
        key=SecretKey;
        this.IVparameterSpec= new IvParameterSpec(IV);
    }
    
    //Cifrar datos
    public byte[] encrypt(byte[] data_to_be_encrypted){
        try{
        Cipher cipher=Cipher.getInstance(ALGORITHM_MODE);
        cipher.init(1,aesKeySpec,IVparameterSpec);
        byte[] data_encrypted=cipher.doFinal(data_to_be_encrypted);
        return data_encrypted;
        }catch(InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Descifrar datos
    public byte[] decrypt(byte[] data_to_be_decrypted){ 
        try{
        Cipher cipher=Cipher.getInstance(ALGORITHM_MODE);
        cipher.init(2,aesKeySpec,IVparameterSpec);
        byte[] data_decrypted=cipher.doFinal(data_to_be_decrypted);
        return data_decrypted;
        }catch(InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
            System.out.println(e);
        }
        return null;
    }
    
    //Obtener la clave secreta
    public byte[] get_Key(){
        System.out.println(Base64.getEncoder().encode(key));
        return key;
    }
}
