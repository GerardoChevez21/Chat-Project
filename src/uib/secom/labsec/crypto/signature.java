/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uib.secom.labsec.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author Gerard
 */
public class signature {

    private final String SignatureAlgorithm;
    
    public signature(String SignatureAlgorithm){
        this.SignatureAlgorithm=SignatureAlgorithm;
    }
    
    //Crea una firma digital a partir de una clave privada y los datos a firmar, usando el algorítmo de hash anteriormente especificado
    public byte[] get_Signature(PrivateKey privateKey,byte[]dataToBeSigned){
        try {
            Signature signature = Signature.getInstance(SignatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(dataToBeSigned);
            byte[] signatureBytes=signature.sign();
            return signatureBytes;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    //Verifica la firma digital a partir de la clave pública corespondiente a la clave privada utilizada para la firma juntamente a los datos firmados
    public boolean verify_Signature(PublicKey publicKey,byte[]sign, byte[] data){
        try {
            Signature signature = Signature.getInstance(SignatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(data);
            boolean signatureBytes=signature.verify(sign);
            return signatureBytes;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(signature.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
}
