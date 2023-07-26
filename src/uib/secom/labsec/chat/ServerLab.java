package uib.secom.labsec.chat;

import uib.secom.labsec.crypto.signature;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import uib.secom.labsec.crypto.AESCipher;
import uib.secom.labsec.crypto.PKCManager;
import uib.secom.labsec.crypto.RSACipher;

public class ServerLab {

    private static ServerSocket serverSocket;	// socket used by server to accept connections from clients
    private static Socket clientSocket;			// socket used by server to send and receive data from client
    private static DataInputStream dataInput;	// object to read data from socket
    private static DataOutputStream dataOutput;	// object to write data into socket
    private static int serverPort;

    private static final String ROLEMain = "BOB";
    private static final String ROLEClient = "ALICE";

    private static final String CLOSEWORD = "FINALIZAR";
    private static boolean chatOpen = true;

    private static Scanner scanner;
    private static String writer;
    
    //Ruta del archivo PKCS12
    private static final String path="";
    //Contraseña del archivo PKCS12
    private static char[] password;
    private static AESCipher cipher;
    private static PublicKey AlicePubKey;
    private static PrivateKey myPrivateKey;
    
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Default port number: 8000");
            serverPort = 8000;
        } else {
            serverPort = Integer.parseInt(args[0]);
        }

        try {
            serverSocket = new ServerSocket(serverPort);
            log("Esperando conexiones en el puerto: " + serverPort + " ... ");
            clientSocket = serverSocket.accept();
            log("Conexión establecida con el cliente ... ");
            dataOutput = new DataOutputStream(clientSocket.getOutputStream());
            dataInput = new DataInputStream(clientSocket.getInputStream());

            Thread sender = new Thread(new Runnable() {
                public void run() {
                    try {
                        send_certificate();//Enviamos el certificado al cliente
                        send_CApublicKey();//Enviamos la clave pública de la Autoridad de certificación del certificado
                        while (chatOpen) {
                            scanner = new Scanner(System.in);
                            writer = scanner.nextLine();
                            if (!writer.equals(CLOSEWORD)) {
                                sendData(writer);
                            } else {
                                sendData(writer);
                                log("---- CHAT ENDED BY " + ROLEMain + " ----");
                                chatOpen = false;
                                closeAll();
                                System.exit(0);
                            }
                        }
                        closeAll();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        log("---- ERROR --> " + e.toString());
                        System.exit(0);
                        e.printStackTrace();
                    }
                }
            });
            sender.start();

            Thread receiver = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        receiveKeyIV();//Recibimos la clave simétrica e IV generados por Alice
                        receiveAlicePubKey_Password();//Recibimos la clave pública y contraseña de Alice
                        while (listenData(clientSocket)) {
                        }
                        closeAll();
                        System.exit(0);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        log("---- Chat ended --> " + e.toString());
                        closeAll();
                        System.exit(0);
                        e.printStackTrace();
                    }
                }
            });
            receiver.start();

        } catch (IOException e) {
            log("java.net.ConnectException: Connection refused)");
            System.exit(0);
        }
    }

    public static boolean listenData(Socket socket) throws IOException {
        byte[] dataReceived = new byte[dataInput.readInt()];
        dataInput.read(dataReceived);
        textChat("   Data encrypted received from " + ROLEClient + ": " + new String(dataReceived));
        byte[] data=new byte[dataReceived.length-344];
        System.arraycopy(dataReceived, 0, data, 0, data.length);
        byte[] dataReceivedDecrypted=cipher.decrypt(Base64.getDecoder().decode(data));//Obtenemos los datos descifrados
        byte[] signature=new byte[344];//Longitud de la firma fija de 344 bytes en Base64
        for(int i=0;i<signature.length;i++){
            signature[i]=dataReceived[data.length+i];//Obtenemos la firma
        }
        signature sign= new signature("SHA256withRSA");
   
        textChat("   Data received from " + ROLEClient + ": " + new String(Base64.getDecoder().decode(Base64.getEncoder().encode(dataReceivedDecrypted))));
        //Palabra de finalización o no se verifica la firma
        if (new String(dataReceived).equals(CLOSEWORD) || !(sign.verify_Signature(AlicePubKey, Base64.getDecoder().decode(signature),dataReceivedDecrypted))) {
            log("---- CHAT ENDED BY " + ROLEMain + " ----");//Si no se verifica la firma o se ha recibido la palabra de finalización
            return false;
        } 
        return true;
    }

    private static void sendData(String datos) throws IOException {
        textChat(datos);
        if (datos != null) {
            byte[] dataToSend = datos.getBytes();
            byte[] dataToSendEncrypted = cipher.encrypt(dataToSend);//Ciframos los datos 
            byte[] dataToSendEncrypted_Base64=Base64.getEncoder().encode(dataToSendEncrypted);
            byte[] Signature_Base64=get_signature_Base64(dataToSend);//Obtenemos la firma digital en Base64
            byte[] result = new byte[dataToSendEncrypted_Base64.length + Signature_Base64.length];//Las unificamos en un byte[]
            System.arraycopy(dataToSendEncrypted_Base64, 0, result, 0, dataToSendEncrypted_Base64.length);
            System.arraycopy(Signature_Base64, 0, result, dataToSendEncrypted_Base64.length, Signature_Base64.length);
            dataOutput.writeInt(result.length);
            dataOutput.write(result);
            dataOutput.flush();
            textChat("   Data encrypted and signature sent for " + ROLEClient + ": " + new String(result));
        }
    }

    private static void closeAll() {
        try {
            dataOutput.close();
            dataInput.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException ex) {
            log("Exception Chat " + ROLEMain + ".closeAll --> " + ex);
        }
    }

    private static void log(String logText) {
        System.out.println(ROLEMain + " LOG CHAT: " + logText);
    }

    private static void textChat(String logText) {
        // TODO Auto-generated method stub
        System.out.println(ROLEMain + " TEXT CHAT: " + logText);
    }
    
    private static void send_certificate(){
        try{
            System.out.println("Introduce la contraseña del archivo PKCS12:");
            scanner = new Scanner(System.in);
            writer = scanner.nextLine();
            password=writer.toCharArray();
            PKCManager PKCS12=new PKCManager(path,password);
            byte[] dataToSend = PKCS12.get_certificate_Base64().getBytes();//Obtenemos el certificado codificado Base64
            dataOutput.writeInt(dataToSend.length);
            dataOutput.write(dataToSend);//Enviamos el certificado 
            dataOutput.flush();
            System.out.println("Certificado enviado!!!");
        }catch(IOException e){
            System.out.println(e);
        }
    }
    
    //Enviar a Alice la clave pública de la CA del certificado
    private static void send_CApublicKey(){
        try{
            PKCManager PKCS12=new PKCManager(path,password);
            byte[] CApubKey = PKCS12.get_CA_pubKey();//Obtenemos la clave pública de la CA del certificado
            dataOutput.writeInt(CApubKey.length);
            dataOutput.write(CApubKey);//Enviamos la clave pública 
            dataOutput.flush();
        }catch(IOException e){
            System.out.println(e);
        }
    }
    
    private static void receiveKeyIV(){
        try {
            byte[] dataReceived = new byte[dataInput.readInt()];
            dataInput.read(dataReceived);
            byte[] secretKey_IV=secretKey_IV(dataReceived);//Obtenemos la clave e IV
            System.out.println("Clave e IV recibidos!!!");
            init_cipher(secretKey_IV);
        } catch (IOException ex) {
            Logger.getLogger(ServerLab.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private static byte[] secretKey_IV(byte[] dataReceived){
        try{
            PKCManager PKCS12=new PKCManager(path,password);
            myPrivateKey=PKCS12.get_private_key();
            RSACipher secretKey_IV_encypted=new RSACipher("RSA/ECB/PKCS1Padding");
            byte[] dataReceived_DER=Base64.getDecoder().decode(dataReceived);//Obtenemos los datos en codificación DER
            byte[] secretKey_IV_decrypted= secretKey_IV_encypted.decrypt(myPrivateKey, dataReceived_DER);//Desciframos
            return secretKey_IV_decrypted;
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    
    //Inicializamos el "AESCipher" con los parámetros recibidos
    private static void init_cipher(byte[] secretKey_IV){
        byte[] secretKey = new byte[16];
        byte[] IV = new byte[16];
        System.arraycopy(secretKey_IV, 0, secretKey, 0, secretKey.length);
        for(int i=0;i<IV.length;i++){
            IV[i]=secretKey_IV[secretKey.length+i];
        }
        cipher=new AESCipher("AES",128,16);
        cipher.init_SecretKeySpec_IVparameterSpec(secretKey, IV);
    }
    
    private static void receiveAlicePubKey_Password(){
        try {
            byte[] dataReceived = new byte[dataInput.readInt()];
            dataInput.read(dataReceived);
            byte[] Password_AlicePubKey=get_Password_AlicePubKey(dataReceived);
            byte[] passw = new byte[12];
            byte[] AlicePublicKey = new byte[Password_AlicePubKey.length-passw.length];
            System.arraycopy(Password_AlicePubKey, 0, passw, 0, passw.length);
            if(!(Arrays.equals("Tve5ju7-gHps".getBytes(), passw))){
                System.out.println("Autenticación de Alice fallida, cerrando conexión...");
                log("---- CHAT ENDED BY " + ROLEClient + " ----");
                closeAll();
            }
            System.out.println("Autenticación de Alice correcta!!!");
            //Obtener la clave pública de Alice
            for(int i=0;i<AlicePublicKey.length;i++){
                AlicePublicKey[i]=Password_AlicePubKey[password.length+i];
            }
            //Generar clave pública a partir de un byte[]
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(AlicePublicKey);
            AlicePubKey = keyFactory.generatePublic(publicKeySpec);
            System.out.println("Clave pública de Alice recibida correctamente!!!");
            System.out.println("Puedes iniciar el intercambio de mensajes, para finalizar introduce "+"\""+CLOSEWORD+"\"");
        } catch (Exception e) {
            System.out.println(e);
        } 
    }
    
    //Descifrar los datos especificados para obtener un byte[] con la contraseña y la clave pública de Alice
    private static byte[] get_Password_AlicePubKey(byte[] dataEncrypted){
        byte[] dataEncrypted_DER=Base64.getDecoder().decode(dataEncrypted);
        byte[] Password_AlicePubKey = cipher.decrypt(dataEncrypted_DER);
        return Password_AlicePubKey;
    }
    
    //Firmar con clave privada los datos especificados
    public static byte[] get_signature_Base64(byte[] dataToSign){
        signature sign=new signature("SHA256withRSA");
        byte[] Signature = sign.get_Signature(myPrivateKey, dataToSign);
        byte[] Signature_Base64=Base64.getEncoder().encode(Signature);
        return Signature_Base64;
    }
}
