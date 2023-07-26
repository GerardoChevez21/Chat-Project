package uib.secom.labsec.chat;

import uib.secom.labsec.crypto.signature;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import uib.secom.labsec.crypto.AESCipher;
import uib.secom.labsec.crypto.PKCManager;
import uib.secom.labsec.crypto.RSACipher;

public class ClientLab {

    private static Socket socketClient;			// socket used by client to send and recieve data from server
    private static DataInputStream dataInput;	// object to read data from socket
    private static DataOutputStream dataOutput;	// object to write data into socket
    private static int serverPort;
    private static InetAddress serverIP;

    private static final String ROLEMain = "ALICE";
    private static final String ROLEClient = "BOB";

    private static final String CLOSEWORD = "FINALIZAR";
    private static boolean chatOpen = true;

    private static Scanner scanner;
    private static String writer;

    private static final String CN="";
    private static AESCipher cipher;
    private static RSACipher RSAcipher;
    private static PublicKey BobPublicKey;

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Default port number: 8000");
            serverPort = 8000;
        } else {
            serverPort = Integer.parseInt(args[0]);
        }
        try {
            serverIP = InetAddress.getLocalHost();
        } catch (UnknownHostException e1) {
            // TODO Auto-generated catch block
            //e1.printStackTrace();
            System.exit(0);
        }
        try {
            textChat("Connect to IP --> " + serverIP + "  Port --> " + serverPort);
            socketClient = new Socket(serverIP, serverPort);
            dataOutput = new DataOutputStream(socketClient.getOutputStream());
            dataInput = new DataInputStream(socketClient.getInputStream());

            Thread sender = new Thread(new Runnable() {
                public void run() {
                    try {
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
                        log("ERROR --> " + e.toString());
                        System.exit(0);
                        //e.printStackTrace();
                    }
                }
            });

            sender.start();
            Thread receiver = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        receiveCertificate();//Obtenemos el certificado enviado por el servidor
                        send_Key_IV();//Enviamos la clave simétrica e IV
                        sendPassword_PublicKey();//Enviamos la contraseña y la clave pública creada
                        while (listenData(socketClient)) {

                        }
                        log("Server out of service");
                        closeAll();
                        System.exit(0);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        log("ERROR --> " + e.toString());
                        closeAll();
                        System.exit(0);
                    }
                }
            });
            receiver.start();
        } catch (IOException e) {
            log("ERROR --> " + e.toString());
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
        byte[] signature=new byte[344];
        for(int i=0;i<signature.length;i++){
            signature[i]=dataReceived[data.length+i];//Obtenemos la firma
        }
        signature sign= new signature("SHA256withRSA");
         
        textChat("   Data received from " + ROLEClient + ": " + new String(Base64.getDecoder().decode(Base64.getEncoder().encode(dataReceivedDecrypted))));
        //Palabra de finalización o no se verifica la firma
        if (new String(dataReceived).equals(CLOSEWORD) || !(sign.verify_Signature(BobPublicKey, Base64.getDecoder().decode(signature),dataReceivedDecrypted))) {
            log("---- CHAT ENDED BY " + ROLEClient + " ----");//Si no se verifica la firma o se ha recibido la palabra de finalización
            return false;
        }
        return true;
    }

    private static void sendData(String datos) throws IOException {
        textChat(datos);
        if (datos != null) {
            byte[] dataToSend = datos.getBytes();
            byte[] dataToSendEncrypted = cipher.encrypt(dataToSend);//Enviamos los datos encriptados
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
            socketClient.close();
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

    private static void receiveCertificate() {
        try {
            byte[] dataReceived = new byte[dataInput.readInt()];
            dataInput.read(dataReceived);
            BobPublicKey = get_public_key(dataReceived);//Obtenemos la clave pública del certificado
            PKCManager man=new PKCManager(null,null);
            //Verificamos el certificado recibido
            if(!(man.certificate_valid(dataReceived, Base64.getDecoder().decode(receiveCApublicKey()),CN))){
                System.out.println("Verificación del certificado fallida, cerrando conexión...");
                log("---- CHAT ENDED BY " + ROLEMain + " ----");
                closeAll();
            }
            System.out.println("Certificado recibido correctamente!!!");
        } catch (Exception e) {
            System.out.println(e);
        } 
    }
    
    //Obtener la clave pública de la CA 
    private static byte[] receiveCApublicKey(){
        try {
            byte[] dataReceived = new byte[dataInput.readInt()];
            dataInput.read(dataReceived);
            return dataReceived;
        } catch (IOException ex) {
            Logger.getLogger(ClientLab.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static void send_Key_IV() {
        try {
            System.out.println("Generando clave simétrica e IV...");
            byte[] Key_IV = generate_Key_IV();//Generamos la clave simétrica y el IV
            RSAcipher = new RSACipher("RSA/ECB/PKCS1Padding");
            //Ciframos la clave simétrica y el IV con la clave pública del servidor
            byte[] secretKey_IV_Encrypted = RSAcipher.encrypt(BobPublicKey, Key_IV);
            //Lo codificamos en Base64
            byte[] secretKey_IV_Encrypted_Base64 = Base64.getEncoder().encode(secretKey_IV_Encrypted);
            dataOutput.writeInt(secretKey_IV_Encrypted_Base64.length);
            //Lo enviamos al servidor
            dataOutput.write(secretKey_IV_Encrypted_Base64);
            dataOutput.flush();
            System.out.println("Clave e IV enviados!!!");
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    //Obtener la clave pública a partir de un byte[] con el certificado
    private static PublicKey get_public_key(byte[] dataReceived) {
        try {
            PKCManager manager = new PKCManager(null, null);
            X509Certificate certificate = manager.get_certificate_X509(dataReceived);//Obtenemos el certificado X509
            PublicKey PublicKey = manager.get_public_key(certificate);//Obtenemos la clave pública
            return PublicKey;
        } catch (Exception e) {
            System.out.println(e);
        }
        return null;
    }

    private static byte[] generate_Key_IV() {
        try {
            cipher = new AESCipher("AES", 128, 16);
            byte[] secretKey = cipher.generate_Key();//Generamos la clave simétrica
            byte[] IV = cipher.generate_IV();//Generamos el IV
            byte[] result = new byte[secretKey.length + IV.length];//Las unificamos en un byte[]
            System.arraycopy(secretKey, 0, result, 0, secretKey.length);
            System.arraycopy(IV, 0, result, secretKey.length, IV.length);
            return result;
        } catch (Exception e) {
            System.out.println(e);
        }
        return null;
    }
    
    //Enviar a Bob la contraseña yla clave pública generada
    private static void sendPassword_PublicKey() {
        try {
            RSAcipher.generateKeyPair("RSA");//Genera par de claves RSA
            System.out.println("Generando par de claves...");
            PublicKey publicKey = RSAcipher.getPublicKey();
            byte[] publicKeyBytes = publicKey.getEncoded();
            String pass = "Tve5ju7-gHps";//Contraseña del usuario
            byte[] passBytes = pass.getBytes();
            byte[] result = new byte[publicKeyBytes.length + passBytes.length];
            System.arraycopy(passBytes, 0, result, 0, passBytes.length);
            System.arraycopy(publicKeyBytes, 0, result, passBytes.length, publicKeyBytes.length);
            byte[] pass_PublicKey_Encrypted = cipher.encrypt(result);
            byte[] pass_PublicKey_Encrypted_Base64 = Base64.getEncoder().encode(pass_PublicKey_Encrypted);
            dataOutput.writeInt(pass_PublicKey_Encrypted_Base64.length);
            //Lo enviamos al servidor
            dataOutput.write(pass_PublicKey_Encrypted_Base64);
            dataOutput.flush();
            System.out.println("Contraseña y clave pública enviadas!!!");
            System.out.println("Puedes iniciar el intercambio de mensajes, para finalizar introduce "+"\""+CLOSEWORD+"\"");
        } catch (IOException ex) {
            Logger.getLogger(ClientLab.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Firmar con clave privada los datos especificados
    public static byte[] get_signature_Base64(byte[] dataToSign){
        signature sign=new signature("SHA256withRSA");
        byte[] Signature = sign.get_Signature(RSAcipher.getPrivateKey(), dataToSign);
        byte[] Signature_Base64=Base64.getEncoder().encode(Signature);
        return Signature_Base64;
    }

}
