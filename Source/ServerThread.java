

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Random;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


public class ServerThread implements Runnable
{
	//I/O variables 
	protected ObjectInputStream inFromClient;
	protected ObjectOutputStream outToClient;
	protected Socket threadSock;
	protected Thread listener;
	private Random rnd = new Random();
	
	//List of all server threads active.
	protected static Vector<ServerThread> serverThreadList = new Vector<ServerThread>();//its static so the same one is used for all.
	
	//RFC Compliant HMAC variables.
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	
	//Used to suspend all regular chat functions while there is a client connecting as to free up tunnels for RSA exchange.
	private boolean suspendAll;
	
	//RSA key exchange stuff
	private String sharedBitString;

	
	public ServerThread(Socket socket, String shared) throws IOException
	{
		sharedBitString = shared;//Take in the shared bits entered earlier.
		threadSock = socket;//assign socket created by server.
		suspendAll = true;//turn off all pipes to client
	}
	
	
	/*
	 * This is the start method. This method is responsible for starting execution of the thread,
	 * Once we start it, the run method begins. In here we also assign the i/o variables
	 */
	public void start()
	{
		try {
			inFromClient = new ObjectInputStream(threadSock.getInputStream());
			outToClient = new ObjectOutputStream(threadSock.getOutputStream());
		    }catch (IOException e) {
		    	//System.exit(0);
			e.printStackTrace();}
		
	    listener = new Thread(this);
		listener.start();
		serverThreadList.addElement(this);//add this element to the list of server threads.
	}
	

	/*

	 */
	public void run() 
	{

		
		try {
			
			//NEW USER
			//Gather up the username hash
			String usernameHash;
			while((usernameHash = (String) inFromClient.readObject()) == null){
				usernameHash = (String) inFromClient.readObject();
			}
			System.out.println(usernameHash);
			
			//In here we are checking our hash database to see if 
			//the client is new or returning.
			boolean isReturning = false;
			File dir = new File("C:/Users/Public/Favorites/srv/");
			File[] directoryListing = dir.listFiles();
			String usernameHashFile = new String(usernameHash+".txt");
			
			if (directoryListing != null) 
			{
				for (File child : directoryListing) 
				{
					String filename = child.getName();
					if(usernameHashFile.equals(filename)){
						isReturning = true;
					}
				}
			} 
			

			
			if(isReturning)
			{
				
				System.out.println("we found a returing user");
				System.out.println("begin reuturning user process");
			    //OLD USER
				Path path = Paths.get("C:\\Users\\Public\\Favorites\\srv\\"+usernameHash+".txt");
				
				//Create public key from encoded bytes,
				byte[] encodedPublic = Files.readAllBytes(path);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
			    PublicKey publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);
			    
				//AUTHENTICATION
			    //Create the random mess used to sign.
			    SecureRandom rnd = new SecureRandom();
				byte[] randomBytes = new byte[16];
				rnd.nextBytes(randomBytes);
				String messToClient = new String(Hex.encodeHex(randomBytes));
				
				//Create the digest
				MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				byte[] temp = sha1.digest(messToClient.getBytes());
				String srvDigest = new String(temp);		
				
				System.out.println("What was sent to client: " +srvDigest);
				outToClient.writeObject(srvDigest);	
				
			    //Wait for the signature.
			    String encodedEncryptedDigest = (String) inFromClient.readObject();

			    
			    System.out.println("This is the encrypted encoded string we get: "+encodedEncryptedDigest);
			    byte[] encryptedDigest = Base64.decodeBase64(encodedEncryptedDigest.getBytes());
				
			    //decrypt digest with our public key we use for the digital signature. 
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE, publicKeyForStorage);
				String digest = new String((cipher.doFinal(encryptedDigest)));
				
				System.out.println("This is what we got from client:" +digest);
				System.out.println("This is the hash of what we sent:" +srvDigest);
				
				if((digest.equals(srvDigest)) == false)
				{
					try {threadSock.close();
					}catch (IOException e) {
						e.printStackTrace();
					}
					serverThreadList.removeElement(this);
				}
				
				publicKeySwap(publicKeyForStorage);
			}
			else
			{
				System.out.println("Start some new client shit");

				//New user, go ahead and gather up the encoded pubkey then store it with
				//the usernamehash as the title to be used for authentication.
				int PIN = 100000 + rnd.nextInt(900000);
				String PINstring = Integer.toString(PIN);
				System.out.println("This is the PIN for the new client:" +PIN);

				
				//Receive the HMAC
				String userHMAC = (String) inFromClient.readObject();
				
				//Receive new user's public key 
				String encodedPublicKey = (String) inFromClient.readObject();
				
				//Calcualte own HMAC
				String srvHMAC = calculateHMAC(encodedPublicKey, PINstring);
				
				if(!(srvHMAC.equals(userHMAC)))//check to see if pin's match.
				{
					System.out.println("YOU ARE NOT WHO YOU SAY YOU ARE");
					threadSock.close();
				}
				else
				{
					//Decode public key so we can make an object with it.
					byte[] decodedPublicKey = Base64.decodeBase64(encodedPublicKey.getBytes());
					
					//Create public key from encoded bytes,
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
				    PublicKey publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);
				
				    //Store the users public key/usernamehash.
				    File directory = new File("C:/Users/Public/Favorites/srv/");
				    directory.mkdir();
					FileOutputStream keyfos2 = new FileOutputStream("C:/Users/Public/Favorites/srv/"+usernameHash+".txt");
					keyfos2.write(decodedPublicKey);
					keyfos2.close();  
					
					publicKeySwap(publicKeyForStorage);
				}
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
				e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		
		//only thing we want run() to do is spam send to all.
		//When an I/O exception is caught, means client is no
		//longer connected so we close the socket and remove that
		//client from the global list.
		suspendAll = false;
		boolean clientConnected = true;
		System.out.println("Entering main thread loop.");
		while(clientConnected)
		{
			try {
				sendToAll((String) inFromClient.readObject());
			} catch (IOException e1) 
			{
				e1.printStackTrace();
				try {threadSock.close();
				}catch (IOException e) {
					e.printStackTrace();
				}
				clientConnected = false;
				serverThreadList.removeElement(this);
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} 
		}
	}
 
	
	/*
	 * This method sort of explains itself. It takes in the encrypted string it would recieve from its client, then 
	 * it goes down the array, sending this message to all clients currently active on the server. So long as suspendAll
	 * is not set. It is set whilst new clients are connecting.
	 */
	protected void sendToAll(String encryptedString)
	{
		if(!suspendAll)
		{
			synchronized(serverThreadList)//Locks up the serverthread list for the time being.
			{
				Enumeration<ServerThread> enumerator = serverThreadList.elements();
				while(enumerator.hasMoreElements())
				{
					ServerThread srvThread = (ServerThread)enumerator.nextElement();
					try{
						TCPServer.getGUI().getChatDisplay().append(encryptedString + "\n");
						srvThread.outToClient.writeObject(encryptedString);
					   }catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}	
		}
	}
	
	
	//=======================================
	//
	// 			 RFC Compliant HMAC 
	//
	//=======================================

	public static String calculateHMAC(String data, String key)
			throws java.security.SignatureException
	{
		String result;
		
		try {

			// get an hmac_sha1 key from the raw key bytes
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);

			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(data.getBytes());
			
			// base64-encode the hmac
			result = new String(Base64.encodeBase64(rawHmac));

		} catch (Exception e) {
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
	
		return result;
	}

	
	
	synchronized private void publicKeySwap(PublicKey value) throws IOException, InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
	    
		//==============================
		//		Create and encrypt
		//==============================
		
		String encryptedSharedBytes = null;
		try {
			encryptedSharedBytes = EncryptRSA(sharedBitString, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		outToClient.writeObject(encryptedSharedBytes);
		
		System.out.println("Sent Encrypted private secret to client");
	}
	
	
	private static String EncryptRSA(String plainText, PublicKey pubKey)  throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		String encodedEncryptedString = new String(Base64.encodeBase64(cipher.doFinal(plainText.getBytes())));
		return encodedEncryptedString;
	}

						
	protected ObjectOutputStream getOutToClient() {
		return outToClient;
	}
}





