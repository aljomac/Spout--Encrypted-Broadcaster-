
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
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
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


public class ServerThread extends Thread
{
	//I/O variables 
	protected BufferedReader inFromClient;
	protected DataOutputStream outToClient;
	protected Socket threadSock;
	protected Thread listener;
	
	//List of all server threads active.
	protected static Vector<ServerThread> serverThreadList = new Vector<ServerThread>();//its static so the same one is used for all.
	
	
	
	//Used to suspend all regular chat functions while there is a client connecting as to free up tunnels for RSA exchange.
	private boolean suspendAll;
	
	//RSA key exchange stuff
	private String sharedBitString;

	
	public ServerThread(Socket socket, String shared) throws IOException
	{
		sharedBitString = shared;//Take in the shared bits entered earlier.
		threadSock = socket;
		suspendAll = true;
	}
	
	
	/*
	 * Ran as a starting point for the thread, it initiates the IO and starts a new thread listener. 
	 */
	public void start()
	{
		try {
				inFromClient = new BufferedReader(new InputStreamReader(threadSock.getInputStream()));
				outToClient = (new DataOutputStream(threadSock.getOutputStream()));
		    }catch (IOException e) {
			e.printStackTrace();}
		
	    listener = new Thread(this);
		listener.start();
		serverThreadList.addElement(this);//add this element to the list of server threads.
	}
	

	/*
	 * Alright so in the run method we first fire up our publicKeySwap() method in order to answer to the similar loop
	 * within the client. This is where the elements of the clients public key are transfered over in order for 
	 * this particular server thread to used them to encrypt the shared secret. Then we have 
	 */
	public void run() 
	{
		try {
			
			//NEW USER
			//Gather up the username hash
			String usernameHash;
			while((usernameHash = inFromClient.readLine()) == null){
				usernameHash = inFromClient.readLine();
			}
			System.out.println(usernameHash);
			
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
			
			
			if(isReturning){
				System.out.println("we found a returing user");
			}

			
			if(isReturning)
			{
				
			    //OLD USER
				Path path = Paths.get("C:\\Users\\Public\\Favorites\\srv\\"+usernameHash+".txt");
				
				//Create public key from encoded bytes,
				byte[] encodedPublic = Files.readAllBytes(path);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
			    PublicKey publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);
			    
			    //Create the random mess used to sign.
			    SecureRandom rnd = new SecureRandom();
				byte[] randomBytes = new byte[8];
				rnd.nextBytes(randomBytes);
				String messToClient = new String(Hex.encodeHexString(randomBytes));
				
				System.out.println("What was sent to client: " +messToClient);
				outToClient.writeBytes(messToClient + "\n");	
				
				//Create the digest
				MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				byte[] temp = sha1.digest(messToClient.getBytes());
				String srvDigest = new String(temp);		
				
			    //Wait for the signature.
			    String encodedEncryptedDigest = inFromClient.readLine();

			    
			    System.out.println("This is the encrypted encoded string we get: "+encodedEncryptedDigest);
			    byte[] encryptedDigest = Base64.decodeBase64(encodedEncryptedDigest.getBytes());
				
			    //decrypt digest with our public key we use for the digital signature. 
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE, publicKeyForStorage);
				String digest = new String((cipher.doFinal(encryptedDigest)));
				
				if((digest.equals(srvDigest)) == false)
				{
					try {threadSock.close();
					}catch (IOException e) {
						e.printStackTrace();
					}
					serverThreadList.removeElement(this);
				}
					
				System.out.println("This is what we got from client:" +digest);
				System.out.println("This is the hash of what we sent:" +srvDigest);
				
				publicKeySwap(publicKeyForStorage);
			}
			else
			{
				//New user, go ahead and gather up the encoded pubkey then store it with
				//the usernamehash as the title to be used for authentication.
				
				String encodedPublicKey = inFromClient.readLine();

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
				
				//AUTHENTICATION
			    //Create the random mess used to sign.
			    SecureRandom rnd = new SecureRandom();
				byte[] randomBytes = new byte[16];
				rnd.nextBytes(randomBytes);
				String messToClient = new String(Hex.encodeHexString(randomBytes));
				
				//Create the digest
				MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				byte[] temp = sha1.digest(messToClient.getBytes());
				String srvDigest = new String(temp);		
				
				System.out.println("What was sent to client: " +messToClient);
				outToClient.writeBytes(messToClient + "\n");	
				
			    //Wait for the signature.
			    String encodedEncryptedDigest = inFromClient.readLine();

			    
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
				sendToAll(inFromClient.readLine());
			} catch (IOException e1) 
			{
				e1.printStackTrace();
				try {threadSock.close();
				}catch (IOException e) {
					e.printStackTrace();
				}
				clientConnected = false;
				serverThreadList.removeElement(this);
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
			synchronized(serverThreadList)
			{
				Enumeration<ServerThread> enumerator = serverThreadList.elements();
				while(enumerator.hasMoreElements())
				{
					ServerThread srvThread = (ServerThread)enumerator.nextElement();
					try{
						TCPServer.getGUI().getChatDisplay().append(encryptedString + "\n");
						srvThread.outToClient.writeBytes(encryptedString + '\n');
					   }catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}	
		}
	}
	
	
	/*
	 * So, this is where we join the client in gathering its public key (RSA). This works by letting 
	 * the client know when it is ready to take in the RSAe by sending it an ack bit of "1".
	 */
	
	synchronized private void publicKeySwap(PublicKey value) throws IOException, InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		String encodedPublicKey = inFromClient.readLine();
		PublicKey clientSigKey = value;
		
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] srvHashBytes = sha1.digest(encodedPublicKey.getBytes());
		String srvHash = new String(srvHashBytes);
		
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, clientSigKey);
		
		
		//Create public key from encoded bytes,
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] decodedPublicKey = Base64.decodeBase64(encodedPublicKey.getBytes());
	    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
	    PublicKey clientPubKey = keyFactory.generatePublic(publicKeySpec);
	    
	    
	    String signature = inFromClient.readLine();
	    
	    System.out.println("signature from client: "+signature);
	    
	    byte[] decodedEncryptedSignature = Base64.decodeBase64(signature.getBytes());
	    byte[] decryptedSignature = cipher.doFinal(decodedEncryptedSignature);
	    String clientHash = new String(decryptedSignature);
		
	    System.out.println("Client Hash: "+clientHash);
	    System.out.println("Server Hash: "+srvHash);
	    
	    if(!clientHash.equals(srvHash)){
	    	System.out.println("Hash Missmatch!!! Either data is corrupted or tampered with");
	    	
			try {threadSock.close();
			}catch (IOException e) {
				e.printStackTrace();
			}
			serverThreadList.removeElement(this);
	    }
	    	
	    
	    
		//==============================
		//		Create and encrypt
		//==============================
		
		String encryptedSharedBytes = null;
		try {
			encryptedSharedBytes = EncryptRSA(sharedBitString, clientPubKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		outToClient.writeBytes(encryptedSharedBytes + "\n");
		
		System.out.println("Sent Encrypted private secret to client");
	}
	
	
	private static String EncryptRSA(String plainText, PublicKey pubKey)  throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		String encodedEncryptedString = new String(Base64.encodeBase64String(cipher.doFinal(plainText.getBytes())));
		return encodedEncryptedString;
	}

						
	protected DataOutputStream getOutToClient() {
		return outToClient;
	}
}





