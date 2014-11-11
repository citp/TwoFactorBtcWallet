package com.google.bitcoin.core;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import javax.annotation.Nullable;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import threshold.mr04.Alice;
import threshold.mr04.Util;
import threshold.mr04.data.*;

import com.apple.dnssd.DNSSD;
import com.apple.dnssd.DNSSDException;
import com.apple.dnssd.DNSSDRegistration;
import com.apple.dnssd.DNSSDService;
import com.apple.dnssd.RegisterListener;
import com.google.bitcoin.core.Transaction.SigHash;
import com.google.bitcoin.crypto.KeyCrypterException;

public class RemoteECKey extends ECKey implements Serializable, RegisterListener {
	private static final Logger log = LoggerFactory.getLogger(RemoteECKey.class);
	private static final long serialVersionUID = 2238409707902166695L;
	public static final String ServiceType = "_bitcointwofactor._tcp";
	private Alice mAlice;
	private byte[] pubKeyBytes;
	private File mKeystore;
	private String mKeystorePassword;
	
	transient public Socket mSocket;
	transient private SSLServerSocket mSSLServerSocket;
	
	public RemoteECKey(Alice alice, final PublicParameters params, final BigInteger bobShare, final byte[] publicKey, final byte[] oneTimePass, File keystore, String keystorePassword) {
		super(null, Util.compressPoint(alice.getQ(), CURVE).getEncoded());
		mAlice = alice;
		pubKeyBytes = publicKey;
		mKeystore = keystore;
		mKeystorePassword = keystorePassword;
		log.debug("Creating RemoteECKey");
		startServerAndGetResponse(2, false, new ConnectionHandler<Boolean>() {
			public RemoteResult<Boolean> handleConnection(ObjectInputStream ois, ObjectOutputStream oos) throws IOException, ClassNotFoundException {
				log.debug("Asking for password");
    			int passLength = ois.readInt();
    			log.debug("Got pass length " + passLength);
    			byte[] pass = new byte[passLength];
    			ois.read(pass);
    			log.debug("Recieved potential password");
    			Boolean correctPass = Arrays.equals(pass, oneTimePass);
    			log.debug("Sending phone password response");
    			oos.writeObject(correctPass);
    			oos.flush();
    			log.debug("Sent phone password response");
    			RemoteResult<Boolean> result = new RemoteResult<Boolean>();
    			result.response = correctPass;
    			if (correctPass) {
    				log.debug("Password is correct");
    				X509Certificate cert = (X509Certificate) ois.readObject();
    				log.debug("Cert being added is " + cert);
    				MakeCertificate.addPublicCert(Base64.toBase64String(pubKeyBytes), cert, mKeystore, mKeystorePassword);
    				oos.writeObject(params);
    				oos.writeObject(bobShare);
    				oos.writeInt(publicKey.length);
    				oos.write(publicKey);
    				oos.flush();
    				log.debug("Sent phone wallet information");
    				result.status = RemoteResultStatus.SUCCESS;
    			} else {
    				result.status = RemoteResultStatus.NO_MATCH;
    			}
				return result;
			}
		});
		log.debug("Finished creating RemoteECKey");
	}
	
	private void writeObject(java.io.ObjectOutputStream out)
		     throws IOException {
		out.defaultWriteObject();
	}
	
	private void readObject(java.io.ObjectInputStream in)
		     throws IOException, ClassNotFoundException {
		in.defaultReadObject();
	}
	
	public boolean hasPrivKey() {
		return true;
	}
	
	protected void finalize() throws Throwable {
	     try {
	         mSocket.close();
	     } finally {
	         super.finalize();
	     }
	 }
	
    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using DER format, so you want {@link com.google.bitcoin.core.ECKey.ECDSASignature#encodeToDER()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if this ECKey doesn't have a private part.
     */
	public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
		return sign(input, aesKey, null, 0, null, null, false);
    }
	
	public enum RemoteResultStatus {
		SUCCESS, NO_MATCH, REJECTED;
	}
	
	public class RemoteResult<T> {
	    public RemoteResultStatus status;
	    public T response;
	}
	
	private interface ConnectionHandler<T> {
		public RemoteResult<T> handleConnection(ObjectInputStream ois, ObjectOutputStream oos) throws IOException, ClassNotFoundException;
	}
	
	private <T> T startServerAndGetResponse(final int requestType, boolean needsClientAuth, final ConnectionHandler<T> handler) {
		final CountDownLatch latch = new CountDownLatch(1);
		mSSLServerSocket = getSSLServerSocket(needsClientAuth);
		int listentingPort = mSSLServerSocket.getLocalPort();
		final ArrayList<T> tList = new ArrayList<T>();
        try {
        	final DNSSDRegistration registration = DNSSD.register(null, ServiceType, listentingPort, this);
        	log.debug("Server started and listening");
        	new Thread() {
        		public void run() {
        			try
                    {
        				log.debug("Waiting for responses");
                        while (true) {
                            SSLSocket sslSocket = (SSLSocket) mSSLServerSocket.accept();
                            if (sslSocket != null) {
                                log.debug("Successfully accepted socket");
                                ObjectOutputStream oos = new ObjectOutputStream( new BufferedOutputStream(sslSocket.getOutputStream()));
                    			oos.flush();
                    			ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(sslSocket.getInputStream()));
                    			log.debug("Successfully created streams");
                    			oos.writeInt(requestType);
                    			oos.flush();
                    			log.debug("Sent request");
                    			int response = ois.readInt();
                    			log.debug("Got response " + response);
                    			RemoteResult<T> result = handler.handleConnection(ois, oos);
                                log.debug("Finished handling response");
                                sslSocket.close();
                                switch (result.status) {
								case SUCCESS:
									tList.add(result.response);
                                	latch.countDown();
									return;
								case NO_MATCH:
									break;
								case REJECTED:
									latch.countDown();
									return;
								}
                            }
                        }
                    }
                    catch (Exception e) { e.printStackTrace(  ); }
        		}
        	}.start();
        	log.debug("Waiting for server to return");
        	latch.await();
        	registration.stop();
        	mSSLServerSocket.close();
        	log.debug("Server is finished");
        	if (tList.size() > 0) {
        		return tList.get(0);
        	} else {
        		return null;
        	}
		} catch (DNSSDException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
    public ECDSASignature sign(final Sha256Hash input, @Nullable KeyParameter aesKey,
    		final Transaction tx, final int inputIndex, final byte[] connectedPubKeyScript, final SigHash hashType,
    		final boolean anyoneCanPay) throws KeyCrypterException {
    	ECDSASignature signature = startServerAndGetResponse(2, true, new ConnectionHandler<ECDSASignature>() {
    		public RemoteResult<ECDSASignature> handleConnection(ObjectInputStream ois, ObjectOutputStream oos) throws IOException, ClassNotFoundException {
    			log.debug("Starting sign procedure");
    			oos.writeInt(pubKeyBytes.length);
    			oos.write(pubKeyBytes);
    			oos.flush();
    			log.debug("Sent public key");
    			boolean response = (Boolean) ois.readObject();
    			log.debug("Received response");
    			RemoteResult<ECDSASignature> result = new RemoteResult<ECDSASignature>();
    			if (!response) {
    				log.debug("Phone does not have matching key");
    				result.status = RemoteResultStatus.NO_MATCH;
    			} else {
    				Boolean isTx = tx != null;
    				oos.writeObject(isTx);
    				oos.flush();
    				log.debug("Sent isTx");
    				if (isTx) {
    					log.debug("Sending tx data");
    					oos.writeObject(tx);
        				oos.writeInt(inputIndex);
        				oos.writeInt(connectedPubKeyScript.length);
        				oos.write(connectedPubKeyScript);
        				oos.writeObject(hashType);
        				oos.writeObject(anyoneCanPay);
        				oos.flush();
    				}
    				log.debug("Finished sending data");
    	    		boolean willSign = (Boolean) ois.readObject();
    	    		log.debug("Got response");
    	    		if (!willSign) {
    	    			log.debug("Phone rejected transaction");
    	    			result.status = RemoteResultStatus.REJECTED;
    	    		} else {
    	    			Round1Message round1Message = mAlice.aliceToBobRound1(input.getBytes());
    	    			log.debug("Sending round 1");
    	    			oos.writeObject(round1Message);
    	    			oos.flush();
    	    			boolean willingToSign = (Boolean) ois.readObject();
    	    			if (!willingToSign) {
    	    				log.debug("Phone says signature doesn't match");
    	    				result.status = RemoteResultStatus.REJECTED;
    	    			} else {
    	    				Round2Message round2Message = (Round2Message) ois.readObject();
        	    			log.debug("Got round 2");
        	    	    	Round3Message round3Message = mAlice.aliceToBobRound3(round2Message);
        	    	    	oos.writeObject(round3Message);
        	    	    	oos.flush();
        	    	    	Round4Message round4Message = (Round4Message) ois.readObject();
        	    	    	
        	    	    	BigInteger[] components = mAlice.aliceOutput(round4Message);
        	    	    	final ECDSASignature signature = new ECDSASignature(components[0], components[1]);
        	    	        signature.ensureCanonical();
        	    	        result.status = RemoteResultStatus.SUCCESS;
        	    	        result.response = signature;
    	    			}
    	    		}
    			}

    			return result;
    		}
    	});
    	return signature;
    }
    
    /**
     * Signs a text message using the standard Bitcoin messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this ECKey does not have the private part.
     * @throws KeyCrypterException if this ECKey is encrypted and no AESKey is provided or it does not decrypt the ECKey.
     */
    public String signMessage(String message, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        byte[] data = Utils.formatMessageForSigning(message);
        Sha256Hash hash = Sha256Hash.createDouble(data);
        ECDSASignature sig = sign(hash, aesKey);
        if (sig == null) {
        	log.debug("Message signing returned null");
        	return null;
        }
        // Now we have to work backwards to figure out the recId needed to recover the signature.
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            ECKey k = ECKey.recoverFromSignature(i, sig, hash, isCompressed());
            if (k != null && Arrays.equals(k.pub, pub)) {
                recId = i;
                break;
            }
        }
        if (recId == -1)
            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
        int headerByte = recId + 27 + (isCompressed() ? 4 : 0);
        byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
        sigData[0] = (byte)headerByte;
        System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
        System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
        return new String(Base64.encode(sigData), Charset.forName("UTF-8"));
    }
    
    public void operationFailed(DNSSDService service, int errorCode)
    {
        log.debug("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // If our name changes while we're running, we update window title.
    // In the event that we're registering in multiple domains (Wide-Area
    // DNS-SD) we'll use the local (mDNS) name for display purposes.
    public void serviceRegistered(DNSSDRegistration sd, int flags,
                                  String serviceName, String regType, String domain)
    {
        log.debug("name = " + serviceName);
    }
    
    public SSLServerSocket getSSLServerSocket(boolean needsClientAuth) {

        //Create and load the Keystore
        try {
        	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyStore ks = KeyStore.getInstance("BKS");
            ks.load(new FileInputStream(mKeystore), mKeystorePassword.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, mKeystorePassword.toCharArray());
            
            // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(ks);
            
            // Create the ServerSocket as an SSLServerSocket
            SSLContext secureSocket = SSLContext.getInstance("TLS");
            secureSocket.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLServerSocketFactory ssf = secureSocket.getServerSocketFactory();
            SSLServerSocket ssocket = (SSLServerSocket) ssf.createServerSocket(0);

            // This explicitly states TLS with 2-way authentication
            ssocket.setNeedClientAuth(needsClientAuth);
            return ssocket;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
}