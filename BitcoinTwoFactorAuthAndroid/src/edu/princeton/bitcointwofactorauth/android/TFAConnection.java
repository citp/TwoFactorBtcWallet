package edu.princeton.bitcointwofactorauth.android;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;

import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.Transaction.SigHash;

import threshold.mr04.Util;
import threshold.mr04.data.PublicParameters;
import threshold.mr04.data.Round1Message;
import threshold.mr04.data.Round2Message;
import threshold.mr04.data.Round3Message;
import threshold.mr04.data.Round4Message;
import android.util.Log;


public class TFAConnection {
	private static TFAConnection mMainConnection = null;
    private static final String TAG = "TFAConnection";

    private WalletData mWalletData;
    private SSLSocket mSocket;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;
    
    public TransactionData mTransactionData;
    
    public static TFAConnection getMainConnection() {
    	return mMainConnection;
	}
    
    public static void setMainConnection(TFAConnection mainConnection) {
    	mMainConnection = mainConnection;
    }
    // http://www.nealgroothuis.name/import-a-private-key-into-a-java-keystore/
    public TFAConnection(SSLSocket socket) throws IOException {
    	Log.d(TAG, "Creating TFAConnection");
    	mSocket = socket;
    	oos = new ObjectOutputStream(new BufferedOutputStream(mSocket.getOutputStream()));
		oos.flush();
    	ois = new ObjectInputStream(new BufferedInputStream(mSocket.getInputStream()));
    	Log.d(TAG, "Getting request");
    	int requestType = ois.readInt();
    	Log.d(TAG, "Got requestType + " + requestType);
    	oos.writeInt(4);
    	oos.flush();
    	Log.d(TAG, "Created TFAConnection");
    }
    
    public void tearDown() throws IOException {
		mSocket.close();
    }
    
    public void setState(WalletData walletData, TransactionData txData) {
    	mWalletData = walletData;
    	mTransactionData = txData;
    }
    
    public InitializationParams initializeWallet(byte[] oneTimePass, X509Certificate cert) throws IOException {
    	InitializationParams params = null;
		try {
			Log.d(TAG, "Initializing wallet");
			sendByteArray(oneTimePass);
			Log.d(TAG, "Sent pass");
			boolean passwordApproved = (Boolean) ois.readObject();
			Log.d(TAG, "Got response");
			if (passwordApproved) {
				Log.d(TAG, "Password was approved");
				sendObject(cert);
				Log.d(TAG, "Sent cert");
				Log.d(TAG, "Reading Initialization Params");
				PublicParameters publicParams = (PublicParameters) ois.readObject();
				BigInteger bobShare = (BigInteger) ois.readObject();
				byte[] publicKey = readPublicKey();
				Log.d(TAG, "Read Initialization Params");
				params = new InitializationParams(publicParams, bobShare, publicKey);
			}
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return params;
    }
    
    public void sendBoolean(Boolean bool) throws IOException {
    	sendObject(bool);
    }
    
    public byte[] readPublicKey() throws IOException {
    	Log.d(TAG, "Reading public key");
		byte[] publicKey = receiveByteArray();
		Log.d(TAG, "Read public key");
    	return publicKey;
    }
    
    public TransactionData readTransactionData() throws IOException {
    	try {
    		Log.d(TAG, "Reading Transaction Data");
    		boolean isTx = (Boolean) ois.readObject();
    		if (isTx) {
    			System.out.println("Getting actual transaction");
    			Transaction tx = (Transaction) ois.readObject();
    			int inputIndex = ois.readInt();
    			byte[] connectedPubKeyScript = receiveByteArray();
    			SigHash hashType = (SigHash) ois.readObject();
    			boolean anyoneCanPay = (Boolean) ois.readObject();
    			Log.d(TAG, "Read Transaction Data");
    			return new TransactionData(tx, inputIndex, connectedPubKeyScript, hashType, anyoneCanPay);
    		} else {
    			System.out.println("Producing fake transaction");
    			return new TransactionData(null, 0, null, SigHash.ALL, true);
    		}
			
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return null;
    }
    
    public boolean signTransaction(TransactionData txData) throws IOException {
		try {
			Round1Message round1Message = (Round1Message) ois.readObject();
			if (txData.isTransaction()) {
				BigInteger receivedMPrime = round1Message.getmPrime();
				BigInteger calculatedMPrime = Util.calculateMPrime(mWalletData.mBob.q, txData.getSigningHash().getBytes());
				if (!receivedMPrime.equals(calculatedMPrime)) {
					Boolean response = false;
					sendObject(response);
					return false;
				}
			}
			Boolean response = true;
			sendObject(response);
			Round2Message round2Message = mWalletData.mBob.bobToAliceRound2(round1Message);
			sendObject(round2Message);
			Round3Message round3Message = (Round3Message) ois.readObject();
			Round4Message round4Message = mWalletData.mBob.bobToAliceRound4(round3Message);
			sendObject(round4Message);
			return true;
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
    }
    
    private void sendObject(Object obj) throws IOException {
    	oos.writeObject(obj);
    	oos.flush();
    }
    
    private void sendByteArray(byte[] objArray) throws IOException {
    	oos.writeInt(objArray.length);
    	oos.write(objArray);
    	oos.flush();
    }
    
    private byte[] receiveByteArray() throws IOException {
    	int arrayLength = ois.readInt();
    	byte[] array = new byte[arrayLength];
    	ois.read(array);
    	return array;
    }
}
