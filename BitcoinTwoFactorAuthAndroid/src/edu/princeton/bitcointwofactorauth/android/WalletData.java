package edu.princeton.bitcointwofactorauth.android;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import threshold.mr04.Bob;

public class WalletData implements Serializable {

	private static final long serialVersionUID = -2087859102158713425L;
	public byte[] mOneTimePass;
	public X509Certificate mCert;
	
	public Bob mBob;
	public byte[] mPublicKey;
	public String mName;
	public static final String TAG = "WalletData";
	private boolean mInitialized;
	public WalletData(byte[] oneTimePass, X509Certificate cert) {
		this.mOneTimePass = oneTimePass;
		this.mCert = cert;
		this.mName = "Awesome Wallet";
		this.mInitialized = false;
	}
	
	public boolean initialize(TFAConnection connection, SecureRandom rand, X509Certificate phoneCert) throws IOException, ClassNotFoundException {
		InitializationParams ip = connection.initializeWallet(mOneTimePass, phoneCert);
		if (ip != null) {
			mPublicKey = ip.mPublicKey;
			mBob = new Bob(ip.mBobShare, ip.mPublicKey, rand, ip.mParams);
			mInitialized = true;
		}
		return ip != null;
	}
	
	public String displayName() {
		if (mInitialized) {
			return mName;
		} else {
			return mName + " (uninitialized)";
		}
	}
	
	public String toString() {
		return displayName();
	}

}
