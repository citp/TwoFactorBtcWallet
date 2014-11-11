package edu.princeton.bitcointwofactorauth.android;

import java.math.BigInteger;

import threshold.mr04.data.PublicParameters;

public class InitializationParams {

	PublicParameters mParams;
	BigInteger mBobShare;
	byte[] mPublicKey;
	
	public InitializationParams(PublicParameters params, BigInteger bobShare, byte[] publicKey) {
		mParams = params;
		mBobShare = bobShare;
		mPublicKey = publicKey;
	}

}
