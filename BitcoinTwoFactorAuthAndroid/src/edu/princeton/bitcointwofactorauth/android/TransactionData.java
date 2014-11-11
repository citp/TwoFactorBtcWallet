package edu.princeton.bitcointwofactorauth.android;

import java.math.BigInteger;

import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.Transaction.SigHash;

public class TransactionData {
	private Transaction mTX;
	private int mInputIndex;
	private byte[] mConnectedPubKeyScript;
	private SigHash mHashType;
	private boolean mAnyoneCanPay;
	
	public TransactionData(Transaction tx, int inputIndex, byte[] connectedPubKeyScript,
			SigHash hashType, boolean anyoneCanPay) {
		mTX = tx;
		mInputIndex = inputIndex;
		mConnectedPubKeyScript = connectedPubKeyScript;
		mHashType = hashType;
		mAnyoneCanPay = anyoneCanPay;
	}
	
	public boolean isTransaction() {
		return mTX != null;
	}
	
	public BigInteger getValue() {
		if (mTX != null) {
			return mTX.getOutput(0).getValue();
		} else {
			return new BigInteger("0");
		}
	}
	
	public String getToAddress() {
		if (mTX != null) {
			return mTX.getOutput(0).getScriptPubKey().getToAddress(mTX.getParams()).toString();
		} else {
			return "No one";
		}
		
	}
	
	public String getFromAddress() {
		if (mTX != null) {
			return mTX.getInput(mInputIndex).getConnectedOutput().getScriptPubKey().getToAddress(mTX.getParams()).toString();
		} else {
			return "Me";
		}
		
	}

	public Sha256Hash getSigningHash() {
		if (mTX != null) {
			return mTX.hashForSignature(mInputIndex, mConnectedPubKeyScript, mHashType, mAnyoneCanPay);
		} else {
			return null;
		}
		
	}
	
}
