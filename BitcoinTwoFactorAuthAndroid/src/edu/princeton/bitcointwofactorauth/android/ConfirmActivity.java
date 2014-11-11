package edu.princeton.bitcointwofactorauth.android;

import java.math.BigInteger;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

public class ConfirmActivity extends Activity {
	private static final String TAG = "ConfirmActivity";
	ProgressDialog progress;
	TFAConnection connection;
	TransactionData mTXData;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_confirm);
		connection = TFAConnection.getMainConnection();
		mTXData = connection.mTransactionData;
        BigInteger value = connection.mTransactionData.getValue();
        String toAddress = connection.mTransactionData.getToAddress();
        String fromAddress = connection.mTransactionData.getFromAddress();
		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction()
					.add(R.id.container, ConfirmFragment.newInstance(fromAddress, toAddress, value)).commit();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.confirm, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
	
	 private class ConfirmTask extends AsyncTask<TFAConnection, String, Boolean> {

		@Override
		protected Boolean doInBackground(TFAConnection... arg0) {
			try {
	        	TFAConnection connection = arg0[0];
	    		publishProgress("Signing Transaction");
	    		connection.sendBoolean(true);
	    		return connection.signTransaction(mTXData);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
			return null;
		}
		
		protected void onProgressUpdate(String... message) {
			progress.setMessage(message[0]);
	     }
		
		protected void onPostExecute(Boolean result) {
	    	progress.dismiss();
			returnToMain();
        }
		
        protected void onPreExecute() {
        	showDialog();
        }

	 }
	 
	 private class RejectTask extends AsyncTask<TFAConnection, String, Void> {

			@Override
			protected Void doInBackground(TFAConnection... arg0) {
				try {
		        	TFAConnection connection = arg0[0];
		    		connection.sendBoolean(false);
		    		return null;
		        } catch (Exception e) {
		            e.printStackTrace();
		        }
				return null;
			}
			
			protected void onPostExecute(Void result) {
				returnToMain();
	        }

		 }
	 
	private void showDialog() {
		progress = new ProgressDialog(this);
    	progress.setTitle("Signing");
    	progress.setMessage("Wait while transaction is signed...");
    	progress.show();
	}
	 
	private void returnToMain() {
		Intent intent = new Intent(this, MainActivity.class);
	    startActivity(intent);
	}
	
	public void confirmTransaction(View view) {
		Log.d(TAG, "Confirming transaction");
		new ConfirmTask().execute(connection);
	}
	
	public void rejectTransaction(View view) {
		Log.d(TAG, "Rejecting transaction");
		new RejectTask().execute(connection);
	}
}
