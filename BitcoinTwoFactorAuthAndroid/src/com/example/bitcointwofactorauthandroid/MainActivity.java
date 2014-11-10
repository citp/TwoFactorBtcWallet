package com.example.bitcointwofactorauthandroid;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import android.app.Activity;
import android.app.Fragment;
import android.net.nsd.NsdManager.ResolveListener;
import android.net.nsd.NsdServiceInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

public class MainActivity extends Activity  implements Runnable, ResolveListener {
	public static final String TAG = "NsdTFA";
	
	private NsdHelper mNsdHelper;
	private TFAConnection mConnection;
	public String mServiceName = "BitcoinTwoFactor";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		Log.d("appm", "Calling onCreate for application");
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction().add(R.id.container, new PlaceholderFragment()).commit();
		}

		Log.d(TAG, "Setting up NSD.");
		
		mNsdHelper = new NsdHelper(this);
		mNsdHelper.initializeNsd();
//		mNsdHelper.mResolveListener = this;
    
		mNsdHelper.discoverServices();
		
		Log.d(TAG, "Discovering NSD.");
		
//		new Thread(this).start();
	}
	
	@Override
	public void run() {
		Log.d(TAG, "Looking for service.");
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
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

	/**
	 * A placeholder fragment containing a simple view.
	 */
	public static class PlaceholderFragment extends Fragment {

		public PlaceholderFragment() {
		}

		@Override
		public View onCreateView(LayoutInflater inflater, ViewGroup container,
				Bundle savedInstanceState) {
			View rootView = inflater.inflate(R.layout.fragment_main, container,
					false);
			return rootView;
		}
	}
	
	@Override
    protected void onPause() {
        if (mNsdHelper != null) {
            mNsdHelper.tearDown();
        }
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mNsdHelper != null) {
            mNsdHelper.discoverServices();
        }
    }

    @Override
    protected void onDestroy() {
        mNsdHelper.tearDown();
        mConnection.tearDown();
        super.onDestroy();
    }
    
    @Override
    public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
        Log.e(TAG, "Resolve failed: " + errorCode);
    }

    @Override
    public void onServiceResolved(NsdServiceInfo serviceInfo) {
        Log.e(TAG, "Resolve Succeeded. " + serviceInfo);

        if (serviceInfo.getServiceName().equals(mServiceName)) {
            Log.d(TAG, "Same IP.");
            return;
        }
        
        
		try {
			InetAddress host = serviceInfo.getHost();
			int port = serviceInfo.getPort();
			SSLSocketFactory factory = newSslSocketFactory();
			Log.e(TAG, "Creating SSL Socket " + host.toString() + ":" + port);
			SSLSocket sslSock = (SSLSocket) factory.createSocket(host, port);
			Log.e(TAG, "Created SSL Socket " + serviceInfo);
			mConnection = new TFAConnection(sslSock);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    private SSLSocketFactory newSslSocketFactory() {
        try {
            // Get an instance of the Bouncy Castle KeyStore format
            KeyStore trusted = KeyStore.getInstance("BKS");
            // Get the raw resource, which contains the keystore with
            // your trusted certificates (root and any intermediate certs)
            InputStream in = getResources().openRawResource(R.raw.mysystem);
            try {
                // Initialize the keystore with the provided trusted certificates
                // Also provide the password of the keystore
                trusted.load(in, "welcome".toCharArray());
            } finally {
                in.close();
            }
            
         // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(trusted);
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            SSLSocketFactory sf = context.getSocketFactory();
            return sf;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
