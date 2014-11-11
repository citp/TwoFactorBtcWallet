package edu.princeton.bitcointwofactorauth.android;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.google.bitcoin.core.MakeCertificate;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import android.app.Activity;
import android.content.Intent;
import android.net.nsd.NsdManager.ResolveListener;
import android.net.nsd.NsdServiceInfo;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;


public class MainActivity extends Activity  implements ResolveListener {
	
	public enum State {
	    INITIALIZING, SIGNING, WAITING
	}
	
	
	public static final String TAG = "NsdTFA";
	private static String KEYSTORE_FILENAME = "mykeystore.bks";
	private static String KEYSTORE_PASSWORD = "password";
	
	private NsdHelper mNsdHelper;
	public static final String mServiceName = "BitcoinTwoFactor";
	public static final String PREFS_NAME = mServiceName;
	private static final String WALLET_DATA_FILENAME = "walletDataList";
	private  ListView mListView;
	private State state;
	private ArrayList<WalletData> walletDataList;
	private SecureRandom rand = new SecureRandom();
	private ArrayAdapter<WalletData> mAdapter;
	private File keystoreFile;
	private X509Certificate publicCert;
	
	

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		Log.d("appm", "Calling onCreate for application");
		super.onCreate(null);
		setContentView(R.layout.activity_main);
		
		keystoreFile = getFileStreamPath(KEYSTORE_FILENAME);
		
		if (!keystoreFile.exists()) {
			MakeCertificate.generateSelfSignedCertificate("phoneTLSCert", keystoreFile, KEYSTORE_PASSWORD);
		}
		
		
		try {
			KeyStore store = KeyStore.getInstance("BKS");
			FileInputStream fis = new FileInputStream(keystoreFile);
	        store.load(fis, KEYSTORE_PASSWORD.toCharArray());
	        fis.close();
			publicCert = (X509Certificate) store.getCertificate("phoneTLSCert");
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		
		this.state = State.WAITING;
		
		this.walletDataList = loadWalletDataList();
		
		mListView = (ListView) findViewById(R.id.listView);

        mAdapter = new ArrayAdapter<WalletData>(this, R.layout.mytextview, android.R.id.text1, walletDataList);
        
        if (mListView == null) {
        	Log.d(TAG, "ERROR NULL mListView");
        }
        
        // Assign adapter to ListView
        mListView.setAdapter(mAdapter); 
        
        // ListView Item Click Listener
        mListView.setOnItemClickListener(new OnItemClickListener() {

              public void onItemClick(AdapterView<?> parent, View view,
                 int position, long id) {
                
               // ListView Clicked item index
               int itemPosition     = position;
               
               // ListView Clicked item value
               String  itemValue    = (String) mListView.getItemAtPosition(position);
                  
                // Show Alert 
                Toast.makeText(getApplicationContext(),
                  "Position :"+itemPosition+"  ListItem : " +itemValue , Toast.LENGTH_LONG)
                  .show();
             
              }

         });
	}
	
	private void saveWalletDataList() {
		ObjectOutputStream objectOut = null;
        try {

            FileOutputStream fileOut = openFileOutput(WALLET_DATA_FILENAME, Activity.MODE_PRIVATE);
            objectOut = new ObjectOutputStream(fileOut);
            objectOut.writeObject(walletDataList);
            fileOut.getFD().sync();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (objectOut != null) {
                try {
                    objectOut.close();
                } catch (IOException e) {
                    // do nowt
                }
            }
        }
	}
	
	@SuppressWarnings("unchecked")
	private ArrayList<WalletData> loadWalletDataList() {
		ArrayList<WalletData> list = null;
		ObjectInputStream objectIn = null;
        try {

            FileInputStream fileIn = getApplicationContext().openFileInput(WALLET_DATA_FILENAME);
            objectIn = new ObjectInputStream(fileIn);
            list = (ArrayList<WalletData>) objectIn.readObject();
        } catch (Exception e) {
        	list = new ArrayList<WalletData>();
        } finally {
            if (objectIn != null) {
                try {
                    objectIn.close();
                } catch (IOException e) {
                    
                }
            }
        }
        return list;
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
	
	protected void onStart() {
		mNsdHelper = new NsdHelper(this);
		mNsdHelper.initializeNsd();
		mNsdHelper.discoverServices();
		super.onStart();
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
        super.onDestroy();
    }
    
    public void newWallet(View view) {
		IntentIntegrator scanIntegrator = new IntentIntegrator(this);
		scanIntegrator.initiateScan();
    }
    
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
    	IntentResult scanningResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
    	if (scanningResult != null) {
    		String scanContent = scanningResult.getContents();
    		if (scanContent != null) {
    			try {
    				byte[] qrBytes = Base64.decode(scanContent, Base64.DEFAULT);
    				byte[] oneTimePass = Arrays.copyOf(qrBytes, 256);
    				byte[] certBytes = Arrays.copyOfRange(qrBytes, oneTimePass.length, qrBytes.length);
    				InputStream is = new ByteArrayInputStream(certBytes);
    				CertificateFactory cf = CertificateFactory.getInstance("X.509");
    				X509Certificate cert = (X509Certificate)cf.generateCertificate(is);
    	            is.close();
    	            WalletData data = new WalletData(oneTimePass, cert);
    	            walletDataList.add(data);
    	            saveWalletDataList();
    	            runOnUiThread(new Runnable() {
    	    	        public void run() {
    	    	        	if(mAdapter != null) {
    	    		        		mAdapter.notifyDataSetChanged();
    	    		        	}
    	    		        }
    	    			});
    	            state = State.INITIALIZING;
    	            Log.d(TAG, "Got certificate and password from QR code");
    			} catch (CertificateException e) {
    				// TODO Auto-generated catch block
    				e.printStackTrace();
    			} catch (IOException e) {
    				// TODO Auto-generated catch block
    				e.printStackTrace();
    			}
                
    		}
    	}
    }
    
    public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
        Log.e(TAG, "Resolve failed: " + errorCode);
    }
    
    public void onServiceResolved(NsdServiceInfo serviceInfo) {
        Log.e(TAG, "Resolve Succeeded. " + serviceInfo);

        if (serviceInfo.getServiceName().equals(mServiceName)) {
            Log.d(TAG, "Same IP.");
            return;
        }
        
		try {
			
			InetAddress host = serviceInfo.getHost();
			int port = serviceInfo.getPort();
			
			if (state.equals(State.INITIALIZING)) {
				Log.d(TAG, "Initializing wallet");
				WalletData walletData = walletDataList.get(walletDataList.size() - 1);
				System.out.println("Cert being added is " + walletData.mCert);
				MakeCertificate.addPublicCert(Base64.encodeToString(walletData.mOneTimePass, Base64.DEFAULT), walletData.mCert, keystoreFile, KEYSTORE_PASSWORD);
				Log.d(TAG, "Creating SSL Socket " + host.toString() + ":" + port);
				SSLSocketFactory socketFactory = newSSLSocketFactory();
				SSLSocket sslSock = (SSLSocket) socketFactory.createSocket(host, port);
				Log.d(TAG, "Created SSL Socket " + serviceInfo);
				
				TFAConnection connection = new TFAConnection(sslSock);
				
				walletData.initialize(connection, rand, publicCert);
				// TODO Fix cert alias
				
				
				saveWalletDataList();
				mListView.refreshDrawableState();
				connection.tearDown();
				this.runOnUiThread(new Runnable() {
			        public void run() {
			        	mAdapter.notifyDataSetChanged();
			        }
				});
				Log.d(TAG, "Finished initializing wallet");
				state = State.WAITING;
			} else if (state.equals(State.WAITING)) {
				Log.d(TAG, "Signing transaction");
				Log.d(TAG, "Creating SSL Socket " + host.toString() + ":" + port);
				SSLSocketFactory socketFactory = newSSLSocketFactory();
				SSLSocket sslSock = (SSLSocket) socketFactory.createSocket(host, port);
				Log.d(TAG, "Created SSL Socket " + serviceInfo);
				
				TFAConnection connection = new TFAConnection(sslSock);
				byte[] publicKey = connection.readPublicKey();
				WalletData walletData = null;
				ArrayList<WalletData> list = loadWalletDataList();
				for (WalletData wd : list) {
					if (Arrays.equals(publicKey, wd.mPublicKey)) {
						walletData = wd;
						break;
					}
				}
				Boolean canSign = walletData != null;
				connection.sendBoolean(canSign);
				if (canSign) {
					TransactionData txData = connection.readTransactionData();
					connection.setState(walletData, txData);
					TFAConnection.setMainConnection(connection);
					Intent intent = new Intent(this, ConfirmActivity.class);
				    Log.e(TAG, "Switching to confirm activity");
				    startActivity(intent);
				}
			}
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    private SSLSocketFactory newSSLSocketFactory() {
        try {
        	
        	// Get an instance of the Bouncy Castle KeyStore format
            KeyStore store = KeyStore.getInstance("BKS");
            FileInputStream fis = new FileInputStream(keystoreFile);
            store.load(fis, KEYSTORE_PASSWORD.toCharArray());
            fis.close();
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(store, KEYSTORE_PASSWORD.toCharArray());
            
            // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(store);
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLSocketFactory sf = context.getSocketFactory();
            return sf;
        } catch (Exception e) {
        	e.printStackTrace();
            throw new AssertionError(e);
        }
    }
}
