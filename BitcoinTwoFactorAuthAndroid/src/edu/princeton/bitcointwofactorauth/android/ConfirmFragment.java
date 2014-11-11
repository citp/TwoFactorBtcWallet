package edu.princeton.bitcointwofactorauth.android;

import java.math.BigInteger;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

public class ConfirmFragment extends Fragment {
		
	public ConfirmFragment() {
	}
	
	public static ConfirmFragment newInstance(String from, String to, BigInteger value) {
		ConfirmFragment f = new ConfirmFragment();

        // Supply index input as an argument.
        Bundle args = new Bundle();
        args.putString("from", from);
        args.putString("to", to);
        args.putSerializable("value", value);
        f.setArguments(args);

        return f;
    }
	
	public String getFrom() {
		return getArguments().getString("from");
    }
	
	public String getTo() {
		return getArguments().getString("to");
    }
	
	public double getValue() {
		return ((BigInteger) getArguments().getSerializable("value")).doubleValue() / 100000000.0;
    }

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.fragment_confirm, container, false);
		TextView toField = (TextView) rootView.findViewById(R.id.to_field);
		TextView fromField = (TextView) rootView.findViewById(R.id.from_field);
		TextView valueField = (TextView) rootView.findViewById(R.id.value_field);
		toField.setText(getTo());
		fromField.setText(getFrom());
		valueField.setText(String.format("%.4f", getValue()) + " BTC");
		return rootView;
	}
}