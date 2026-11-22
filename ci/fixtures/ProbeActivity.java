package com.appguardian.probe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

public final class ProbeActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (!getIntent().getBooleanExtra("query-dns", false)) {
            finish();
            return;
        }
        new Thread(() -> {
            try {
                Log.i("GuardianProbe", "fixture DNS result " + query());
            } catch (IOException error) {
                Log.i("GuardianProbe", "fixture DNS request failed");
            } finally {
                runOnUiThread(this::finish);
            }
        }, "Guardian DNS fixture").start();
    }

    private static int query() throws IOException {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(new byte[]{0x33, 0x44, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        for (String label : new String[]{"guardian-ci", "example"}) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            message.write(bytes.length);
            message.write(bytes);
        }
        message.write(new byte[]{0, 0, 1, 0, 1});
        byte[] query = message.toByteArray();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByAddress(new byte[]{10, (byte) 211, 0, 2}), 53);
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(query, query.length));
            byte[] payload = new byte[512];
            DatagramPacket response = new DatagramPacket(payload, payload.length);
            socket.receive(response);
            if (response.getLength() < 12 || payload[0] != 0x33 || payload[1] != 0x44 || (payload[2] & 128) == 0) {
                throw new IOException("Unmatched DNS response");
            }
            return payload[3] & 15;
        }
    }
}
