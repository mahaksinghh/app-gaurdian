package com.appguardian.privacy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.IOException
import java.net.URL
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

internal enum class DnsProvider(val label: String, val endpoint: String) {
    CLOUDFLARE("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    GOOGLE("Google", "https://dns.google/dns-query")
}

internal data class NetworkStatus(
    val provider: DnsProvider? = null,
    val blocked: Int = 0,
    val failed: Int = 0,
    val note: String? = null
)

class DnsProtectionService : VpnService() {
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var active: Session? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            stop()
            return START_NOT_STICKY
        }
        if (intent?.action != START || active != null) return START_NOT_STICKY

        val provider = DnsProvider.entries.firstOrNull { it.name == intent.getStringExtra(PROVIDER) }
        if (provider == null) {
            stop("Choose a DNS provider before starting protection.")
            return START_NOT_STICKY
        }

        try {
            val rules = DomainRules.parse(intent.getStringExtra(RULES).orEmpty())
            startForeground(NOTIFICATION_ID, notification(provider))
            val tunnel = Builder().setSession("AppGuardian DNS protection")
                .setMtu(DnsPackets.MTU)
                .setBlocking(true)
                .addAddress("10.211.0.1", 32)
                .addRoute("10.211.0.2", 32)
                .addDnsServer("10.211.0.2")
                .allowFamily(OsConstants.AF_INET6)
                .addDisallowedApplication(packageName)
                .establish()
                ?: throw IOException("Android VPN consent is unavailable")
            val session = try {
                Session(tunnel, provider, rules)
            } catch (error: Exception) {
                tunnel.close()
                throw error
            }
            active = session
            mutableStatus.value = NetworkStatus(provider)
            Thread({ process(session) }, "AppGuardian DNS packets").start()
        } catch (_: Exception) {
            stop("Android could not start DNS protection.")
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        handler.post { stop("Android ended the DNS protection session.") }
        super.onRevoke()
    }

    override fun onDestroy() {
        closeActive()
        if (mutableStatus.value.provider != null) mutableStatus.value = NetworkStatus()
        super.onDestroy()
    }

    private class Session(
        val descriptor: ParcelFileDescriptor,
        val provider: DnsProvider,
        val rules: Set<String>
    ) {
        val input = ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
        val output = try {
            ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
        } catch (error: IOException) {
            input.close()
            throw error
        }
        val workers = ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, ArrayBlockingQueue(16))
    }

    private fun process(session: Session) {
        val watch = StructPollfd().apply {
            fd = session.descriptor.fileDescriptor
            events = OsConstants.POLLIN.toShort()
        }
        val poll = arrayOf(watch)
        val bytes = ByteArray(DnsPackets.MTU)
        try {
            while (active === session) {
                if (Os.poll(poll, 500) == 0) continue
                if (watch.revents.toInt() and OsConstants.POLLIN == 0) break
                val count = session.input.read(bytes)
                if (count < 0) break
                val query = DnsPackets.decode(bytes, count) ?: continue
                if (DomainRules.blocks(query.hostname, session.rules)) {
                    respond(session, query, DnsPackets.error(query, 3), blocked = true)
                } else {
                    try {
                        session.workers.execute {
                            val response = runCatching { lookup(session.provider, query) }.getOrNull()
                            respond(session, query, response ?: DnsPackets.error(query, 2), failed = response == null)
                        }
                    } catch (_: RejectedExecutionException) {
                        respond(session, query, DnsPackets.error(query, 2), failed = true)
                    }
                }
            }
        } catch (_: Exception) {
            // Normal when Android or the user closes the tunnel.
        } finally {
            handler.post {
                if (active === session) stop("The DNS tunnel closed.")
            }
        }
    }

    private fun lookup(provider: DnsProvider, query: DnsPackets.Query): ByteArray {
        val connection = URL(provider.endpoint).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 4000
            connection.readTimeout = 4000
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.doOutput = true
            connection.useCaches = false
            connection.setRequestProperty("Accept", DNS_CONTENT_TYPE)
            connection.setRequestProperty("Content-Type", DNS_CONTENT_TYPE)
            connection.setFixedLengthStreamingMode(query.payload.size)
            connection.outputStream.use { it.write(query.payload) }
            if (connection.responseCode != 200 || connection.contentType?.substringBefore(';') != DNS_CONTENT_TYPE) {
                throw IOException("Unexpected DNS response")
            }
            return connection.inputStream.use { body ->
                val bytes = ByteArray(DnsPackets.MAX_DNS + 1)
                var size = 0
                while (size < bytes.size) {
                    val count = body.read(bytes, size, bytes.size - size)
                    if (count < 0) break
                    if (count == 0) throw IOException("Incomplete DNS response")
                    size += count
                }
                if (size !in 12..DnsPackets.MAX_DNS || bytes[0] != query.payload[0] ||
                    bytes[1] != query.payload[1] || bytes[2].toInt() and 0x80 == 0
                ) throw IOException("Invalid or oversized DNS response")
                bytes.copyOf(size)
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun respond(
        session: Session,
        query: DnsPackets.Query,
        dns: ByteArray,
        blocked: Boolean = false,
        failed: Boolean = false
    ) {
        synchronized(session.output) {
            if (active !== session) return
            try {
                session.output.write(DnsPackets.reply(query, dns))
                if (blocked || failed) mutableStatus.update { state ->
                    if (active !== session) state else state.copy(
                        blocked = state.blocked + if (blocked) 1 else 0,
                        failed = state.failed + if (failed) 1 else 0
                    )
                }
            } catch (_: IOException) {
                handler.post { if (active === session) stop("The DNS tunnel closed.") }
            }
        }
    }

    private fun closeActive() {
        val session = active ?: return
        active = null
        session.workers.shutdownNow()
        runCatching { session.descriptor.close() }
        runCatching { session.input.close() }
        runCatching { session.output.close() }
    }

    private fun stop(note: String? = null) {
        closeActive()
        mutableStatus.value = NetworkStatus(note = note)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(provider: DnsProvider): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "DNS protection", NotificationManager.IMPORTANCE_LOW))
        val stopAction = PendingIntent.getService(
            this,
            1,
            Intent(this, DnsProtectionService::class.java).setAction(STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("AppGuardian DNS protection is on")
            .setContentText("Using ${provider.label} DNS over HTTPS")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stopAction).build())
            .build()
    }

    internal companion object {
        const val START = "com.appguardian.privacy.START_DNS"
        const val STOP = "com.appguardian.privacy.STOP_DNS"
        const val PROVIDER = "provider"
        const val RULES = "rules"
        private const val CHANNEL = "appguardian.dns"
        private const val NOTIFICATION_ID = 312
        private const val DNS_CONTENT_TYPE = "application/dns-message"
        private val mutableStatus = MutableStateFlow(NetworkStatus())
        val status = mutableStatus.asStateFlow()
    }
}
