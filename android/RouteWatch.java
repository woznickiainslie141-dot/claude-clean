// SPDX-License-Identifier: MIT
package org.claudeclean;

import android.os.SystemClock;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/** On-device session started by the owner's authorized Android debug shell. */
public final class RouteWatch {
    static final String TARGET = "com.anthropic.claude", VPN = "com.sakura.app";
    static final Path DIR = Paths.get("/data/local/tmp/claude-clean-watch");
    static final Set<String> REMOTE = new HashSet<>(Arrays.asList("trojan","shadowsocks","shadowsocksr",
            "vmess","vless","wireguard","hysteria","hysteria2","tuic","snell","http","socks5","anytls"));
    static final Pattern TUN = Pattern.compile("\\bdev\\s+(tun[0-9]+)\\b");
    static String user, uid, vpnUid;

    static String read(InputStream in, int limit) throws IOException {
        try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] block = new byte[8192];
            for (int n; (n = input.read(block)) != -1;) {
                if (out.size() + n > limit) throw new IOException("检测结果过长");
                out.write(block, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
        }
    }

    static String cmd(String... args) throws Exception {
        List<String> words = new ArrayList<>(Arrays.asList("/system/bin/timeout","4"));
        Collections.addAll(words, args);
        Process p = new ProcessBuilder(words).redirectErrorStream(true).start();
        try {
            String result = read(p.getInputStream(), 2_000_000);
            if (p.waitFor() != 0 || result.startsWith("Security exception") || result.startsWith("Error:"))
                throw new IOException("系统命令未完成 " + args[0]);
            return result;
        } finally { p.destroy(); }
    }

    static String get(String url, int timeout, int limit) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection(Proxy.NO_PROXY);
        try {
            c.setConnectTimeout(timeout); c.setReadTimeout(timeout); c.setUseCaches(false);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("Cache-Control", "no-cache");
            c.setRequestProperty("Connection", "close");
            if (c.getResponseCode() != 200) throw new IOException("检测服务未返回结果");
            return read(c.getInputStream(), limit);
        } finally { c.disconnect(); }
    }

    static JSONObject local(String path) throws Exception {
        return new JSONObject(get("http://127.0.0.1:39797" + path, 900, 4_000_000));
    }

    static String route() throws Exception {
        if (!local("/configs").getString("mode").equalsIgnoreCase("global"))
            throw new IOException("已离开全局代理模式");
        String name = "GLOBAL";
        List<String> chain = new ArrayList<>();
        while (chain.size() < 16 && !chain.contains(name)) {
            if (name.equalsIgnoreCase("DIRECT") || name.equalsIgnoreCase("PASS")) break;
            chain.add(name);
            JSONObject obj = local("/proxies/" + URLEncoder.encode(name, "UTF-8").replace("+","%20"));
            String kind = obj.getString("type").toLowerCase(Locale.ROOT);
            if (REMOTE.contains(kind)) return new org.json.JSONArray(chain).toString() + "/" + kind;
            if (!kind.equals("selector")) break;
            name = obj.getString("now");
        }
        throw new IOException("当前路径为直连或无法核验");
    }

    static String getUid(String pkg) throws Exception {
        Matcher m = Pattern.compile("(?m)^package:" + Pattern.quote(pkg) + "\\s+uid:(\\d+)$")
                .matcher(cmd("cmd","package","list","packages","-U","--user",user,pkg));
        if (!m.find()) throw new IOException("找不到应用 " + pkg);
        return m.group(1);
    }

    static void setup() throws Exception {
        user = cmd("am","get-current-user");
        if (!user.matches("[0-9]+") || !cmd("id","-u").equals("2000"))
            throw new IOException("需要本机授权的 Android 调试会话");
        uid = getUid(TARGET); vpnUid = getUid(VPN);
    }

    static String tunnel(String id) throws Exception {
        Matcher m = TUN.matcher(cmd("ip","route","get","192.0.2.1","uid",id));
        if (!m.find()) throw new IOException("应用或检测进程未走 VPN");
        return m.group(1);
    }

    static void checkVpn() throws Exception {
        if (!user.equals(cmd("am","get-current-user")) || !tunnel("2000").equals(tunnel(uid)))
            throw new IOException("用户或 VPN 路由已变");
        Set<String> owners = new HashSet<>();
        Pattern owner = Pattern.compile("\\bOwnerUid:\\s*(\\d+)");
        for (String line : cmd("dumpsys","connectivity").split("\n")) {
            if (line.contains("VPN CONNECTED") || line.contains("Transports: VPN")) {
                Matcher m = owner.matcher(line);
                if (m.find()) owners.add(m.group(1));
            }
        }
        if (!owners.equals(Collections.singleton(vpnUid))) throw new IOException("SakuraCat VPN 不在运行");
    }

    static String exitIp() throws Exception {
        checkVpn();
        String ip = get("https://api.ipify.org/", 3500, 64);
        if (!ip.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) throw new IOException("无法读取 IPv4 出口");
        InetAddress address = InetAddress.getByName(ip);
        if (!ip.equals(address.getHostAddress()) || address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress())
            throw new IOException("出口地址无效");
        return ip;
    }

    static String hash(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder text = new StringBuilder();
        for (byte b : digest) text.append(String.format(Locale.ROOT,"%02x",b));
        return text.toString();
    }

    static void write(String name, String text) throws Exception {
        Path temp = DIR.resolve(name + ".tmp");
        Files.write(temp, text.getBytes(StandardCharsets.UTF_8));
        Files.move(temp, DIR.resolve(name), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    static void notifyPhone(String message) throws Exception {
        cmd("cmd","notification","post","-t","手机代理保护","claude-clean-watch",message);
    }

    static boolean targetActive() throws Exception {
        String state = cmd("cmd","activity","get-uid-state",uid);
        if (!state.matches("[0-9]+\\s+\\([A-Za-z_]+\\)")) throw new IOException("无法识别应用进程状态");
        return !state.endsWith("(NONEXISTENT)");
    }

    interface Actions {
        boolean active() throws Exception;
        void stop() throws Exception;
    }
    static boolean enforce(Actions actions) throws Exception {
        if (!actions.active()) return false;
        actions.stop();
        return true;
    }

    static final Actions DEVICE = new Actions() {
        public boolean active() throws Exception { return targetActive(); }
        public void stop() throws Exception { cmd("am","force-stop","--user",user,TARGET); }
    };

    static String pin() throws Exception { return hash(route()) + "\n" + hash(exitIp()); }

    static void match(String actual, String expected, String message) throws IOException {
        if (!actual.equals(expected)) throw new IOException(message);
    }

    static void watch(String[] expected) throws Exception {
        ExecutorService io = Executors.newSingleThreadExecutor();
        Future<String> pending = null;
        long started = 0, nextProbe = 0, lastGood = 0, heartbeat = 0, verifyAfter = 0;
        boolean locked = false;
        String lastMessage = "", alarm = "", action = "";
        try {
            while (!Files.exists(DIR.resolve("stop"))) {
                long now = SystemClock.elapsedRealtime();
                String problem = null;
                boolean fresh = false;
                try {
                    if (lastGood != 0 && now - lastGood > 18000) {
                        lastGood = 0;
                        throw new IOException("出口检查超时或手机刚刚唤醒");
                    }
                    match(tunnel("2000"), tunnel(uid), "应用已离开 VPN");
                    match(hash(route()), expected[0], "代理节点已改变");
                    if (pending == null && now >= nextProbe) {
                        started = now;
                        pending = io.submit(() -> hash(exitIp()));
                    }
                    if (pending != null && pending.isDone()) {
                        Future<String> done = pending; pending = null; nextProbe = now + 5000;
                        match(done.get(), expected[1], "出口 IP 已改变");
                        lastGood = now; fresh = started >= verifyAfter;
                    } else if (pending != null && now - started > 11000) {
                        throw new IOException("出口核验未及时完成");
                    }
                } catch (Exception e) {
                    problem = e instanceof IOException && !(e instanceof java.net.SocketException)
                            && !(e instanceof java.net.SocketTimeoutException) ? e.getMessage() : "无法核验 SakuraCat 或出口";
                    if (problem == null) problem = "代理或出口核验失败";
                }
                if (problem != null) {
                    if (!locked) { locked = true; alarm = problem; action = ""; }
                    verifyAfter = now;
                    lastGood = 0;
                } else if (fresh && locked) { locked = false; }
                String message = lastGood == 0 ? "正在手机上核验出口。" : "已在手机上监测 SakuraCat 和 IPv4 出口。";
                if (locked) {
                    try {
                        if (enforce(DEVICE)) action = " 已请求停止运行中的 Claude。";
                    } catch (Exception e) { action = " 系统未确认停止操作，请手动强行停止 Claude。"; }
                    message = alarm + "。请检查节点。" + action;
                }
                boolean changed = !message.equals(lastMessage);
                if (changed) {
                    try { notifyPhone(message); lastMessage = message; }
                    catch (Exception ignored) { /* Keep enforcing and retry the handset notification. */ }
                }
                if (now >= heartbeat || changed) {
                    String state = locked ? "LOCKED" : lastGood == 0 ? "CHECKING" : "ARMED";
                    if (!message.equals(lastMessage)) state = "ALERT_ERROR";
                    write("status",state + " " + now);
                    heartbeat = now + 2500;
                }
                Thread.sleep(850);
            }
        } finally { io.shutdownNow(); }
    }

    static void fixture() throws Exception {
        final boolean[] running = {false};
        final int[] stops = {0};
        Actions fake = new Actions() {
            public boolean active() { return running[0]; }
            public void stop() { stops[0]++; running[0] = false; }
        };
        if (enforce(fake)) throw new AssertionError();
        for (String changed : Arrays.asList("direct","other-exit","missing")) {
            running[0] = true;
            try { match(changed,"trusted","fixture"); throw new AssertionError(); }
            catch (IOException expected) { if (!enforce(fake) || enforce(fake)) throw new AssertionError(); }
        }
        if (stops[0] != 3) throw new AssertionError();
        System.out.println("Simulated direct route, changed exit, missing VPN, running and idle app passed");
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("selftest")) { fixture(); return; }
        setup();
        if (args.length == 1 && args[0].equals("probe")) { System.out.println(pin()); return; }
        if (args.length != 1 || !args[0].equals("run"))
            throw new IOException("未知操作");
        try (RandomAccessFile lock = new RandomAccessFile(DIR.resolve("lock").toFile(),"rw");
             FileLock held = lock.getChannel().tryLock()) {
            if (held == null) throw new IOException("守护程序已在运行");
            String[] expected = new String(Files.readAllBytes(DIR.resolve("pin")),StandardCharsets.UTF_8).trim().split("\\s+");
            if (expected.length != 2 || !expected[0].matches("[0-9a-f]{64}") || !expected[1].matches("[0-9a-f]{64}"))
                throw new IOException("可信节点记录无效");
            write("status","CHECKING " + SystemClock.elapsedRealtime());
            write("pid","" + android.os.Process.myPid());
            try {
                watch(expected);
            } finally {
                write("status","STOPPED");
                notifyPhone("手机守护已停止。");
            }
        }
    }
}
