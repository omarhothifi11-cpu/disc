import asyncio
from getpass import getpass
import json
import socket
import struct
import time
import aiohttp
import websockets

try:
    import davey
except ImportError:
    print("[-] Missing 'davey' library! Run: pip install davey aiohttp websockets")
    raise SystemExit(1)

TOKEN = input("Enter discord token account: ").strip()
CHANNEL_ID = input("Enter Voice Channel (Room) ID: ").strip()

MAIN_GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"


async def get_channel_info(token, channel_id):
    headers = {
        "Authorization": token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://discord.com/api/v10/channels/{channel_id}", headers=headers) as resp:
            if resp.status != 200:
                print(f"[-] HTTP {resp.status}: Invalid Token or Channel ID.")
                return None
            return await resp.json()


def discover_udp_ip(ip, port, ssrc):
    """Performs UDP hole-punching and IP discovery with Discord's media server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    try:
        packet = struct.pack(">HHI", 1, 70, ssrc) + b"\x00" * 66
        sock.sendto(packet, (ip, port))
        data, _ = sock.recvfrom(74)
        ip_end = data.index(0, 8)
        ext_ip = data[8:ip_end].decode("ascii")
        ext_port = struct.unpack_from(">H", data, 72)[0]
        return ext_ip, ext_port, sock
    except Exception:
        return ip, port, sock


async def handle_rtc_websocket(endpoint, server_id, dave_group_id, user_id, session_id, token, label="VOICE"):
    """Connects to Discord Voice/Stream WebSocket v8 with full DAVE E2EE (Code 4017 fix)."""
    uri = f"wss://{endpoint}/?v=8"
    udp_sock = None
    hb_task = None
    udp_task = None

    try:
        async with websockets.connect(uri, max_size=None) as vws:
            last_seq = -1
            dave_version = davey.DAVE_PROTOCOL_VERSION
            dave_session = None

            def init_dave(proto_ver):
                nonlocal dave_session, dave_version
                dave_version = proto_ver
                if proto_ver > 0:
                    dave_session = davey.DaveSession(proto_ver, int(user_id), int(dave_group_id))
                else:
                    dave_session = None

            async def send_key_package():
                if dave_session:
                    kp = dave_session.get_serialized_key_package()
                    # Binary Opcode 26 (MLS_KEY_PACKAGE)
                    await vws.send(b"\x1a" + kp)

            # 1. Send OP 0 (Identify) WITH max_dave_protocol_version
            identify_payload = {
                "op": 0,
                "d": {
                    "server_id": str(server_id),
                    "user_id": str(user_id),
                    "session_id": session_id,
                    "token": token,
                    "video": True,
                    "streams": [{"type": "screen", "rid": "100", "quality": 100}],
                    "max_dave_protocol_version": dave_version
                }
            }
            await vws.send(json.dumps(identify_payload))

            async def voice_heartbeat(interval_sec):
                while True:
                    await asyncio.sleep(interval_sec)
                    try:
                        await vws.send(json.dumps({
                            "op": 3,
                            "d": {
                                "t": int(time.time() * 1000),
                                "seq_ack": last_seq
                            }
                        }))
                    except Exception:
                        break

            async def udp_keepalive(sock, ip, port):
                while True:
                    await asyncio.sleep(15)
                    try:
                        sock.sendto(b"\x80\xc8\x00\x06\x00\x00\x00\x00", (ip, port))
                    except Exception:
                        break

            audio_ssrc = 0
            video_ssrc = 0
            rtx_ssrc = 0

            async for raw in vws:
                # --- Handle Binary DAVE MLS Opcodes (25, 27, 29, 30) ---
                if isinstance(raw, bytes):
                    if len(raw) < 3:
                        continue
                    last_seq = struct.unpack_from(">H", raw, 0)[0]
                    bin_op = raw[2]

                    if not dave_session:
                        init_dave(dave_version or 1)

                    if bin_op == 25:  # MLS_EXTERNAL_SENDER
                        dave_session.set_external_sender(raw[3:])

                    elif bin_op == 27:  # MLS_PROPOSALS
                        optype_int = raw[3]
                        optype = (
                            davey.ProposalsOperationType.append
                            if optype_int == 0
                            else davey.ProposalsOperationType.revoke
                        )
                        res = dave_session.process_proposals(optype, raw[4:])
                        if res:
                            if hasattr(res, "commit"):
                                payload = res.commit + (res.welcome if getattr(res, "welcome", None) else b"")
                            else:
                                payload = bytes(res)
                            # Binary Opcode 28 (MLS_COMMIT_WELCOME)
                            await vws.send(b"\x1c" + payload)

                    elif bin_op == 29:  # MLS_ANNOUNCE_COMMIT_TRANSITION
                        transition_id = struct.unpack_from(">H", raw, 3)[0]
                        try:
                            dave_session.process_commit(raw[5:])
                            dave_session.prepare_transition(transition_id, dave_version)
                            if transition_id != 0:
                                await vws.send(json.dumps({"op": 23, "d": {"transition_id": transition_id}}))
                        except Exception:
                            await vws.send(json.dumps({"op": 31, "d": {"transition_id": transition_id}}))
                            init_dave(dave_version)
                            await send_key_package()

                    elif bin_op == 30:  # MLS_WELCOME
                        transition_id = struct.unpack_from(">H", raw, 3)[0]
                        try:
                            dave_session.process_welcome(raw[5:])
                            dave_session.prepare_transition(transition_id, dave_version)
                            if transition_id != 0:
                                await vws.send(json.dumps({"op": 23, "d": {"transition_id": transition_id}}))
                        except Exception:
                            await vws.send(json.dumps({"op": 31, "d": {"transition_id": transition_id}}))
                            init_dave(dave_version)
                            await send_key_package()
                    continue

                # --- Handle JSON Opcodes ---
                data = json.loads(raw)
                op = data.get("op")
                d = data.get("d", {})
                if data.get("seq") is not None:
                    last_seq = data["seq"]

                if op == 8:  # HELLO
                    interval = d["heartbeat_interval"] / 1000.0
                    if hb_task:
                        hb_task.cancel()
                    hb_task = asyncio.create_task(voice_heartbeat(interval))

                elif op == 2:  # READY
                    audio_ssrc = d["ssrc"]
                    ip = d["ip"]
                    port = d["port"]
                    modes = d.get("modes", [])
                    streams = d.get("streams", [])

                    if streams:
                        video_ssrc = streams[0].get("ssrc", audio_ssrc + 1)
                        rtx_ssrc = streams[0].get("rtx_ssrc", audio_ssrc + 2)
                    else:
                        video_ssrc = audio_ssrc + 1
                        rtx_ssrc = audio_ssrc + 2

                    if "aead_aes256_gcm_rtpsize" in modes:
                        selected_mode = "aead_aes256_gcm_rtpsize"
                    elif "aead_xchacha20_poly1305_rtpsize" in modes:
                        selected_mode = "aead_xchacha20_poly1305_rtpsize"
                    else:
                        selected_mode = modes[0]

                    ext_ip, ext_port, udp_sock = await asyncio.get_event_loop().run_in_executor(
                        None, discover_udp_ip, ip, port, audio_ssrc
                    )
                    udp_task = asyncio.create_task(udp_keepalive(udp_sock, ip, port))

                    # OP 1: Select Protocol
                    await vws.send(json.dumps({
                        "op": 1,
                        "d": {
                            "protocol": "udp",
                            "data": {
                                "address": ext_ip,
                                "port": ext_port,
                                "mode": selected_mode
                            },
                            "codecs": [
                                {"name": "opus", "type": "audio", "priority": 1000, "payload_type": 120},
                                {
                                    "name": "H264",
                                    "type": "video",
                                    "priority": 1000,
                                    "payload_type": 101,
                                    "rtx_payload_type": 102,
                                    "encode": True,
                                    "decode": True
                                }
                            ]
                        }
                    }))

                elif op == 4:  # SESSION_DESCRIPTION
                    proto_ver = d.get("dave_protocol_version", 1)
                    init_dave(proto_ver)
                    if proto_ver > 0:
                        await send_key_package()

                    # OP 12: Video / Screen Stream SSRC Activation
                    await vws.send(json.dumps({
                        "op": 12,
                        "d": {
                            "audio_ssrc": audio_ssrc,
                            "video_ssrc": video_ssrc,
                            "rtx_ssrc": rtx_ssrc,
                            "streams": [
                                {
                                    "type": "video",
                                    "rid": "100",
                                    "ssrc": video_ssrc,
                                    "active": True,
                                    "quality": 100,
                                    "rtx_ssrc": rtx_ssrc,
                                    "max_bitrate": 2500000,
                                    "max_framerate": 30,
                                    "max_resolution": {"type": "fixed", "width": 1280, "height": 720}
                                }
                            ]
                        }
                    }))

                    await vws.send(json.dumps({
                        "op": 5,
                        "d": {"speaking": 0, "delay": 0, "ssrc": audio_ssrc}
                    }))
                    print(f"[+] [{label}] RTC signaling ready. This script does not send video frames.")

                elif op == 21:  # DAVE_PREPARE_TRANSITION
                    tid = d.get("transition_id", 0)
                    pver = d.get("protocol_version", dave_version)
                    dave_version = pver
                    if dave_session:
                        dave_session.prepare_transition(tid, pver)
                    if tid != 0:
                        await vws.send(json.dumps({"op": 23, "d": {"transition_id": tid}}))

                elif op == 22:  # DAVE_EXECUTE_TRANSITION
                    tid = d.get("transition_id", 0)
                    if dave_session:
                        try:
                            dave_session.execute_transition(tid)
                        except Exception:
                            pass

                elif op == 24:  # DAVE_PREPARE_EPOCH
                    epoch = d.get("epoch")
                    pver = d.get("protocol_version", dave_version)
                    if epoch == 1:
                        init_dave(pver)
                        await send_key_package()

    except websockets.exceptions.ConnectionClosed as e:
        print(f"[!] [{label}] WebSocket Closed (Code {e.code}: {e.reason})")
    except Exception as e:
        print(f"[!] [{label}] Error: {e}")
    finally:
        if hb_task:
            hb_task.cancel()
        if udp_task:
            udp_task.cancel()
        if udp_sock:
            udp_sock.close()


async def main():
    info = await get_channel_info(TOKEN, CHANNEL_ID)
    if not info:
        return

    guild_id = info.get("guild_id")
    room_name = info.get("name", CHANNEL_ID)
    print(f"[+] Target Voice Channel: #{room_name} (Guild ID: {guild_id})")

    while True:
        rtc_tasks = []
        try:
            async with websockets.connect(MAIN_GATEWAY, max_size=None) as ws:
                hello = json.loads(await ws.recv())
                hb_interval = hello["d"]["heartbeat_interval"] / 1000.0
                last_s = None

                async def gateway_heartbeat():
                    while True:
                        await asyncio.sleep(hb_interval)
                        try:
                            await ws.send(json.dumps({"op": 1, "d": last_s}))
                        except Exception:
                            break

                hb_task = asyncio.create_task(gateway_heartbeat())

                await ws.send(json.dumps({
                    "op": 2,
                    "d": {
                        "token": TOKEN,
                        "capabilities": 30717,
                        "properties": {
                            "os": "Windows",
                            "browser": "Discord Client",
                            "release_channel": "stable",
                            "client_version": "1.0.9185",
                            "os_version": "10.0.22631",
                            "os_arch": "x64",
                            "app_arch": "x64",
                            "system_locale": "en-US"
                        },
                        "presence": {
                            "status": "online",
                            "since": 0,
                            "activities": [],
                            "afk": False
                        },
                        "compress": False
                    }
                }))

                user_id = None
                voice_session_id = None
                voice_endpoint = None
                voice_token = None
                voice_connected = False
                rtc_server_id = None
                stream_channel_id = CHANNEL_ID

                async for raw_msg in ws:
                    msg = json.loads(raw_msg)
                    if msg.get("s") is not None:
                        last_s = msg["s"]

                    t = msg.get("t")
                    d = msg.get("d", {})

                    if t == "READY":
                        user_id = d["user"]["id"]
                        print(f"[+] Logged in as {d['user']['username']} ({user_id})")

                        await ws.send(json.dumps({
                            "op": 4,
                            "d": {
                                "guild_id": guild_id,
                                "channel_id": CHANNEL_ID,
                                "self_mute": False,
                                "self_deaf": False,
                                "self_video": False
                            }
                        }))

                    elif t == "VOICE_STATE_UPDATE":
                        if d.get("user_id") == user_id:
                            voice_session_id = d.get("session_id")
                            if d.get("self_stream"):
                                print("[+] Red LIVE Badge is ACTIVE (self_stream = True)!")

                    elif t == "VOICE_SERVER_UPDATE":
                        voice_endpoint = d.get("endpoint")
                        voice_token = d.get("token")

                    if voice_session_id and voice_endpoint and not voice_connected:
                        voice_connected = True
                        print("[*] Starting DAVE Voice WebSocket Handshake...")
                        rtc_tasks.append(asyncio.create_task(
                            handle_rtc_websocket(
                                voice_endpoint, guild_id, CHANNEL_ID, user_id, voice_session_id, voice_token, "VOICE"
                            )
                        ))

                        await asyncio.sleep(3)
                        print("[*] Sending OP 18 (Create Go-Live Stream)...")
                        await ws.send(json.dumps({
                            "op": 18,
                            "d": {
                                "type": "guild",
                                "guild_id": guild_id,
                                "channel_id": CHANNEL_ID,
                                "preferred_region": None
                            }
                        }))

                    elif t == "STREAM_CREATE":
                        stream_key = d.get("stream_key")
                        rtc_server_id = d.get("rtc_server_id")
                        stream_channel_id = d.get("rtc_channel_id") or rtc_server_id
                        print(f"[+] STREAM_CREATE received! key={stream_key}")

                        await ws.send(json.dumps({
                            "op": 22,
                            "d": {"stream_key": stream_key, "paused": False}
                        }))

                    elif t == "STREAM_SERVER_UPDATE":
                        s_endpoint = d.get("endpoint")
                        s_token = d.get("token")
                        if s_endpoint and rtc_server_id:
                            print("[*] Connecting to DAVE Go-Live Stream Server...")
                            rtc_tasks.append(asyncio.create_task(
                                handle_rtc_websocket(
                                    s_endpoint, rtc_server_id, stream_channel_id, user_id, voice_session_id, s_token, "GOLIVE-STREAM"
                                )
                            ))

                hb_task.cancel()

        except Exception as e:
            print(f"[!] Gateway disconnected ({e}). Reconnecting in 5s...")
        finally:
            for task in rtc_tasks:
                task.cancel()
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
