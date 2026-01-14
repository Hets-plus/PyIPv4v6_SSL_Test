#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PyIPv4v6_SSL_Test - SSL/TLS 测试工具
Copyright (c) 2026 by hets

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import os
import sys
import socket
import ssl
import threading
try:
    import Queue as queue
except ImportError:
    import queue as queue
import json
import binascii
import subprocess
import tempfile
from datetime import datetime

try:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    from ScrolledText import ScrolledText
except ImportError:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText


def is_ip_address(host):
    host = host.strip().strip("[]")
    if ":" in host:
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


class ConfigManager(object):
    def __init__(self, config_file="tls_config.json", log_dir=None):
        self.config_file = config_file
        self.log_dir = log_dir
        self.loaded_from_file = False
        self.config = self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    cfg = json.load(f)
                    self.loaded_from_file = True
                    return cfg
        except Exception:
            pass
        self.loaded_from_file = False
        return self.get_default_config()

    def get_default_config(self):
        return {
            "mode": "both",
            "server": {
                "port": 8443,
                "use_ipv6": False,
                "ssl_version": "Default",
                "auth_mode": "OneWay",
                "server_cert": "",
                "server_key": "",
                "ca_cert": "",
                "auto_reply": True,
                "data_mode": "Transparent"
            },
            "client": {
                "host": "127.0.0.1",
                "port": 8443,
                "auth_mode": "OneWay",
                "client_cert": "",
                "client_key": "",
                "ca_cert": "",
                "hex_send": False,
                "ssl_version": "Default",
                
            }
        }

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass

    def get_ssl_protocol(self, version_str):
        mapping = {
            "SSL 2.0": getattr(ssl, 'PROTOCOL_SSLv2', None),
            "SSL 3.0": getattr(ssl, 'PROTOCOL_SSLv3', None),
            "TLS 1.0": getattr(ssl, 'PROTOCOL_TLSv1', None),
            "TLS 1.1": getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            "TLS 1.2": getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            "Default": getattr(ssl, 'PROTOCOL_SSLv23', getattr(ssl, 'PROTOCOL_TLS', None))
        }
        return mapping.get(version_str, None)

    def append_log(self, line):
        _write_log_line(self.config_file, line, self.log_dir)


def _normalize_config_path(config_file):
    try:
        if hasattr(sys, "frozen"):
             config_base = os.path.dirname(sys.executable)
        else:
             config_base = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        config_base = os.getcwd()
    cfg = config_file or "tls_config.json"
    if not os.path.isabs(cfg):
        cfg = os.path.join(config_base, cfg)
    return cfg


def _resolve_config_relative(path_value, config_file):
    p = (path_value or "").strip()
    if not p:
        return ""
    
    if os.path.isabs(p) and os.path.exists(p):
        return p

    try:
        base_dir = os.path.dirname(os.path.abspath(config_file))
    except Exception:
        base_dir = os.getcwd()
    
    # Try absolute path fallback to relative basename
    if os.path.isabs(p):
        candidate = os.path.join(base_dir, os.path.basename(p))
        if os.path.exists(candidate):
            return candidate
        return p

    return os.path.join(base_dir, p)


def _stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _pick_log_dir(config_file, forced_log_dir=None):
    if forced_log_dir:
        try:
            if not os.path.exists(forced_log_dir):
                os.makedirs(forced_log_dir)
            return forced_log_dir
        except Exception:
            pass

    candidates = []
    try:
        cfg = _normalize_config_path(config_file)
        candidates.append(os.path.dirname(os.path.abspath(cfg)))
    except Exception:
        pass
    try:
        candidates.append(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass
    try:
        candidates.append(os.getcwd())
    except Exception:
        pass
    try:
        pd = os.environ.get("PROGRAMDATA") or os.environ.get("ProgramData")
        if pd:
            candidates.append(os.path.join(pd, "PyIPv6_TLS_Tool"))
    except Exception:
        pass

    for base_dir in candidates:
        if not base_dir:
            continue
        try:
            log_dir = os.path.join(base_dir, "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            test_file = os.path.join(log_dir, ".__write_test__")
            try:
                with open(test_file, "a"):
                    pass
                try:
                    os.remove(test_file)
                except Exception:
                    pass
            except Exception:
                continue
            return log_dir
        except Exception:
            continue

    try:
        fallback = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        if not os.path.exists(fallback):
            os.makedirs(fallback)
        return fallback
    except Exception:
        return None


def _write_log_line(config_file, text, log_dir=None):
    try:
        log_dir = _pick_log_dir(config_file, log_dir)
        if not log_dir:
            return
        log_file = os.path.join(log_dir, "tls_tool.log")
        line = (text or "").rstrip("\n") + "\n"
        try:
            with open(log_file, "a") as f:
                f.write(line)
        except Exception:
            try:
                with open(log_file, "ab") as f:
                    try:
                        f.write(line.encode("utf-8"))
                    except Exception:
                        f.write(str(line).encode("utf-8"))
            except Exception:
                pass
    except Exception:
        pass


def _headless_log(config_manager, text):
    line = "[{}] {}".format(_stamp(), text)
    try:
        print(line)
        sys.stdout.flush()
    except Exception:
        pass
    try:
        _write_log_line(getattr(config_manager, "config_file", None), line, getattr(config_manager, "log_dir", None))
    except Exception:
        pass


def append_fallback_log(config_file, text, log_dir=None):
    _write_log_line(config_file, text, log_dir)


class _HeadlessTLSServer(object):
    def __init__(self, config_manager, config_file, stop_event):
        self.config_manager = config_manager
        self.config_file = config_file
        self.stop_event = stop_event
        self.server_sock = None
        self.clients_lock = threading.Lock()
        self.clients = set()

    def _make_context(self):
        server_cfg = self.config_manager.config.get("server", {})
        ssl_version_str = server_cfg.get("ssl_version", "Default")
        protocol = self.config_manager.get_ssl_protocol(ssl_version_str)
        if not protocol:
             protocol = getattr(ssl, "PROTOCOL_SSLv23", getattr(ssl, "PROTOCOL_TLS", None))

        ctx = ssl.SSLContext(protocol)

        try:
            if hasattr(ctx, 'set_ciphers'):
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        except Exception:
            pass

        try:
            if ssl_version_str == "Default":
                 if hasattr(ssl, 'OP_NO_SSLv2'): ctx.options &= ~ssl.OP_NO_SSLv2
                 if hasattr(ssl, 'OP_NO_SSLv3'): ctx.options &= ~ssl.OP_NO_SSLv3
                 if hasattr(ssl, 'OP_NO_TLSv1'): ctx.options &= ~ssl.OP_NO_TLSv1
                 if hasattr(ssl, 'OP_NO_TLSv1_1'): ctx.options &= ~ssl.OP_NO_TLSv1_1
            else:
                 if hasattr(ssl, 'OP_NO_SSLv2'): ctx.options |= ssl.OP_NO_SSLv2
        except Exception:
            pass

        try:
             _headless_log(self.config_manager, "CTX build: version={} proto={} options=0x{:X} openssl={}".format(ssl_version_str, protocol, getattr(ctx, 'options', 0), getattr(ssl, 'OPENSSL_VERSION', 'unknown')))
        except Exception:
             pass

        cert = _resolve_config_relative(server_cfg.get("server_cert", ""), self.config_file)
        key = _resolve_config_relative(server_cfg.get("server_key", ""), self.config_file)
        if not cert or not key:
            raise RuntimeError("Server cert and key required in config")
        try:
            _headless_log(self.config_manager, "Server cert exists={} path={}".format(os.path.exists(cert), cert))
            _headless_log(self.config_manager, "Server key exists={} path={}".format(os.path.exists(key), key))
        except Exception:
            pass
        ctx.load_cert_chain(certfile=cert, keyfile=key)

        auth_mode = server_cfg.get("auth_mode", "OneWay")
        if auth_mode == "TwoWay":
            ca = _resolve_config_relative(server_cfg.get("ca_cert", ""), self.config_file)
            if not ca:
                raise RuntimeError("TwoWay auth requires CA cert")
            try:
                _headless_log(self.config_manager, "Server CA exists={} path={}".format(os.path.exists(ca), ca))
            except Exception:
                pass
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=ca)
        else:
            try:
                ctx.verify_mode = ssl.CERT_NONE
            except Exception:
                pass

        return ctx

    def stop(self):
        try:
            if self.server_sock:
                try:
                    self.server_sock.close()
                except Exception:
                    pass
        finally:
            with self.clients_lock:
                clients = list(self.clients)
                self.clients.clear()
            for s in clients:
                try:
                    s.close()
                except Exception:
                    pass

    def _handle_client(self, ssl_sock, addr, auto_reply, data_mode):
        try:
            _headless_log(self.config_manager, "Client handler start {}:{} auto_reply={} mode={}".format(addr[0], addr[1], auto_reply, data_mode))
        except Exception:
            pass

        try:
            while not self.stop_event.is_set():
                try:
                    ssl_sock.settimeout(1.0)
                    data = ssl_sock.recv(4096)
                    if not data:
                        _headless_log(self.config_manager, "Client disconnected (EOF) {}:{}".format(addr[0], addr[1]))
                        break
                    try:
                        _headless_log(self.config_manager, "<- {}:{}: {}".format(addr[0], addr[1], data.decode('utf-8')))
                    except Exception:
                        _headless_log(self.config_manager, "<- {}:{}: HEX {}".format(addr[0], addr[1], binascii.hexlify(data)))

                    if not auto_reply:
                        continue

                    if data_mode == "Transparent":
                        try:
                            ssl_sock.sendall(data)
                            try:
                                _headless_log(self.config_manager, "-> {}:{}: {}".format(addr[0], addr[1], data.decode('utf-8')))
                            except Exception:
                                _headless_log(self.config_manager, "-> {}:{}: HEX {}".format(addr[0], addr[1], binascii.hexlify(data)))
                        except Exception:
                            pass
                    elif data_mode == "Data":
                        default_payload = "START100raib18mkuz94k5ha9rys117x8v6g3klz93fn318z1d7pkg6wy2np4zl4zv5ilzpmwgshfv09dkwd7l9qw3l0zz100END"
                        payload = default_payload.encode("utf-8")
                        try:
                            ssl_sock.sendall(payload)
                            _headless_log(self.config_manager, "-> {}:{}: {}".format(addr[0], addr[1], default_payload))
                        except Exception:
                            pass
                    else:
                        # Default echo with info
                        reply = "Server received: {} bytes\n".format(len(data))
                        try:
                            ssl_sock.sendall(reply.encode("utf-8"))
                            _headless_log(self.config_manager, "-> {}:{}: {}".format(addr[0], addr[1], reply.strip()))
                        except Exception:
                            pass
                except socket.timeout:
                    continue
                except ssl.SSLError as e:
                    if 'timed out' in str(e):
                        continue
                    _headless_log(self.config_manager, "SSL error {}:{} - {}".format(addr[0], addr[1], e))
                    break
                except Exception as e:
                    _headless_log(self.config_manager, "Client handler error {}:{} - {}".format(addr[0], addr[1], e))
                    break
        finally:
            with self.clients_lock:
                try:
                    self.clients.discard(ssl_sock)
                except Exception:
                    pass
            try:
                ssl_sock.close()
            except Exception:
                pass
            _headless_log(self.config_manager, "Client disconnected: {}:{}".format(addr[0], addr[1]))

    def run(self):
        server_cfg = self.config_manager.config.get("server", {})
        port = int(server_cfg.get("port", 8443))
        use_ipv6 = bool(server_cfg.get("use_ipv6", False))
        auto_reply = bool(server_cfg.get("auto_reply", True))
        data_mode = server_cfg.get("data_mode", "Transparent")

        try:
            ctx = self._make_context()
        except Exception as e:
            _headless_log(self.config_manager, "Context error: {}".format(e))
            return 1

        family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
        bind_addr = "::" if use_ipv6 else "0.0.0.0"

        sock = socket.socket(family, socket.SOCK_STREAM)
        self.server_sock = sock
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            sock.bind((bind_addr, port))
            sock.listen(10)
            sock.settimeout(1.0)
        except Exception as e:
            _headless_log(self.config_manager, "Bind/listen failed {}:{} ({}) err={}".format(bind_addr, port, "IPv6" if use_ipv6 else "IPv4", e))
            try:
                sock.close()
            except Exception:
                pass
            return 1

        _headless_log(self.config_manager, "Server started on {}:{} ({})".format(bind_addr, port, "IPv6" if use_ipv6 else "IPv4"))

        try:
            while not self.stop_event.is_set():
                try:
                    client_sock, addr = sock.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.stop_event.is_set():
                        break
                    _headless_log(self.config_manager, "Accept error: {}".format(e))
                    continue

                try:
                    ssl_sock = ctx.wrap_socket(client_sock, server_side=True)
                    negotiated = None
                    try:
                        negotiated = ssl_sock.version()
                    except Exception:
                        negotiated = None
                    _headless_log(self.config_manager, "Client connected: {}:{} TLS={}".format(addr[0], addr[1], negotiated or 'unknown'))
                except Exception as e:
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    _headless_log(self.config_manager, "Handshake failed {}: {}".format(addr, e))
                    continue

                with self.clients_lock:
                    self.clients.add(ssl_sock)
                t = threading.Thread(target=self._handle_client, args=(ssl_sock, addr, auto_reply, data_mode))
                t.daemon = True
                t.start()
        finally:
            self.stop()
        return 0


def _headless_client_run(config_manager, config_file, stop_event):
    client_cfg = config_manager.config.get("client", {})
    host = (client_cfg.get("host") or "").strip() or "127.0.0.1"
    port = int(client_cfg.get("port", 8443))
    auth_mode = (client_cfg.get("auth_mode") or "").strip() or "OneWay"
    ssl_version_str = (client_cfg.get("ssl_version") or "Default").strip()

    protocol = config_manager.get_ssl_protocol(ssl_version_str)
    if not protocol:
        protocol = getattr(ssl, "PROTOCOL_SSLv23", getattr(ssl, "PROTOCOL_TLS", None))

    ctx = ssl.SSLContext(protocol)
    try:
        ctx.check_hostname = False
    except Exception:
        pass

    ca = _resolve_config_relative(client_cfg.get("ca_cert", ""), config_file)
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        except Exception:
             try:
                 ctx.verify_mode = ssl.CERT_NONE
             except Exception:
                 pass
    else:
        try:
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            pass

    if auth_mode == "TwoWay":
        cert = _resolve_config_relative(client_cfg.get("client_cert", ""), config_file)
        key = _resolve_config_relative(client_cfg.get("client_key", ""), config_file)
        if cert and key:
            ctx.load_cert_chain(certfile=cert, keyfile=key)

    family = socket.AF_INET6 if is_ip_address(host) and ":" in host else socket.AF_INET
    tcp_sock = socket.socket(family, socket.SOCK_STREAM)
    tcp_sock.settimeout(10.0)
    _headless_log(config_manager, "Connecting to {}:{}".format(host, port))
    try:
        tcp_sock.connect((host.strip("[]"), port))
    except Exception as e:
        _headless_log(config_manager, "Connect failed: {}".format(e))
        return 1

    server_hostname = None if is_ip_address(host) else host.strip("[]")
    if hasattr(ctx, 'wrap_socket'):
        # Python 2.7 wrap_socket arguments might differ slightly but usually server_hostname is supported in newer 2.7.9+
        # If not supported, catch exception
        try:
            ssl_sock = ctx.wrap_socket(tcp_sock, server_hostname=server_hostname)
        except TypeError:
             ssl_sock = ctx.wrap_socket(tcp_sock)
    else:
        ssl_sock = ssl.wrap_socket(tcp_sock)

    ssl_sock.settimeout(1.0)
    try:
        _headless_log(config_manager, "Connected TLS={}".format(ssl_sock.version() or 'unknown'))
    except Exception:
        _headless_log(config_manager, "Connected")

    try:
        while not stop_event.is_set():
            try:
                data = ssl_sock.recv(4096)
                if not data:
                    break
                try:
                    _headless_log(config_manager, "<- {}".format(data.decode('utf-8')))
                except Exception:
                    _headless_log(config_manager, "<- HEX {}".format(binascii.hexlify(data)))
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass
    return 0


def run_headless(mode, config_file, stop_event=None, log_dir=None):
    cfg = _normalize_config_path(config_file)
    config_manager = ConfigManager(cfg, log_dir=log_dir)
    stop = stop_event or threading.Event()
    try:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    except Exception:
        user = ""
    try:
        cfg_exists = os.path.exists(cfg)
    except Exception:
        cfg_exists = False
    _headless_log(config_manager, "Headless start: mode={} config={} exists={} loaded={} cwd={} user={} exe={}".format(mode, cfg, cfg_exists, bool(getattr(config_manager, "loaded_from_file", False)), os.getcwd(), user, sys.executable))
    if mode == "server":
        server = _HeadlessTLSServer(config_manager, cfg, stop)
        return server.run()
    if mode == "client":
        return _headless_client_run(config_manager, cfg, stop)
    if mode == "both":
        server = _HeadlessTLSServer(config_manager, cfg, stop)
        server_thread = threading.Thread(target=server.run)
        server_thread.daemon = True
        server_thread.start()
        try:
            return _headless_client_run(config_manager, cfg, stop)
        finally:
            stop.set()
            server.stop()
    return 1


try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    class PyIPv6TLSToolService(win32serviceutil.ServiceFramework):
        _svc_name_ = "PyIPv6_TLS_Tool"
        _svc_display_name_ = "PyIPv6 TLS Tool"
        _svc_description_ = "Runs headless TLS server/client and restarts on failure."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            try:
                self._svc_actual_name = args[0] if args and len(args) else self._svc_name_
            except Exception:
                self._svc_actual_name = self._svc_name_
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._stop_requested = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_requested.set()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            try:
                service_name = getattr(self, "_svc_actual_name", self._svc_name_)
                root_dir = win32serviceutil.GetServiceCustomOption(service_name, "root", None)
                mode = win32serviceutil.GetServiceCustomOption(service_name, "mode", "server")
                config_file = win32serviceutil.GetServiceCustomOption(service_name, "config", "tls_config.json")
                log_dir = win32serviceutil.GetServiceCustomOption(service_name, "log_dir", "") or None
                try:
                    cfg_norm = _normalize_config_path(config_file)
                except Exception:
                    cfg_norm = config_file
                try:
                    append_fallback_log(cfg_norm, "[{}] service start name={} mode={} config={} root={} cwd={} exe={}".format(_stamp(), service_name, mode, cfg_norm, root_dir, os.getcwd(), sys.executable), log_dir=log_dir)
                except Exception:
                    pass

                if root_dir and os.path.isdir(root_dir):
                    try:
                        os.chdir(root_dir)
                    except Exception:
                        pass
                    try:
                        if root_dir not in sys.path:
                            sys.path.insert(0, root_dir)
                    except Exception:
                        pass

                servicemanager.LogInfoMsg("{} starting: mode={} config={}".format(service_name, mode, config_file))

                while not self._stop_requested.is_set():
                    try:
                        code = run_headless(mode, config_file, stop_event=self._stop_requested, log_dir=log_dir)
                    except Exception as e:
                        try:
                            cfg = _normalize_config_path(config_file)
                            append_fallback_log(cfg, "[{}] service exception: {}".format(_stamp(), e), log_dir=log_dir)
                        except Exception:
                            pass
                        code = 1
                    if self._stop_requested.is_set():
                        break
                    if code == 0:
                        win32event.WaitForSingleObject(self.hWaitStop, 1000)
                        continue
                    win32event.WaitForSingleObject(self.hWaitStop, 1000)
            finally:
                try:
                    servicemanager.LogInfoMsg("service stopped")
                except Exception:
                    pass
except Exception:
    PyIPv6TLSToolService = None


def _service_cli(argv):
    import argparse
    try:
        import win32serviceutil
        import win32service
    except Exception as e:
        raise RuntimeError("pywin32 not available: {}".format(e))

    def _find_pythonservice_exe():
        try:
            if hasattr(win32serviceutil, "LocatePythonServiceExe"):
                p = win32serviceutil.LocatePythonServiceExe()
                if p and os.path.exists(p):
                    return p
        except Exception:
            pass
        try:
            util_dir = os.path.dirname(os.path.abspath(win32serviceutil.__file__))
        except Exception:
            util_dir = ""
        candidates = []
        if util_dir:
            candidates.append(os.path.abspath(os.path.join(util_dir, "..", "pythonservice.exe")))
            candidates.append(os.path.abspath(os.path.join(util_dir, "..", "..", "pythonservice.exe")))
            candidates.append(os.path.abspath(os.path.join(util_dir, "..", "..", "pywin32_system32", "pythonservice.exe")))
            candidates.append(os.path.abspath(os.path.join(util_dir, "..", "..", "..", "pywin32_system32", "pythonservice.exe")))
        candidates.append(os.path.abspath(os.path.join(sys.prefix, "pythonservice.exe")))
        candidates.append(os.path.abspath(os.path.join(sys.prefix, "Lib", "site-packages", "pywin32_system32", "pythonservice.exe")))
        candidates.append(os.path.abspath(os.path.join(sys.prefix, "lib", "site-packages", "pywin32_system32", "pythonservice.exe")))
        for p in candidates:
            try:
                if p and os.path.exists(p):
                    return p
            except Exception:
                pass
        return None

    parser = argparse.ArgumentParser(prog="service")
    sub = parser.add_subparsers(dest="action")

    p_install = sub.add_parser("install")
    p_install.add_argument("--name", default="PyIPv6_TLS_Tool")
    p_install.add_argument("--display", default="PyIPv6 TLS Tool")
    p_install.add_argument("--mode", choices=["client", "server", "both"], default="server")
    p_install.add_argument("--config", default="tls_config.json")
    p_install.add_argument("--startup", choices=["auto", "manual"], default="auto")
    p_install.add_argument("--log-dir", dest="log_dir", default="")

    p_uninstall = sub.add_parser("uninstall")
    p_uninstall.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_start = sub.add_parser("start")
    p_start.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("--name", default="PyIPv6_TLS_Tool")

    p_status = sub.add_parser("status")
    p_status.add_argument("--name", default="PyIPv6_TLS_Tool")

    args = parser.parse_args(argv)

    if args.action == "install":
        cfg = _normalize_config_path(args.config)
        root_dir = os.path.dirname(os.path.abspath(__file__))
        start_type = win32service.SERVICE_AUTO_START if args.startup == "auto" else win32service.SERVICE_DEMAND_START
        python_class = os.path.splitext(os.path.abspath(__file__))[0] + ".PyIPv6TLSToolService"
        exe_name = _find_pythonservice_exe()
        try:
            if PyIPv6TLSToolService is not None:
                PyIPv6TLSToolService._svc_name_ = args.name
                PyIPv6TLSToolService._svc_display_name_ = args.display
        except Exception:
            pass
        try:
            install_kwargs = {
                "startType": start_type,
                "description": "Runs headless TLS server/client and restarts on failure.",
            }
            if exe_name:
                install_kwargs["exeName"] = exe_name
            win32serviceutil.InstallService(
                python_class,
                args.name,
                args.display,
                **install_kwargs
            )
        except Exception as e:
            try:
                import traceback
                sys.stderr.write("InstallService failed: {}\n".format(e))
                sys.stderr.write("python={}\n".format(sys.executable))
                sys.stderr.write("sys.prefix={}\n".format(sys.prefix))
                sys.stderr.write("pythonservice.exe={}\n".format(exe_name or "NOT_FOUND"))
                try:
                    msg = str(e)
                except Exception:
                    msg = ""
                if ("1073" in msg) or ("exists" in msg.lower() and "service" in msg.lower()):
                    sys.stderr.write("hint: service may already exist. try: --service uninstall --name {}\n".format(args.name))
                sys.stderr.write(traceback.format_exc() + "\n")
            except Exception:
                pass
            return 1
        try:
            win32serviceutil.SetServiceCustomOption(args.name, "mode", args.mode)
            win32serviceutil.SetServiceCustomOption(args.name, "config", cfg)
            win32serviceutil.SetServiceCustomOption(args.name, "root", root_dir)
            win32serviceutil.SetServiceCustomOption(args.name, "log_dir", args.log_dir)
        except Exception:
            pass
        try:
            win32serviceutil.StartService(args.name)
        except Exception:
            pass
        return 0

    if args.action == "uninstall":
        try:
            win32serviceutil.StopService(args.name)
        except Exception:
            pass
        win32serviceutil.RemoveService(args.name)
        return 0

    if args.action == "start":
        win32serviceutil.StartService(args.name)
        return 0

    if args.action == "stop":
        win32serviceutil.StopService(args.name)
        return 0

    if args.action == "status":
        st = win32serviceutil.QueryServiceStatus(args.name)
        print(st)
        return 0

    raise RuntimeError("Unknown action: {}".format(args.action))



class TLSServerApp(object):
    def __init__(self, root, config_manager):
        self.root = root
        self.config_manager = config_manager
        self.server_sock = None
        self.ssl_context = None
        self.clients = {}
        self.server_thread = None
        self.running = False
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()
        self.lock = threading.Lock()

        self.port_var = tk.IntVar(value=self.config_manager.config["server"]["port"])
        self.use_ipv6_var = tk.BooleanVar(value=self.config_manager.config["server"]["use_ipv6"])
        self.ssl_version_var = tk.StringVar(value=self.config_manager.config["server"]["ssl_version"])
        self.auth_mode_var = tk.StringVar(value=self.config_manager.config["server"]["auth_mode"])
        self.auto_reply_var = tk.BooleanVar(value=self.config_manager.config["server"]["auto_reply"])
        self.data_mode_var = tk.StringVar(value=self.config_manager.config["server"]["data_mode"])

        self.server_cert_path = tk.StringVar(value=self.config_manager.config["server"]["server_cert"])
        self.server_key_path = tk.StringVar(value=self.config_manager.config["server"]["server_key"])
        self.ca_cert_path = tk.StringVar(value=self.config_manager.config["server"]["ca_cert"])
        self._last_open_dir_server = ""

        self.sent_bytes = tk.IntVar(value=0)
        self.recv_bytes = tk.IntVar(value=0)
        self.send_text_cache = ""

        self._build_ui()
        self.root.after(100, self._process_ui_queue)

    def _build_ui(self):
        config_frame = ttk.LabelFrame(self.root, text="SSL/TCP Server")
        config_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        ttk.Label(config_frame, text="Version:").grid(row=0, column=0, padx=6, pady=6, sticky=tk.W)
        versions = ["Default", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"]
        ttk.Combobox(config_frame, textvariable=self.ssl_version_var, values=versions, width=10, state="readonly").grid(row=0, column=1, padx=2, pady=6)

        ttk.Label(config_frame, text="Auth:").grid(row=0, column=2, padx=6, pady=6, sticky=tk.W)
        auth_modes = ["OneWay", "TwoWay"]
        ttk.Combobox(config_frame, textvariable=self.auth_mode_var, values=auth_modes, width=10, state="readonly").grid(row=0, column=3, padx=2, pady=6)

        ttk.Button(config_frame, text="Server Cert...", command=self._choose_server_cert).grid(row=0, column=4, padx=6)
        self.server_cert_label = ttk.Label(config_frame, text="None")
        self.server_cert_label.grid(row=0, column=5, sticky=tk.W)

        ttk.Button(config_frame, text="Server Key...", command=self._choose_server_key).grid(row=0, column=6, padx=6)
        self.server_key_label = ttk.Label(config_frame, text="None")
        self.server_key_label.grid(row=0, column=7, sticky=tk.W)

        ttk.Button(config_frame, text="CA Cert...", command=self._choose_ca_cert).grid(row=0, column=8, padx=6)
        self.ca_cert_label = ttk.Label(config_frame, text="None")
        self.ca_cert_label.grid(row=0, column=9, sticky=tk.W)

        ttk.Label(config_frame, text="Port:").grid(row=1, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(config_frame, textvariable=self.port_var, width=8).grid(row=1, column=1, padx=2, pady=6)
        ttk.Checkbutton(config_frame, text="IPv6", variable=self.use_ipv6_var).grid(row=1, column=2, padx=6)
        self.listen_btn = ttk.Button(config_frame, text="Listen", command=self.toggle_server)
        self.listen_btn.grid(row=1, column=3, padx=6)
        ttk.Checkbutton(config_frame, text="Auto Reply", variable=self.auto_reply_var).grid(row=1, column=4, padx=6)
        ttk.Label(config_frame, text="Mode:").grid(row=1, column=5, padx=6, sticky=tk.W)
        data_modes = ["Transparent", "Data"]
        ttk.Combobox(config_frame, textvariable=self.data_mode_var, values=data_modes, width=8, state="readonly").grid(row=1, column=6, padx=2, pady=6)

        ttk.Label(config_frame, text="Sent:").grid(row=1, column=7, padx=6, sticky=tk.E)
        ttk.Entry(config_frame, textvariable=self.sent_bytes, width=10, state="readonly").grid(row=1, column=8, padx=2)
        ttk.Label(config_frame, text="Recv:").grid(row=1, column=9, padx=6, sticky=tk.E)
        ttk.Entry(config_frame, textvariable=self.recv_bytes, width=10, state="readonly").grid(row=1, column=10, padx=2)

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        client_frame = ttk.LabelFrame(main_frame, text="Clients")
        client_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))
        self.client_listbox = tk.Listbox(client_frame, width=25, height=15)
        self.client_listbox.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        client_btn_frame = ttk.Frame(client_frame)
        client_btn_frame.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(client_btn_frame, text="Disconnect", command=self._disconnect_selected_client).pack(side=tk.LEFT, padx=2)
        ttk.Button(client_btn_frame, text="Disconnect All", command=self._disconnect_all_clients).pack(side=tk.LEFT, padx=2)

        log_frame = ttk.LabelFrame(main_frame, text="Log")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))
        self.log = ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        ttk.Button(bottom_frame, text="Clear", command=self._clear_log).pack(side=tk.LEFT)
        self.send_text = tk.Text(bottom_frame, height=3)
        self.send_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        send_btn_frame = ttk.Frame(bottom_frame)
        send_btn_frame.pack(side=tk.RIGHT)
        ttk.Button(send_btn_frame, text="Send", command=self._send_to_selected).pack(pady=4)

        self.status_var = tk.StringVar(value="Server stopped")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status.pack(fill=tk.X, padx=8, pady=(0, 8))

        self._update_cert_labels()
        self._sync_send_text_cache()

    def _sync_send_text_cache(self):
        try:
            self.send_text_cache = self.send_text.get("1.0", tk.END).strip()
        except Exception:
            pass
        self.root.after(200, self._sync_send_text_cache)

    def _choose_server_cert(self):
        start_dir = os.path.dirname(self.server_cert_path.get()) if self.server_cert_path.get() else (self._last_open_dir_server or os.getcwd())
        path = filedialog.askopenfilename(title="Choose Server Cert", initialdir=start_dir, filetypes=[("PEM/CRT", "*.pem *.crt"), ("All", "*.*")])
        if path:
            try:
                self._last_open_dir_server = os.path.dirname(path)
            except Exception:
                pass
            self.server_cert_path.set(path)
            self.config_manager.config["server"]["server_cert"] = path
            self._update_cert_labels()

    def _choose_server_key(self):
        start_dir = os.path.dirname(self.server_key_path.get()) if self.server_key_path.get() else (self._last_open_dir_server or os.getcwd())
        path = filedialog.askopenfilename(title="Choose Server Key", initialdir=start_dir, filetypes=[("PEM/KEY", "*.pem *.key"), ("All", "*.*")])
        if path:
            try:
                self._last_open_dir_server = os.path.dirname(path)
            except Exception:
                pass
            self.server_key_path.set(path)
            self.config_manager.config["server"]["server_key"] = path
            self._update_cert_labels()

    def _choose_ca_cert(self):
        start_dir = os.path.dirname(self.ca_cert_path.get()) if self.ca_cert_path.get() else (self._last_open_dir_server or os.getcwd())
        path = filedialog.askopenfilename(title="Choose CA Cert", initialdir=start_dir, filetypes=[("PEM/CRT", "*.pem *.crt"), ("All", "*.*")])
        if path:
            self.ca_cert_path.set(path)
            self.config_manager.config["server"]["ca_cert"] = path
            self._update_cert_labels()
            try:
                self._last_open_dir_server = os.path.dirname(path)
            except Exception:
                pass

    

    def _update_cert_labels(self):
        self.server_cert_label.config(text=os.path.basename(self.server_cert_path.get()) if self.server_cert_path.get() else "None")
        self.server_key_label.config(text=os.path.basename(self.server_key_path.get()) if self.server_key_path.get() else "None")
        self.ca_cert_label.config(text=os.path.basename(self.ca_cert_path.get()) if self.ca_cert_path.get() else "None")

    def _clear_log(self):
        self.log.delete("1.0", tk.END)

    def _log(self, text):
        stamp = datetime.now().strftime("%m-%d %H:%M:%S")
        line = "[{}] {}".format(stamp, text)
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        try:
            self.config_manager.append_log(line)
        except Exception:
            pass

    def _status(self, text):
        self.status_var.set(text)

    def _process_ui_queue(self):
        while True:
            try:
                msg = self.ui_queue.get_nowait()
                self._log(msg)
            except queue.Empty:
                break
        self.root.after(100, self._process_ui_queue)

    def toggle_server(self):
        if not self.running:
            self.start_server()
        else:
            self.stop_server()

    def _build_ssl_context(self):
        protocol = self.config_manager.get_ssl_protocol(self.ssl_version_var.get())
        auth_mode = self.auth_mode_var.get()
        cert = _resolve_config_relative(self.server_cert_path.get(), self.config_manager.config_file)
        key = _resolve_config_relative(self.server_key_path.get(), self.config_manager.config_file)
        ca = _resolve_config_relative(self.ca_cert_path.get(), self.config_manager.config_file)
        if not cert or not key:
            raise Exception("Server cert and key required")
        ctx = None
        if hasattr(ssl, 'SSLContext') and protocol:
            ctx = ssl.SSLContext(protocol)
            try:
                if hasattr(ctx, 'set_ciphers'):
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                ver = self.ssl_version_var.get()
                if ver == "Default":
                    if hasattr(ssl, 'OP_NO_SSLv2'):
                        ctx.options &= ~ssl.OP_NO_SSLv2
                    if hasattr(ssl, 'OP_NO_SSLv3'):
                        ctx.options &= ~ssl.OP_NO_SSLv3
                    if hasattr(ssl, 'OP_NO_TLSv1'):
                        ctx.options &= ~ssl.OP_NO_TLSv1
                    if hasattr(ssl, 'OP_NO_TLSv1_1'):
                        ctx.options &= ~ssl.OP_NO_TLSv1_1
                else:
                    if hasattr(ssl, 'OP_NO_SSLv2'):
                        ctx.options |= ssl.OP_NO_SSLv2
            except Exception:
                pass
            try:
                self.ui_queue.put("CTX build: version={} proto={} options=0x{:X} auth={} ca={} openssl={}".format(self.ssl_version_var.get(), protocol, getattr(ctx, 'options', 0), auth_mode, bool(ca), getattr(ssl, 'OPENSSL_VERSION', 'unknown')))
            except Exception:
                pass
            if auth_mode == "TwoWay":
                ctx.verify_mode = ssl.CERT_REQUIRED
                if ca:
                    ctx.load_verify_locations(cafile=ca)
            else:
                try:
                    ctx.verify_mode = ssl.CERT_NONE
                except Exception:
                    pass
            ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    def start_server(self):
        version = self.ssl_version_var.get()
        proto = self.config_manager.get_ssl_protocol(version)
        if proto is None and version != "Default":
            messagebox.showerror("SSL Config", "{} not supported by current Python/OpenSSL".format(version))
            return
        try:
            self.ssl_context = self._build_ssl_context()
        except Exception as e:
            messagebox.showerror("SSL Config", str(e))
            return
        self.running = True
        self.stop_event.clear()
        self.listen_btn.config(text="Stop")
        self._status("Starting server on port {}".format(self.port_var.get()))
        t = threading.Thread(target=self._server_loop)
        t.daemon = True
        t.start()

    def stop_server(self):
        self.running = False
        self.stop_event.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        with self.lock:
            items = list(self.clients.items())
        for sock, (thread, addr) in items:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception:
                pass
        self.listen_btn.config(text="Listen")
        self._status("Server stopped")
        self._log("Server stopped")
        self.client_listbox.delete(0, tk.END)

    def _server_loop(self):
        try:
            family = socket.AF_INET6 if self.use_ipv6_var.get() else socket.AF_INET
            self.server_sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            bind_addr = "::" if self.use_ipv6_var.get() else "0.0.0.0"
            self.server_sock.bind((bind_addr, int(self.port_var.get())))
            self.server_sock.listen(10)
            self._log("Listening {}:{} ({})".format(bind_addr, self.port_var.get(), "IPv6" if self.use_ipv6_var.get() else "IPv4"))
            self._status("Server running - port {}".format(self.port_var.get()))
        except Exception as e:
            self.ui_queue.put("Server start failed: {}".format(e))
            self.root.after(0, self.stop_server)
            return
        while self.running and not self.stop_event.is_set():
            try:
                self.server_sock.settimeout(1.0)
                client_sock, addr = self.server_sock.accept()
                try:
                    if self.ssl_version_var.get() == "Default":
                        hdr = b""
                        try:
                            client_sock.settimeout(0.5)
                        except Exception:
                            pass
                        attempts = 0
                        while attempts < 10:
                            attempts += 1
                            try:
                                hdr = client_sock.recv(5, socket.MSG_PEEK)
                            except socket.timeout:
                                hdr = b""
                            except Exception:
                                hdr = b""
                            if hdr:
                                break
                            try:
                                self.ui_queue.put("Default peek retry {}: {}:{} hdr={}".format(attempts, addr[0], addr[1], binascii.hexlify(hdr)))
                            except Exception:
                                pass
                            try:
                                import time as _t
                                _t.sleep(0.05)
                            except Exception:
                                pass
                        try:
                            self.ui_queue.put("Default peek: {}:{} hdr={} attempts={}".format(addr[0], addr[1], binascii.hexlify(hdr), attempts))
                        except Exception:
                            pass
                        try:
                            client_sock.settimeout(5)
                        except Exception:
                            pass
                        chosen_sock = None
                        if hdr and len(hdr) >= 3:
                            try:
                                b0, b1, b2 = ord(hdr[0:1]), ord(hdr[1:2]), ord(hdr[2:3])
                            except Exception:
                                b0, b1, b2 = hdr[0], hdr[1], hdr[2]
                            if b0 == 0x16 and b1 == 0x03:
                                if b2 == 0x00 and getattr(ssl, 'PROTOCOL_SSLv3', None):
                                    try:
                                        self.ui_queue.put("Default choose: SSLv3 for {}:{}".format(addr[0], addr[1]))
                                    except Exception:
                                        pass
                                    chosen_sock = ssl.wrap_socket(
                                        client_sock,
                                        server_side=True,
                                        certfile=self.server_cert_path.get(),
                                        keyfile=self.server_key_path.get(),
                                        cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE,
                                        ca_certs=self.ca_cert_path.get() or None,
                                        ssl_version=ssl.PROTOCOL_SSLv3
                                    )
                                elif b2 == 0x01 and getattr(ssl, 'PROTOCOL_TLSv1', None):
                                    try:
                                        self.ui_queue.put("Default choose: TLS1.0 for {}:{}".format(addr[0], addr[1]))
                                    except Exception:
                                        pass
                                    chosen_sock = ssl.wrap_socket(
                                        client_sock,
                                        server_side=True,
                                        certfile=self.server_cert_path.get(),
                                        keyfile=self.server_key_path.get(),
                                        cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE,
                                        ca_certs=self.ca_cert_path.get() or None,
                                        ssl_version=ssl.PROTOCOL_TLSv1
                                    )
                                elif b2 == 0x02 and getattr(ssl, 'PROTOCOL_TLSv1_1', None):
                                    try:
                                        self.ui_queue.put("Default choose: TLS1.1 for {}:{}".format(addr[0], addr[1]))
                                    except Exception:
                                        pass
                                    chosen_sock = ssl.wrap_socket(
                                        client_sock,
                                        server_side=True,
                                        certfile=self.server_cert_path.get(),
                                        keyfile=self.server_key_path.get(),
                                        cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE,
                                        ca_certs=self.ca_cert_path.get() or None,
                                        ssl_version=ssl.PROTOCOL_TLSv1_1
                                    )
                                elif b2 == 0x03 and getattr(ssl, 'PROTOCOL_TLSv1_2', None):
                                    try:
                                        self.ui_queue.put("Default choose: TLS1.2 for {}:{}".format(addr[0], addr[1]))
                                    except Exception:
                                        pass
                                    chosen_sock = ssl.wrap_socket(
                                        client_sock,
                                        server_side=True,
                                        certfile=self.server_cert_path.get(),
                                        keyfile=self.server_key_path.get(),
                                        cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE,
                                        ca_certs=self.ca_cert_path.get() or None,
                                        ssl_version=ssl.PROTOCOL_TLSv1_2
                                    )
                            else:
                                try:
                                    b0 = hdr[0] if isinstance(hdr[0], int) else ord(hdr[0:1])
                                except Exception:
                                    b0 = 0
                                if (b0 & 0x80) and getattr(ssl, 'PROTOCOL_SSLv3', None):
                                    try:
                                        self.ui_queue.put("Default choose: SSLv2 ClientHello -> SSLv3 for {}:{}".format(addr[0], addr[1]))
                                    except Exception:
                                        pass
                                    chosen_sock = ssl.wrap_socket(
                                        client_sock,
                                        server_side=True,
                                        certfile=self.server_cert_path.get(),
                                        keyfile=self.server_key_path.get(),
                                        cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE,
                                        ca_certs=self.ca_cert_path.get() or None,
                                        ssl_version=ssl.PROTOCOL_SSLv3
                                    )
                        if chosen_sock is not None:
                            ssl_sock = chosen_sock
                        else:
                            try:
                                self.ui_queue.put("Default fallback context for {}:{}".format(addr[0], addr[1]))
                            except Exception:
                                pass
                            try:
                                client_sock.settimeout(5)
                            except Exception:
                                pass
                            if self.ssl_context is not None:
                                ssl_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                            else:
                                ssl_sock = ssl.wrap_socket(client_sock, server_side=True, certfile=self.server_cert_path.get(), keyfile=self.server_key_path.get(), cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE, ca_certs=self.ca_cert_path.get() or None)
                    else:
                        if self.ssl_context is not None:
                            ssl_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                        else:
                            ssl_sock = ssl.wrap_socket(client_sock, server_side=True, certfile=self.server_cert_path.get(), keyfile=self.server_key_path.get(), cert_reqs=ssl.CERT_REQUIRED if self.auth_mode_var.get() == "TwoWay" else ssl.CERT_NONE, ca_certs=self.ca_cert_path.get() or None)
                    self.ui_queue.put("Client connected: {}:{}".format(addr[0], addr[1]))
                    with self.lock:
                        th = threading.Thread(target=self._handle_client, args=(ssl_sock, addr))
                        th.daemon = True
                        self.clients[ssl_sock] = (th, addr)
                        th.start()
                    self.root.after(0, self._update_client_list)
                except ssl.SSLError as e:
                    try:
                        hdr2 = client_sock.recv(5, socket.MSG_PEEK)
                    except Exception:
                        hdr2 = b""
                    try:
                        self.ui_queue.put("SSL handshake failed {}: {} hdr={}".format(addr, e, binascii.hexlify(hdr2)))
                    except Exception:
                        self.ui_queue.put("SSL handshake failed {}: {}".format(addr, e))
                    try:
                        client_sock.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.ui_queue.put("Server error: {}".format(e))
                break


    def _handle_client(self, ssl_sock, addr):
        try:
            while self.running and not self.stop_event.is_set():
                try:
                    ssl_sock.settimeout(1.0)
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    self.recv_bytes.set(self.recv_bytes.get() + len(data))
                    try:
                        text = data.decode('utf-8')
                        self.ui_queue.put("<- {}:{}: {}".format(addr[0], addr[1], text))
                    except Exception:
                        self.ui_queue.put("<- {}:{}: HEX {}".format(addr[0], addr[1], binascii.hexlify(data)))
                    if self.auto_reply_var.get():
                        mode = self.data_mode_var.get()
                        if mode == "Transparent":
                            try:
                                ssl_sock.send(data)
                                self.sent_bytes.set(self.sent_bytes.get() + len(data))
                            except Exception:
                                pass
                        else:
                            default_payload = "START100raib18mkuz94k5ha9rys117x8v6g3klz93fn318z1d7pkg6wy2np4zl4zv5ilzpmwgshfv09dkwd7l9qw3l0zz100END"
                            text_to_send = self.send_text_cache if self.send_text_cache else default_payload
                            try:
                                payload = text_to_send.encode('utf-8')
                                ssl_sock.send(payload)
                                self.sent_bytes.set(self.sent_bytes.get() + len(payload))
                                self.ui_queue.put("-> {}:{}: {}".format(addr[0], addr[1], text_to_send))
                            except Exception:
                                pass
                except socket.timeout:
                    continue
                except ssl.SSLError as e:
                    try:
                        msg = str(e)
                    except Exception:
                        msg = ''
                    if 'timed out' in msg:
                        continue
                    break
                except Exception:
                    break
        except Exception as e:
            self.ui_queue.put("Client error {}: {}".format(addr, e))
        finally:
            self._remove_client(ssl_sock, addr)

    def _remove_client(self, ssl_sock, addr):
        try:
            try:
                ssl_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            ssl_sock.close()
        except Exception:
            pass
        with self.lock:
            if ssl_sock in self.clients:
                del self.clients[ssl_sock]
        self.ui_queue.put("Client disconnected: {}:{}".format(addr[0], addr[1]))
        self.root.after(0, self._update_client_list)

    def _update_client_list(self):
        self.client_listbox.delete(0, tk.END)
        with self.lock:
            for sock, (thread, addr) in self.clients.items():
                self.client_listbox.insert(tk.END, "{}:{}".format(addr[0], addr[1]))

    def _disconnect_selected_client(self):
        selection = self.client_listbox.curselection()
        if not selection:
            return
        with self.lock:
            clients_list = list(self.clients.items())
        if selection[0] < len(clients_list):
            sock, (thread, addr) = clients_list[selection[0]]
            self._remove_client(sock, addr)

    def _disconnect_all_clients(self):
        with self.lock:
            clients_copy = list(self.clients.items())
        for sock, (thread, addr) in clients_copy:
            self._remove_client(sock, addr)

    def _send_to_selected(self):
        selection = self.client_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Client", "Select a client")
            return
        text = self.send_text.get("1.0", tk.END).strip()
        if not text:
            return
        with self.lock:
            clients_list = list(self.clients.items())
        if selection[0] < len(clients_list):
            sock, (thread, addr) = clients_list[selection[0]]
            try:
                sock.send(text.encode('utf-8'))
                self.sent_bytes.set(self.sent_bytes.get() + len(text))
                self._log("-> {}:{}: {}".format(addr[0], addr[1], text))
            except Exception as e:
                self._log("Send failed {}: {}".format(addr, e))


class TLSClientApp(object):
    def __init__(self, root, config_manager):
        self.root = root
        self.config_manager = config_manager
        self.ssl_sock = None
        self.tcp_sock = None
        self.recv_thread = None
        self.connected = False
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()

        self.host_var = tk.StringVar(value=self.config_manager.config["client"]["host"])
        self.port_var = tk.IntVar(value=self.config_manager.config["client"]["port"])
        self.auth_mode_var = tk.StringVar(value=self.config_manager.config["client"]["auth_mode"])
        self.hex_send_var = tk.BooleanVar(value=self.config_manager.config["client"]["hex_send"])
        self.ssl_version_var = tk.StringVar(value=self.config_manager.config["client"].get("ssl_version", "Default"))

        self.sent_bytes = tk.IntVar(value=0)
        self.recv_bytes = tk.IntVar(value=0)

        self.ca_cert_path = tk.StringVar(value=self.config_manager.config["client"]["ca_cert"])
        self.client_cert_path = tk.StringVar(value=self.config_manager.config["client"]["client_cert"])
        self.client_key_path = tk.StringVar(value=self.config_manager.config["client"]["client_key"])
        self._last_open_dir_client = ""

        self._build_ui()
        self.root.after(100, self._process_ui_queue)

    def _build_ui(self):
        top = ttk.LabelFrame(self.root, text="SSL/TCP Client")
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        ttk.Label(top, text="Auth:").grid(row=0, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Combobox(top, textvariable=self.auth_mode_var, values=["OneWay", "TwoWay"], width=6, state="readonly").grid(row=0, column=1, padx=2, pady=6)

        ttk.Button(top, text="Client Cert...", command=self._choose_client_cert).grid(row=0, column=2, padx=6)
        self.client_cert_label = ttk.Label(top, text="None")
        self.client_cert_label.grid(row=0, column=3, sticky=tk.W)

        ttk.Button(top, text="Client Key...", command=self._choose_client_key).grid(row=0, column=4, padx=6)
        self.client_key_label = ttk.Label(top, text="None")
        self.client_key_label.grid(row=0, column=5, sticky=tk.W)

        ttk.Button(top, text="CA Cert...", command=self._choose_ca_cert).grid(row=0, column=6, padx=6)
        self.ca_cert_label = ttk.Label(top, text="None")
        self.ca_cert_label.grid(row=0, column=7, sticky=tk.W)

        ttk.Label(top, text="Version:").grid(row=0, column=8, padx=6, pady=6, sticky=tk.W)
        versions = ["Default", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"]
        ttk.Combobox(top, textvariable=self.ssl_version_var, values=versions, width=8, state="readonly").grid(row=0, column=9, padx=2, pady=6, sticky=tk.W)

        ttk.Label(top, text="Host:").grid(row=1, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(top, textvariable=self.host_var, width=18).grid(row=1, column=1, padx=2, pady=6)
        ttk.Label(top, text="Port:").grid(row=1, column=2, padx=6, pady=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=1, column=3, padx=2, pady=6, sticky=tk.W)
        self.connect_btn = ttk.Button(top, text="Connect", command=self.toggle_connect)
        self.connect_btn.grid(row=1, column=4, padx=6)
        ttk.Label(top, text="Sent:").grid(row=1, column=5, padx=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.sent_bytes, width=10, state="readonly").grid(row=1, column=6, padx=2, sticky=tk.W)
        ttk.Label(top, text="Recv:").grid(row=1, column=7, padx=6, sticky=tk.E)
        ttk.Entry(top, textvariable=self.recv_bytes, width=10, state="readonly").grid(row=1, column=8, padx=2, sticky=tk.W)

        self.log = ScrolledText(self.root, wrap=tk.WORD, height=18)
        self.log.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        bottom = ttk.Frame(self.root)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        ttk.Button(bottom, text="Clear", command=self._clear_log).pack(side=tk.LEFT)
        self.send_text = tk.Text(bottom, height=4)
        self.send_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Checkbutton(bottom, text="Hex", variable=self.hex_send_var).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Send", command=self.send_message).pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(value="Disconnected")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status.pack(fill=tk.X, padx=8, pady=(0, 8))
        if hasattr(self.root, 'protocol'):
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._update_cert_labels()

    def _update_cert_labels(self):
        try:
            self.client_cert_label.config(text=os.path.basename(self.client_cert_path.get()) if self.client_cert_path.get() else "None")
        except Exception:
            pass
        try:
            self.client_key_label.config(text=os.path.basename(self.client_key_path.get()) if self.client_key_path.get() else "None")
        except Exception:
            pass
        try:
            self.ca_cert_label.config(text=os.path.basename(self.ca_cert_path.get()) if self.ca_cert_path.get() else "None")
        except Exception:
            pass

    def _choose_client_cert(self):
        start_dir = os.path.dirname(self.client_cert_path.get()) if self.client_cert_path.get() else (self._last_open_dir_client or os.getcwd())
        path = filedialog.askopenfilename(title="Choose Client Cert", initialdir=start_dir, filetypes=[("PEM/CRT", "*.pem *.crt"), ("All", "*.*")])
        if path:
            self.client_cert_path.set(path)
            self.config_manager.config["client"]["client_cert"] = path
            self.client_cert_label.config(text=os.path.basename(path))
            try:
                self._last_open_dir_client = os.path.dirname(path)
            except Exception:
                pass

    def _choose_client_key(self):
        start_dir = os.path.dirname(self.client_key_path.get()) if self.client_key_path.get() else (self._last_open_dir_client or os.getcwd())
        path = filedialog.askopenfilename(title="Choose Client Key", initialdir=start_dir, filetypes=[("PEM/KEY", "*.pem *.key"), ("All", "*.*")])
        if path:
            self.client_key_path.set(path)
            self.config_manager.config["client"]["client_key"] = path
            self.client_key_label.config(text=os.path.basename(path))
            try:
                self._last_open_dir_client = os.path.dirname(path)
            except Exception:
                pass

    def _choose_ca_cert(self):
        start_dir = os.path.dirname(self.ca_cert_path.get()) if self.ca_cert_path.get() else (self._last_open_dir_client or os.getcwd())
        path = filedialog.askopenfilename(title="Choose CA Cert", initialdir=start_dir, filetypes=[("PEM/CRT", "*.pem *.crt"), ("All", "*.*")])
        if path:
            self.ca_cert_path.set(path)
            self.config_manager.config["client"]["ca_cert"] = path
            self.ca_cert_label.config(text=os.path.basename(path))
            try:
                self._last_open_dir_client = os.path.dirname(path)
            except Exception:
                pass

    def _clear_log(self):
        self.log.delete("1.0", tk.END)

    def _log(self, text):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = "[{}] {}".format(stamp, text)
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        try:
            self.config_manager.append_log(line)
        except Exception:
            pass

    def _status(self, text):
        self.status_var.set(text)

    def _process_ui_queue(self):
        while True:
            try:
                msg = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            self._log(msg)
        self.root.after(100, self._process_ui_queue)

    def toggle_connect(self):
        if not self.connected:
            self._connect()
        else:
            self._disconnect()

    def _build_context(self):
        mode = self.auth_mode_var.get()
        ca = _resolve_config_relative(self.ca_cert_path.get(), self.config_manager.config_file) or None
        cert = _resolve_config_relative(self.client_cert_path.get(), self.config_manager.config_file) or None
        key = _resolve_config_relative(self.client_key_path.get(), self.config_manager.config_file) or None
        version = self.ssl_version_var.get()
        protocol = self.config_manager.get_ssl_protocol(version)
        ctx = None
        if hasattr(ssl, 'SSLContext') and protocol:
            if mode == "TwoWay":
                ctx = ssl.SSLContext(protocol)
                try:
                    if hasattr(ctx, 'set_ciphers'):
                        ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                    if version == "Default":
                        if hasattr(ssl, 'OP_NO_SSLv2'):
                            ctx.options &= ~ssl.OP_NO_SSLv2
                        if hasattr(ssl, 'OP_NO_SSLv3'):
                            ctx.options &= ~ssl.OP_NO_SSLv3
                        if hasattr(ssl, 'OP_NO_TLSv1'):
                            ctx.options &= ~ssl.OP_NO_TLSv1
                        if hasattr(ssl, 'OP_NO_TLSv1_1'):
                            ctx.options &= ~ssl.OP_NO_TLSv1_1
                    else:
                        if hasattr(ssl, 'OP_NO_SSLv2'):
                            ctx.options |= ssl.OP_NO_SSLv2
                except Exception:
                    pass
                if ca:
                    ctx.load_verify_locations(cafile=ca)
                ctx.check_hostname = False
                if not cert or not key:
                    raise Exception("Client cert and key required")
                ctx.load_cert_chain(certfile=cert, keyfile=key)
            else:
                if ca:
                    ctx = ssl.SSLContext(protocol)
                    try:
                        if hasattr(ctx, 'set_ciphers'):
                            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                        if version == "Default":
                            if hasattr(ssl, 'OP_NO_SSLv2'):
                                ctx.options &= ~ssl.OP_NO_SSLv2
                            if hasattr(ssl, 'OP_NO_SSLv3'):
                                ctx.options &= ~ssl.OP_NO_SSLv3
                            if hasattr(ssl, 'OP_NO_TLSv1'):
                                ctx.options &= ~ssl.OP_NO_TLSv1
                            if hasattr(ssl, 'OP_NO_TLSv1_1'):
                                ctx.options &= ~ssl.OP_NO_TLSv1_1
                        else:
                            if hasattr(ssl, 'OP_NO_SSLv2'):
                                ctx.options |= ssl.OP_NO_SSLv2
                    except Exception:
                        pass
                    ctx.load_verify_locations(cafile=ca)
                    ctx.check_hostname = False
                    try:
                        ctx.verify_mode = ssl.CERT_REQUIRED
                    except Exception:
                        pass
                else:
                    try:
                        ctx = ssl._create_unverified_context()
                    except Exception:
                        ctx = None
        return ctx

    def _connect(self):
        host = self.host_var.get().strip().strip("[]")
        port = int(self.port_var.get())
        version = self.ssl_version_var.get()
        proto = self.config_manager.get_ssl_protocol(version)
        if version != "Default" and proto is None:
            messagebox.showerror("SSL Config", "{} not supported by current Python/OpenSSL".format(version))
            return
        try:
            ctx = self._build_context()
        except Exception as e:
            messagebox.showerror("SSL Config", str(e))
            return
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            messagebox.showerror("DNS", "{}:{} -> {}".format(host, port, e))
            return
        last_err = None
        for family, socktype, proto, canonname, sockaddr in infos:
            try:
                s = socket.socket(family, socktype, proto)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                except Exception:
                    pass
                s.settimeout(5)
                s.connect(sockaddr)
                s.settimeout(None)
                self.tcp_sock = s
                break
            except Exception as e:
                last_err = e
                try:
                    s.close()
                except Exception:
                    pass
                self.tcp_sock = None
        if not self.tcp_sock:
            messagebox.showerror("Connect", "Cannot connect {}:{}\n{}".format(host, port, last_err))
            return
        try:
            server_hostname = None if is_ip_address(host) else host
            if ctx is not None and hasattr(ctx, 'wrap_socket'):
                self.ssl_sock = ctx.wrap_socket(self.tcp_sock, server_hostname=server_hostname)
            else:
                self.ssl_sock = ssl.wrap_socket(self.tcp_sock)
            try:
                self.ssl_sock.settimeout(None)
            except Exception:
                pass
        except Exception as e:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
            self.tcp_sock = None
            messagebox.showerror("TLS", str(e))
            return
        self.connected = True
        self.stop_event.clear()
        self.connect_btn.config(text="Disconnect")
        self._status("Connected")
        t = threading.Thread(target=self._recv_loop)
        t.daemon = True
        t.start()

    

    def _disconnect(self):
        self.stop_event.set()
        self.connected = False
        try:
            if self.ssl_sock:
                try:
                    self.ssl_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.ssl_sock.close()
        finally:
            self.ssl_sock = None
        try:
            if self.tcp_sock:
                self.tcp_sock.close()
        finally:
            self.tcp_sock = None
        self.connect_btn.config(text="Connect")
        self._status("Disconnected")
        self._log("Disconnected")

    def _recv_loop(self):
        while not self.stop_event.is_set() and self.ssl_sock:
            try:
                data = self.ssl_sock.recv(4096)
                if not data:
                    self.ui_queue.put("Peer closed")
                    break
                self.recv_bytes.set(self.recv_bytes.get() + len(data))
                try:
                    text = data.decode("utf-8")
                    self.ui_queue.put("<- {}".format(text))
                except Exception:
                    self.ui_queue.put("<- HEX {}".format(binascii.hexlify(data)))
            except socket.timeout:
                continue
            except Exception:
                break
        self.root.after(0, self._disconnect)

    def send_message(self):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Connect first")
            return
        text = self.send_text.get("1.0", tk.END).strip()
        if not text:
            return
        try:
            payload = binascii.unhexlify(''.join(text.split())) if self.hex_send_var.get() else text.encode("utf-8")
            self.ssl_sock.sendall(payload)
            self.sent_bytes.set(self.sent_bytes.get() + len(payload))
            self._log("-> {}{}".format("HEX " if self.hex_send_var.get() else "", text))
        except Exception as e:
            messagebox.showerror("Send", str(e))

    def _on_close(self):
        try:
            self._disconnect()
        finally:
            self.root.destroy()


class TLSToolApplication(object):
    def __init__(self, root, mode="both", config_file="tls_config.json", autostart=False):
        self.root = root
        self.mode = mode
        self.autostart = autostart
        self.root.title("IPv4/IPv6 SSL Tool")
        self.root.geometry("1000x700")
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            base_dir = os.getcwd()
        cfg_path = config_file if os.path.isabs(config_file) else os.path.join(base_dir, config_file)
        self.config_manager = ConfigManager(cfg_path)
        ico = os.path.join(base_dir, "app.ico")
        png = os.path.join(base_dir, "app.png")
        if os.path.exists(ico):
            try:
                self.root.iconbitmap(ico)
            except Exception:
                pass
        elif os.path.exists(png):
            try:
                self.root.iconphoto(True, tk.PhotoImage(file=png))
            except Exception:
                pass
        self.create_menu_bar()
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        if mode == "server" or mode == "both":
            self.server_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.server_frame, text="SSL TCP Server")
            self.server_app = TLSServerApp(self.server_frame, self.config_manager)
        if mode == "client" or mode == "both":
            self.client_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.client_frame, text="SSL TCP Client")
            self.client_app = TLSClientApp(self.client_frame, self.config_manager)
        if mode == "both" and hasattr(self, "server_frame"):
            self.notebook.select(self.server_frame)
        if self.autostart:
            def _do_autostart():
                if self.mode in ("server", "both") and hasattr(self, "server_app"):
                    try:
                        self.server_app.start_server()
                    except Exception:
                        pass
                if self.mode in ("client", "both") and hasattr(self, "client_app"):
                    try:
                        self.client_app._connect()
                    except Exception:
                        pass
            self.root.after(200, _do_autostart)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def save_config(self):
        if hasattr(self, 'client_app'):
            client_config = self.config_manager.config["client"]
            client_config["host"] = self.client_app.host_var.get()
            client_config["port"] = int(self.client_app.port_var.get())
            client_config["auth_mode"] = self.client_app.auth_mode_var.get()
            client_config["hex_send"] = bool(self.client_app.hex_send_var.get())
            client_config["client_cert"] = self.client_app.client_cert_path.get()
            client_config["client_key"] = self.client_app.client_key_path.get()
            client_config["ca_cert"] = self.client_app.ca_cert_path.get()
            client_config["ssl_version"] = self.client_app.ssl_version_var.get()
        if hasattr(self, 'server_app'):
            server_config = self.config_manager.config["server"]
            server_config["port"] = int(self.server_app.port_var.get())
            server_config["use_ipv6"] = bool(self.server_app.use_ipv6_var.get())
            server_config["ssl_version"] = self.server_app.ssl_version_var.get()
            server_config["auth_mode"] = self.server_app.auth_mode_var.get()
            server_config["auto_reply"] = bool(self.server_app.auto_reply_var.get())
            server_config["data_mode"] = self.server_app.data_mode_var.get()
            server_config["server_cert"] = self.server_app.server_cert_path.get()
            server_config["server_key"] = self.server_app.server_key_path.get()
            server_config["ca_cert"] = self.server_app.ca_cert_path.get()
        self.config_manager.save_config()
        messagebox.showinfo("Config", "Saved")

    def show_about(self):
        messagebox.showinfo("About", "IPv4/IPv6 SSL Tool (Python 2.7)\nSupports SSL 3.0 and TLS 1.0/1.1/1.2")

    def on_close(self):
        try:
            if hasattr(self, 'client_app'):
                self.client_app._disconnect()
            if hasattr(self, 'server_app'):
                self.server_app.stop_server()
        finally:
            self.root.destroy()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--service":
        try:
            sys.exit(_service_cli(sys.argv[2:]))
        except Exception as e:
            print(str(e))
            sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "--headless":
        # Usage: --headless [mode] [config] [--log-dir DIR]
        mode = "server"
        config = "tls_config.json"
        log_dir = None
        args = sys.argv[2:]
        if len(args) > 0 and not args[0].startswith("--"):
            mode = args[0]
            args = args[1:]
        if len(args) > 0 and not args[0].startswith("--"):
            config = args[0]
            args = args[1:]

        i = 0
        while i < len(args):
            if args[i] == "--log-dir" and i + 1 < len(args):
                log_dir = args[i+1]
                i += 2
            else:
                i += 1

        sys.exit(run_headless(mode, config, log_dir=log_dir))

    try:
        mode = "both"
        config_file = "tls_config.json"
        autostart = False
        if len(sys.argv) > 1:
            if sys.argv[1].lower() in ["client", "server", "both"]:
                mode = sys.argv[1].lower()
            if len(sys.argv) > 2:
                config_file = sys.argv[2]
            autostart = True
        root = tk.Tk()
        app = TLSToolApplication(root, mode, config_file, autostart)
        root.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        try:
            sys.stderr.write(str(e) + "\n")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
