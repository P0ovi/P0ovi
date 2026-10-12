import ctypes
import socket
import struct
import time
import os
import psutil
from typing import List, Dict, Any, Tuple

# Win32 API Constants & Data Structures for Socket-to-PID Mapping
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.c_ulong),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]

class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.c_ulong),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


class ProcessSocketMonitor:
    """
    High-performance Windows daemon for mapping active network sockets to PIDs,
    process names, full executable paths, and bandwidth consumption.
    """

    def __init__(self):
        self.iphlpapi = ctypes.windll.iphlpapi if hasattr(ctypes, "windll") else None
        self._prev_io_counters: Dict[int, Any] = {}
        self._prev_timestamp: float = time.time()

    def get_extended_tcp_table(self) -> List[Dict[str, Any]]:
        """
        Queries native Win32 iphlpapi.dll GetExtendedTcpTable to inspect active TCP sockets and PIDs.
        """
        connections = []
        if not self.iphlpapi:
            return self._psutil_fallback_connections("tcp")

        try:
            dwSize = ctypes.c_ulong(0)
            self.iphlpapi.GetExtendedTcpTable(
                None, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
            )

            if dwSize.value == 0:
                return self._psutil_fallback_connections("tcp")

            buf = ctypes.create_string_buffer(dwSize.value)
            ret = self.iphlpapi.GetExtendedTcpTable(
                buf, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
            )

            if ret != 0:
                return self._psutil_fallback_connections("tcp")

            table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
            num_entries = table.dwNumEntries

            entry_ptr = ctypes.cast(
                ctypes.addressof(table.table), ctypes.POINTER(MIB_TCPROW_OWNER_PID)
            )

            for i in range(num_entries):
                row = entry_ptr[i]
                local_ip = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
                local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
                remote_ip = socket.inet_ntoa(struct.pack("<I", row.dwRemoteAddr))
                remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
                pid = row.dwOwningPid

                connections.append({
                    "protocol": "TCP",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": self._tcp_state_to_str(row.dwState),
                    "pid": pid
                })
        except Exception:
            return self._psutil_fallback_connections("tcp")

        return connections if connections else self._psutil_fallback_connections("tcp")

    def get_active_process_connections(self) -> List[Dict[str, Any]]:
        """
        Maps connections to active process names, full file paths, and socket connection info.
        """
        raw_conns = self.get_extended_tcp_table()
        pid_map: Dict[int, Dict[str, Any]] = {}

        now = time.time()
        time_delta = max(0.1, now - self._prev_timestamp)

        for conn in raw_conns:
            pid = conn["pid"]
            if pid <= 0:
                continue

            if pid not in pid_map:
                name = f"Process_{pid}"
                exe_path = "N/A"
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe_path = proc.exe()
                except Exception:
                    pass

                pid_map[pid] = {
                    "pid": pid,
                    "name": name,
                    "exe_path": exe_path,
                    "remote_endpoints": set(),
                    "total_connections": 0,
                    "bandwidth_kbps": 0.0
                }

            remote_ip = conn["remote_ip"]
            remote_port = conn["remote_port"]
            if remote_ip and remote_ip != "0.0.0.0":
                pid_map[pid]["remote_endpoints"].add(f"{remote_ip}:{remote_port}")
            else:
                pid_map[pid]["remote_endpoints"].add(f"Listening :{conn['local_port']}")

            pid_map[pid]["total_connections"] += 1

        # Fallback process scanner if pid_map is empty
        if not pid_map:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        conns = proc.net_connections(kind='inet')
                        if conns:
                            endpoints = set()
                            for c in conns:
                                if c.raddr:
                                    endpoints.add(f"{c.raddr.ip}:{c.raddr.port}")
                                elif c.laddr:
                                    endpoints.add(f"Listening :{c.laddr.port}")
                            pid_map[proc.info['pid']] = {
                                "pid": proc.info['pid'],
                                "name": proc.info['name'] or "Unknown",
                                "exe_path": proc.info['exe'] or "N/A",
                                "remote_endpoints": endpoints,
                                "total_connections": len(conns),
                                "bandwidth_kbps": 0.0
                            }
                    except Exception:
                        pass
            except Exception:
                pass

        # Calculate per-process throughput / cumulative data transmitted
        for pid, data in pid_map.items():
            try:
                proc = psutil.Process(pid)
                if hasattr(proc, 'io_counters'):
                    io = proc.io_counters()
                    bytes_total = getattr(io, 'bytes_sent', 0) + getattr(io, 'bytes_recv', 0)
                    if bytes_total == 0:
                        bytes_total = getattr(io, 'read_bytes', 0) + getattr(io, 'write_bytes', 0)
                    
                    data["total_bytes"] = bytes_total
                    data["data_transmitted_str"] = self.format_bytes(bytes_total)

                    if pid in self._prev_io_counters:
                        prev_bytes = self._prev_io_counters[pid]
                        bytes_diff = max(0, bytes_total - prev_bytes)
                        data["bandwidth_kbps"] = round((bytes_diff / 1024.0) / time_delta, 2)
                    self._prev_io_counters[pid] = bytes_total
                else:
                    data["total_bytes"] = 0
                    data["data_transmitted_str"] = "0 KB"
            except Exception:
                data["total_bytes"] = 0
                data["data_transmitted_str"] = "0 KB"
                data["bandwidth_kbps"] = 0.0

        self._prev_timestamp = now

        result = []
        for pid, data in pid_map.items():
            endpoints_list = list(data["remote_endpoints"])[:5]
            data["remote_endpoints"] = endpoints_list
            result.append(data)

        return sorted(result, key=lambda x: (x.get("total_bytes", 0), x["total_connections"]), reverse=True)

    @staticmethod
    def format_bytes(bytes_num: int) -> str:
        """
        Converts bytes count to human-readable string (KB, MB, GB).
        """
        if bytes_num < 1024:
            return f"{bytes_num} B"
        elif bytes_num < 1024 * 1024:
            return f"{bytes_num / 1024.0:.2f} KB"
        elif bytes_num < 1024 * 1024 * 1024:
            return f"{bytes_num / (1024.0 * 1024.0):.2f} MB"
        else:
            return f"{bytes_num / (1024.0 * 1024.0 * 1024.0):.2f} GB"

    def _psutil_fallback_connections(self, proto: str) -> List[Dict[str, Any]]:
        conns = []
        try:
            for c in psutil.net_connections(kind=proto):
                r_ip = c.raddr.ip if c.raddr else "0.0.0.0"
                r_port = c.raddr.port if c.raddr else 0
                l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
                l_port = c.laddr.port if c.laddr else 0
                conns.append({
                    "protocol": proto.upper(),
                    "local_ip": l_ip,
                    "local_port": l_port,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "state": c.status,
                    "pid": c.pid or 0
                })
        except Exception:
            pass
        return conns

    @staticmethod
    def _tcp_state_to_str(state: int) -> str:
        states = {
            1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
            5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
            8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
            11: "TIME_WAIT", 12: "DELETE_TCB"
        }
        return states.get(state, "UNKNOWN")


if __name__ == "__main__":
    monitor = ProcessSocketMonitor()
    print("Testing Win32 Socket & Process Resolver...")
    procs = monitor.get_active_process_connections()
    for p in procs[:10]:
        print(f"PID: {p['pid']} | Name: {p['name']} | Path: {p['exe_path']} | Bandwidth: {p['bandwidth_kbps']} KB/s | Endpoints: {p['remote_endpoints']}")
