import subprocess
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from threading import Thread, Lock, Event
from os import makedirs
from os import getcwd
import paramiko
from time import sleep


class Networker():
    buffer_pkgs: list[ET.Element] = []
    is_reading: bool = True
    stdout = None
    stdin = None
    stderr = None
    tshark_pcap = None
    tshark_std = None
    buffer_lock = Lock()
    thread_pcap:Thread = None
    thread_pdml:Thread = None
    is_done = Event()



    def __init__(self, iface: str, filter: str, user: str, direction: str, lua_script: str, passwd: str) -> None:
        self.cmd_tcpdump = f"sudo tcpdump -i {iface} -U -w -"

        self.cmd_tshark_pcap = [
            "tshark", "-l",
            "-r", "-", "-X", f"lua_script:{lua_script}",
            "-w", f"./logs/{datetime.now().strftime('%Y%m%d_%H%m%S')}.pcap"
        ]
        self.cmd_tshark_std = [
            "tshark", "-l",
            "-r", "-", "-X", f"lua_script:{lua_script}",
            "-T", "pdml","-q"
        ]

        if filter:
            self.cmd_tshark_std.insert(-1, "-Y")
            self.cmd_tshark_std.insert(-1, filter)

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=direction, username=user, password=passwd)

    def start_sniff(self):
        self.stdin, self.stdout, self.stderr = self.ssh.exec_command(self.cmd_tcpdump)

        self.tshark_pcap = subprocess.Popen(
            self.cmd_tshark_pcap,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            bufsize=0
        )

        self.tshark_std = subprocess.Popen(
            self.cmd_tshark_std,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0
        )

        self.thread_pcap = Thread(target=self._feed_tshark, daemon=True)
        self.thread_pdml = Thread(target=self._read_pdml, daemon=True)

        self.thread_pcap.start()
        self.thread_pdml.start()


    def _feed_tshark(self):
        try:
            while not self.is_done.is_set():
                data = self.stdout.read(8192)
                if not data:
                    break

                for p in (self.tshark_pcap, self.tshark_std):
                    try:
                        p.stdin.write(data)
                        p.stdin.flush()
                    except (BrokenPipeError, ValueError):
                        return
        finally:
            for p in (self.tshark_std, self.tshark_pcap):
                try:
                    p.stdin.close()
                except:
                    pass


    def _read_pdml(self):
        packet_buffer = []

        while not self.is_done.is_set():
            line = self.tshark_std.stdout.readline()
            if not line:
                break

            decoded = line.decode(errors="ignore").strip()

            if decoded.startswith("<packet>"):
                packet_buffer = [decoded]
            elif packet_buffer:
                packet_buffer.append(decoded)

            if decoded.endswith("</packet>") and packet_buffer:
                try:
                    element = ET.fromstring("\n".join(packet_buffer))
                    self.buffer_pkgs.append(element)
                except ET.ParseError:
                    pass

                packet_buffer.clear()

    def stop_sniff(self):
        self.is_done.set()

        self.ssh.exec_command("sudo killall tcpdump")

        self.thread_pcap.join()

        self.tshark_pcap.terminate()
        self.tshark_std.terminate()

        self.ssh.close()

    def clean_stdout_network_data(self):
        with self.buffer_lock:
            self.buffer_pkgs.clear()

    def check_stdout_ntw_directly(self, timeout: int, pattern: str):
        t_before = datetime.now()

        while not (datetime.now() - t_before).total_seconds() > timeout:
            with self.buffer_lock:
                pkgs = list(self.buffer_pkgs)

            for pkg in pkgs:
                if pkg.findall(pattern):
                    return pkg, True

            sleep(0.01)

        return None, False


def main():
    commandln = argparse.ArgumentParser(
        prog="Networker",
        description="This program captures and search patterns in the packages"
    )

    commandln.add_argument(
        '-d',
        '--direction',
        type=str,
        help='IP or domain name server of the remote machine')
    commandln.add_argument(
        '-f',
        '--filter',
        type=str,
        help='wireshark filter')
    commandln.add_argument(
        '-i',
        '--interface',
        type=str,
        help='Select an interace')
    commandln.add_argument(
        '-u',
        '--user',
        type=str,
        help='Remote user')
    commandln.add_argument(
        '-p',
        '--password',
        type=str,
        help='Remote user')
    commandln.add_argument(
        '-x',
        '--lua_script',
        type=str,
        help='LUA Script path')

    args = commandln.parse_args()

    makedirs(f"{getcwd()}/logs", exist_ok=True)

    networker = Networker(
        direction=args.direction,
        filter=args.filter,
        iface=args.interface,
        lua_script=args.lua_script,
        user=args.user,
        passwd=args.password
    )

    networker.start_sniff()

    print(networker.check_stdout_ntw_directly(30, './/proto[@name="frame"]'))
    # sleep(15)

    networker.stop_sniff()




if __name__ == "__main__":
    main()
