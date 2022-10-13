"""Perform packet sniffing.

Adapted from from https://github.com/jpcsmith/wf-tools/.
"""
import io
import time
import logging
import threading
from typing import Optional, IO, List
import signal
import tempfile
import subprocess
from subprocess import CompletedProcess, CalledProcessError


class SnifferStartTimeout(Exception):
    """Raised when the sniffer fails to start due to a timeout."""

class TCPDumpPacketSniffer(object):
    """A wrapper around TCPDump to perform traffic sniffing."""
    start_delay = 2
    # How long to wait before terminating the sniffer
    stop_delay = 2
    buffer_size = 4096

    def __init__(
        self, capture_filter: str = 'udp or tcp', iface: Optional[str] = None,
        snaplen: Optional[int] = None
    ):
        self._log = logging.getLogger(__name__)
        self._subprocess: Optional[subprocess.Popen] = None
        self._pcap: Optional[IO[bytes]] = None
        self.interface = iface or 'any'
        self.snaplen = snaplen or 0
        self.capture_filter = capture_filter
        self._args: List[str] = []
        self._lock = threading.Lock()

    def pcap(self) -> bytes:
        assert self._pcap is not None
        pcap_bytes = self._pcap.read()
        self._pcap.seek(0)
        return pcap_bytes

    def is_running(self) -> bool:
        """Returns true if the sniffer is running."""
        return self._subprocess is not None

    def start(self) -> None:
        assert not self.is_running()
        try:
            self._lock.acquire()
            self._pcap = tempfile.NamedTemporaryFile(mode='rb', suffix='.pcap')
            self._args = [
                'tcpdump', '-n', '--buffer-size', str(self.buffer_size),
                '--interface', self.interface, '--dont-verify-checksums',
                '--no-promiscuous-mode', '--snapshot-length', str(self.snaplen),
                '-w', self._pcap.name, self.capture_filter]
            self._subprocess = subprocess.Popen(
                self._args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(self.start_delay)
            self._log.info("Started tcpdump: '%s'", ' '.join(self._args))
        finally:
            self._lock.release()

    def _terminate(self) -> CompletedProcess:
        assert self.is_running()
        assert self._subprocess is not None

        if self._subprocess.poll() is None:
            # Wait for tcpdump to flush, this may only work because it's in
            # packet-buffered & immediate modes
            self._log.info('Waiting %.2fs for tcpdump to flush',
                           self.stop_delay)
            time.sleep(self.stop_delay)

            stdout, stderr = stop_process(
                self._subprocess, timeout=3, name="tcpdump")
            return_code = 0
        else:
            self._log.debug("tcpdump already terminated")
            stdout, stderr = self._subprocess.communicate()
            return_code = self._subprocess.poll()

        return CompletedProcess(self._args, return_code, stdout, stderr)

    def stop_and_write_async(self, pcap_filename, timeout=60) -> None:
        thread = threading.Thread(target=self.stop_and_write, args=(pcap_filename, timeout), daemon=True)
        thread.start()
        return None

    def stop_and_write(self, pcap_filename, timeout=60) -> None:
        time.sleep(timeout)
        self.stop()
        with open(pcap_filename, "wb") as f:
            f.write(self.pcap())

    def stop(self) -> None:
        """Stops sniffing."""
        assert self.is_running()
        try:
            self._lock.acquire()
            result = self._terminate()
            result.check_returncode()
        except CalledProcessError as err:
            self._log.fatal(
                "TCPDump failed with error:\n%s", err.stderr.decode('utf-8'))
            raise
        else:
            n_collected = ', '.join(result.stderr.decode('utf-8').strip()
                                    .split('\n')[-3:])
            self._log.info("tcpdump complete: %s", n_collected)
        finally:
            self._subprocess = None
            self._lock.release()


def stop_process(
    process: subprocess.Popen, timeout: int = 5, name: str = ''
) -> tuple:
    """Stop the process by sending SIGINT -> SIGTERM -> SIGKILL, waiting 5
    seconds between each pair of signals.
    """
    log = logging.getLogger(__name__)
    name = name or 'process'

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        log.info("Stopping %s with %s.", name, sig)
        next_timeout = None if sig == signal.SIGKILL else timeout

        try:
            process.send_signal(sig)
            return process.communicate(timeout=next_timeout)
        except subprocess.TimeoutExpired:
            log.info("%s did not stop after %.2fs. Trying next signal",
                     name, next_timeout)
        except subprocess.CalledProcessError as err:
            if err.returncode in (signal.SIGTERM, signal.SIGKILL):
                return err.stdout, err.stderr
            raise

    assert False
    return None, None
