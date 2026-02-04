# Copyright (c) Dufferin Software

"""Node abstraction for test infrastructure with SSH support."""

import subprocess
import logging
import threading
from typing import Dict, Optional

import paramiko

logger = logging.getLogger(__name__)


class Node:
    """Represents a node in the test topology with SSH access and interface info."""

    # Class-level connection cache for reusing SSH connections
    _ssh_connections: Dict[str, paramiko.SSHClient] = {}
    _ssh_lock = threading.Lock()

    def __init__(
        self,
        name: str,
        ssh_port: int,
        topology,  # Reference to TopologyParser for node name resolution
    ):
        """
        Initialize a Node.

        Args:
            name: Node name
            ssh_port: SSH port for this node
            topology: TopologyParser reference for logging/resolution
        """
        self.name = name
        self.ssh_port = ssh_port
        self.topology = topology
        self.interfaces: Dict[str, "NodeInterface"] = {}
        self._connection_key = f"{name}:{ssh_port}"

    def _get_ssh_client(self) -> paramiko.SSHClient:
        """
        Get or create a persistent SSH connection to this node.

        Returns:
            Connected SSHClient instance
        """
        with Node._ssh_lock:
            # Check if we have an existing connection
            if self._connection_key in Node._ssh_connections:
                client = Node._ssh_connections[self._connection_key]
                # Verify the connection is still alive
                try:
                    transport = client.get_transport()
                    if transport is not None and transport.is_active():
                        return client
                except Exception:
                    pass
                # Connection is dead, remove it
                try:
                    client.close()
                except Exception:
                    pass
                del Node._ssh_connections[self._connection_key]

            # Create a new connection
            logger.debug(f"[{self.name}] Opening persistent SSH connection")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname="localhost",
                port=self.ssh_port,
                username="netsim",
                timeout=5,
                allow_agent=True,
                look_for_keys=True,
            )
            Node._ssh_connections[self._connection_key] = client
            return client

    @classmethod
    def close_all_connections(cls) -> None:
        """Close all cached SSH connections."""
        with cls._ssh_lock:
            for key, client in cls._ssh_connections.items():
                try:
                    client.close()
                    logger.debug(f"Closed SSH connection: {key}")
                except Exception:
                    pass
            cls._ssh_connections.clear()

    def ssh_command(self, cmd: str, timeout: int = 10) -> str:
        """
        Execute an SSH command on this node using a persistent connection.

        Args:
            cmd: Shell command to run
            timeout: Command timeout in seconds

        Returns:
            Command output (stdout)

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        logger.debug(f"[{self.name}] $ {cmd}")

        try:
            client = self._get_ssh_client()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)

            # Read output
            output = stdout.read().decode("utf-8").strip()
            exit_status = stdout.channel.recv_exit_status()

            if output and len(output) < 200:
                logger.debug(f"[{self.name}] → {output}")
            elif output:
                logger.debug(f"[{self.name}] → <{len(output)} bytes of output>")

            if exit_status != 0:
                stderr_output = stderr.read().decode("utf-8").strip()
                raise subprocess.CalledProcessError(
                    exit_status,
                    cmd,
                    output=output,
                    stderr=stderr_output,
                )

            return output

        except paramiko.SSHException as e:
            # If paramiko fails, try to reconnect once
            logger.warning(f"[{self.name}] SSH error, reconnecting: {e}")
            with Node._ssh_lock:
                if self._connection_key in Node._ssh_connections:
                    try:
                        Node._ssh_connections[self._connection_key].close()
                    except Exception:
                        pass
                    del Node._ssh_connections[self._connection_key]

            # Retry with fresh connection
            client = self._get_ssh_client()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            output = stdout.read().decode("utf-8").strip()
            exit_status = stdout.channel.recv_exit_status()

            if exit_status != 0:
                stderr_output = stderr.read().decode("utf-8").strip()
                raise subprocess.CalledProcessError(
                    exit_status,
                    cmd,
                    output=output,
                    stderr=stderr_output,
                )

            return output

    def ssh_command_with_stdin(
        self, cmd: str, stdin_data: str, timeout: int = 10
    ) -> str:
        """
        Execute an SSH command on this node with data sent to stdin.

        This is useful for commands that need large input data that would
        exceed command-line length limits.

        Args:
            cmd: Shell command to run
            stdin_data: Data to send to stdin
            timeout: Command timeout in seconds

        Returns:
            Command output (stdout)

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        logger.debug(f"[{self.name}] $ {cmd} (with {len(stdin_data)} bytes stdin)")

        try:
            client = self._get_ssh_client()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)

            # Write data to stdin and close it
            stdin.write(stdin_data)
            stdin.channel.shutdown_write()

            # Read output
            output = stdout.read().decode("utf-8").strip()
            exit_status = stdout.channel.recv_exit_status()

            if output and len(output) < 200:
                logger.debug(f"[{self.name}] → {output}")
            elif output:
                logger.debug(f"[{self.name}] → <{len(output)} bytes of output>")

            if exit_status != 0:
                stderr_output = stderr.read().decode("utf-8").strip()
                raise subprocess.CalledProcessError(
                    exit_status,
                    cmd,
                    output=output,
                    stderr=stderr_output,
                )

            return output

        except paramiko.SSHException as e:
            # If paramiko fails, try to reconnect once
            logger.warning(f"[{self.name}] SSH error, reconnecting: {e}")
            with Node._ssh_lock:
                if self._connection_key in Node._ssh_connections:
                    try:
                        Node._ssh_connections[self._connection_key].close()
                    except Exception:
                        pass
                    del Node._ssh_connections[self._connection_key]

            # Retry with fresh connection
            client = self._get_ssh_client()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            stdin.write(stdin_data)
            stdin.channel.shutdown_write()
            output = stdout.read().decode("utf-8").strip()
            exit_status = stdout.channel.recv_exit_status()

            if exit_status != 0:
                stderr_output = stderr.read().decode("utf-8").strip()
                raise subprocess.CalledProcessError(
                    exit_status,
                    cmd,
                    output=output,
                    stderr=stderr_output,
                )

            return output

    def ssh_command_subprocess(self, cmd: str, timeout: int = 10) -> str:
        """
        Execute an SSH command using subprocess (original method).

        This is slower but may be needed for certain edge cases.

        Args:
            cmd: Shell command to run
            timeout: Command timeout in seconds

        Returns:
            Command output (stdout)

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        logger.debug(f"[{self.name}] (subprocess) $ {cmd}")

        full_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-p",
            str(self.ssh_port),
            "netsim@localhost",
            cmd,
        ]

        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )

        output = result.stdout.strip()
        if output and len(output) < 200:
            logger.debug(f"[{self.name}] → {output}")
        elif output:
            logger.debug(f"[{self.name}] → <{len(output)} bytes of output>")

        return output

    def copy_file(
        self,
        local_path: str,
        remote_path: Optional[str] = None,
        timeout: int = 60,
    ) -> str:
        """
        Copy a local file to this node using scp.

        Args:
            local_path: Path to the local file to copy
            remote_path: Destination path on the remote node.
                        If None, copies to /tmp/<filename>

        Returns:
            The remote path where the file was copied

        Raises:
            subprocess.CalledProcessError: If scp fails
        """
        from pathlib import Path

        local_file = Path(local_path)
        if not local_file.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        if remote_path is None:
            remote_path = f"/tmp/{local_file.name}"

        logger.debug(f"[{self.name}] Copying {local_path} → {remote_path}")

        scp_cmd = [
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(self.ssh_port),
            str(local_path),
            f"netsim@localhost:{remote_path}",
        ]

        subprocess.run(
            scp_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )

        logger.debug(f"[{self.name}] ✓ Copied to {remote_path}")
        return remote_path

    def add_interface(self, interface: "NodeInterface") -> None:
        """Add an interface to this node."""
        self.interfaces[interface.if_name] = interface

    def get_interface(self, if_name: str) -> Optional["NodeInterface"]:
        """Get an interface by name."""
        return self.interfaces.get(if_name)


class NodeInterface:
    """Represents a network interface on a node."""

    def __init__(
        self,
        node_name: str,
        if_name: str,
        net_name: str,
        ssh_port: int,
        node: Node,
        ipv4_addr: Optional[str] = None,
        ipv6_addr: Optional[str] = None,
    ):
        """
        Initialize a NodeInterface.

        Args:
            node_name: Node name
            if_name: Interface name (e.g., 'enp0s6')
            net_name: Network name (e.g., 'net1')
            ssh_port: SSH port for the node
            node: Reference to the Node object
            ipv4_addr: IPv4 address in CIDR format
            ipv6_addr: IPv6 address in CIDR format
        """
        self.node_name = node_name
        self.if_name = if_name
        self.net_name = net_name
        self.ssh_port = ssh_port
        self.node = node
        self.ipv4_addr = ipv4_addr
        self.ipv6_addr = ipv6_addr

    def _ssh(self, cmd: str, timeout: int = 10) -> str:
        """Execute SSH command via the associated node."""
        return self.node.ssh_command(cmd, timeout=timeout)

    def get_ip(self) -> str:
        """Get IPv4 address as CIDR string."""
        if self.ipv4_addr:
            return self.ipv4_addr
        output = self._ssh(
            f"ip -4 addr show {self.if_name} | grep 'inet ' | awk '{{print $2}}'",
        )
        return output.strip()

    def get_ip_address(self):
        """Get IPv4 address as netaddr.IPAddress object."""
        import netaddr

        cidr_str = self.get_ip()
        if not cidr_str:
            return None
        return netaddr.IPAddress(cidr_str.split("/")[0])

    def get_ipv6(self) -> str:
        """Get IPv6 address as CIDR string."""
        if self.ipv6_addr:
            return self.ipv6_addr
        output = self._ssh(
            f"ip -6 addr show {self.if_name} | grep 'inet6' | awk '{{print $2}}' | grep -v '^fe80'",
        )
        return output.strip()

    def get_ipv6_address(self):
        """Get IPv6 address as netaddr.IPAddress object."""
        import netaddr

        cidr_str = self.get_ipv6()
        if not cidr_str:
            return None
        return netaddr.IPAddress(cidr_str.split("/")[0])

    def get_ipv4_network(self):
        """Get IPv4 network as netaddr.IPNetwork object."""
        import netaddr

        cidr_str = self.get_ip()
        if not cidr_str:
            return None
        return netaddr.IPNetwork(cidr_str).cidr

    def get_ipv6_network(self):
        """Get IPv6 network as netaddr.IPNetwork object."""
        import netaddr

        cidr_str = self.get_ipv6()
        if not cidr_str:
            return None
        return netaddr.IPNetwork(cidr_str).cidr

    def is_up(self) -> bool:
        """Check if interface is up."""
        output = self._ssh(f"ip link show {self.if_name}")
        return "UP" in output
