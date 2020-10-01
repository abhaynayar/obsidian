# Attacking Network Protocols
James Foreshaw

### Contents

1. [x] [The Basics of Networking](#1---the-basics-of-networking)
2. [ ] [Capturing Application Traffic](#2---capturing-application-traffic)
3. [ ] Network Protocol Structures
4. [ ] Advanced Application Traffic Capture
5. [ ] Analysis from the Wire
6. [ ] Application Reverse Engineering
7. [ ] Network Protocol Security
8. [ ] Implementing the Network Protocol
9. [ ] The Root Causes of Vulnerabilities
10. [ ] Finding and Exploiting Security Vulnerabilities


## 1 - The Basics of Networking

### Functions of a Network Protocol

1. Maintaining session rate
2. Identifying nodes through addressing
3. Controlling flow
4. Guaranteeing the order of transmitted data
5. Detecting and correcting errors
6. Formatting and encoding data

### The Internet Protocol Suite (IPS)

IPS = TCP + IP
<pre>
+-----------------+
|   Application   |  HTTP,SMTP,DNS
+-----------------+
|    Transport    |  TCP,UDP
+-----------------+
|    Internet     |  IPv4,IPv6
+-----------------+
|      Link       |  Ethernet,PPP
+-----------------+
</pre>

### Data Encapsulation

- Data transmitted by each layer is called a Protocol Data Unit (PDU).
- Current list of assigned port numbers are in the ```/etc/services``` file.
- IPv4 uses 32-bit addresses, IPv6 uses 128-bit addresses, while MAC addresses are 64-bit long.

### Network Routing

- Between two networks, the router first unpacks the ethernet frame and the encapsulates it again into a new frame.
- The operating system provides a default routing table entry, called the default gateway, which contains the IP address of a router that can forward IP packets to their destinations.

### Model for Network Protocol Analysis

- For analysis purposes the IPS model is not relevant.
- Therefore we will be using the author's model.

<pre>

+-----------------+
|    Content      |  meaning of what is being communicated
+-----------------+
|    Encoding     |  rules governing content representation
+-----------------+
|    Transport    |  rules governing how data is transferred between nodes
+-----------------+

</pre>


## 2 - Capturing Application Traffic
### Passive Network Traffic Capture

- Wireshark
- To capture traffic from an Ethernet interface (wired or wireless), the capturing device must be in _promiscuous_ mode
- A device in _promiscuous_ mode receives and processes any Ethernet frame it sees, even if that frame wasn’t destined for that interface
- Capturing an application running on the same computer is easy: just monitor the outbound network interface or localhost

### Alternative Passive Capture Techniques

#### System Call Tracing

- When an application wants to connect to a remote server, it issues special system calls to the OS’s kernel to open a connection.
- Most Unix-like systems implement system calls resembling the Berkeley Sockets model for network communication.

| Name                  | Description                                                                                                                                                                 |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| socket                | Creates a new socket file descriptor.                                                                                                                                       |
| connect               | Connects a socket to a known IP address and port.                                                                                                                           |
| bind                  | Binds the socket to a local known IP address and port.                                                                                                                      |
| recv, read, recvfrom  | Receives data from the network via the socket. The generic function read is for reading from a file descriptor, whereas recv and recvfrom are specific to the socket’s API. |
| send, write, sendfrom | Sends data over the network via the socket                                                                                                                                  |

- Many Linux distributions include the handy utility ```strace``` to monitor system calls from a user program without special permissions

```$ strace –e trace=network,read,write /path/to/app args```

- DTrace allows you to set system-wide probes on special trace providers, including system calls. You configure DTrace by writing scripts in a language with a C-like syntax. <http://www.dtracebook.com/index.php/DTrace_Guide>

```
/* traceconnect.d - A simple DTrace script to monitor a connect system call */
struct sockaddr_in {
	short sin_family;
	unsigned short sin_port;
	in_addr_t sin_addr;
	char sin_zero[8];
};
syscall::connect:entry
/arg2 == sizeof(struct sockaddr_in)/
{
	addr = (struct sockaddr_in*)copyin(arg1, arg2);
	printf("process:'%s' %s:%d", execname, inet_ntop(2, &addr->sin_addr),
	ntohs(addr->sin_port));
}
```

```$ sudo dtrace -s traceconnect.d```

#### Process Monitor on Windows

- Windows implements its user-mode network functions without direct system calls
- The networking stack is exposed through a driver, and establishing a connection uses the file open, read and write system calls to configure a network socket for use
- Microsoft’s Process Monitor tool - Sysinternals

### Active Network Traffic Capture

- Influence the flow of the traffic, usually by using a man-in-the-middle attack on the network communication

#### Network Proxies

##### Port Forwarding Proxy

<https://docs.microsoft.com/en-us/dotnet/core/install/linux-package-manager-ubuntu-1904>
<https://github.com/tyranid/CANAPE.Core>

```
$ dotnet build CANAPE.Cli/CANAPE.Cli.csproj -c Release -f netcoreapp3.0
$ cd CANAPE.Cli/bin/Release/netcoreapp3.0
$ dotnet exec CANAPE.Cli.dll Examples/PortFormatProxy.csx --color
```


