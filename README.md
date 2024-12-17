Sure! Here's a comprehensive README for your project:

---

# Packet Sending and Sniffing Project

## Overview

This project provides a packet sending and sniffing system built using **Scapy** and **multiprocessing**. The system allows for sending and receiving large files over a network in smaller chunks, utilizing a custom layer for packaging the file data into packets. The project also includes checksum validation, error handling, and logging to ensure reliable packet transmission.

### Features:
- Sending large files in smaller chunks over the network.
- Custom packet creation using a **ControlLayer** for wrapping file data.
- Validation of packet checksums to ensure data integrity.
- Logging for error tracking and debugging.
- Sniffing and processing incoming packets with Scapy.
- Multiprocessing to handle packet timeouts and retries.

---

## Components

### 1. **`PacketHandler`**
Handles packet creation, file reading, and checksum calculation. This module allows you to create packets by wrapping file data into IP packets.

### 2. **`CustomLayer`**
Defines a custom layer used to wrap the file data in packets. It adds fields like `more_chunk`, `seq_number`, and `load` to the packet.

### 3. **`LoggerService`**
Provides logging capabilities for the project. Logs are generated for packet creation, errors, and debugging information.

### 4. **`PacketService`**
Handles packet sending, validation, and creation of outer packets. It works in conjunction with `PacketHandler` to manage the flow of packets.

### 5. **`Client`**
Manages the process of reading a file, breaking it into chunks, and sending it over the network. It also handles sniffing for acknowledgments and managing the sending process.

### 6. **`Server`**
Listens for incoming packets, processes them, and sends acknowledgment packets back to the client. It manages the packet sequence and handles retransmission if necessary.

---

## Requirements

- Python 3.6 or higher
- Scapy
- Multiprocessing (standard library)
- Logging (standard library)

You can install the required dependencies using `pip`:

```bash
pip install scapy
```

---

## How It Works

### 1. **Client Side:**
   - The client reads a file, splits it into smaller chunks, and sends each chunk as a separate packet.
   - It then waits for the acknowledgment from the server before sending the next chunk.
   - If a chunk is lost or corrupted, the client can resend it after a timeout.

### 2. **Server Side:**
   - The server listens for incoming packets and processes each packet sequentially.
   - After processing each packet, the server sends back IP inner packet.
   - If the server receives a packet out of order or with an invalid checksum, it logs an error.

### 3. **Custom Layer:**
   - The custom layer wraps each chunk of file data. It includes fields for `more_chunk` (to indicate if more data is to come) and `seq_number` (to maintain the sequence order).

### 4. **Checksum Validation:**
   - Each packet is validated for checksum integrity. If the checksum doesn’t match, the packet is discarded, and an error is logged.

### 5. **Multiprocessing:**
   - The project uses multiprocessing to handle packet timeout checks. If a packet isn't received within a specified time, it is resent.

---

## How to Use

### 1. **Run the Server:**
   To start the server, use the following command:

   ```bash
   python server.py
   ```

   The server will start listening for incoming packets on the specified interface (`r"\Device\NPF_Loopback"` by default).

### 2. **Run the Client:**
   To send a file, you need to specify the file path and the destination IP address (default is `127.0.0.1`). You can run the client using:

   ```bash
   python client.py
   ```

   The client will read the file, split it into chunks, and start sending packets to the server.

---

## Example

Here's an example of how to run the server and client:

1. Start the server:

   ```bash
   python server.py
   ```

2. Start the client:

   ```bash
   python client.py
   ```

The client will send chunks of the file, and the server will process and acknowledge each packet.

---

## Logging

The project uses the **LoggerService** to log important information. The logs include:
- Packet creation logs
- Checksum validation errors
- Packet sending and receiving logs
- Errors related to file reading and packet processing

You can adjust the logging level by modifying the `logging.basicConfig` settings in the `LoggerService` class.

---

## File Structure

```
.
├── client.py               # Client code for sending packets
├── server.py               # Server code for receiving packets
├── sample.txt               # Sample file to send
└── utils/
    ├── control_layer.py        # Custom Scapy packet layer
    ├── utills.py           # Contains logging, packet handling, and checksum functions
```

---

## Contribution

If you would like to contribute to this project, feel free to fork the repository, create a branch, and submit a pull request with your changes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
