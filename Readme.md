# DoSinator

DoSinator is a powerful Denial of Service (DoS) testing tool developed in Python.

## Features

- **Multiple Attack Modes**: DoSinator supports SYN Flood, UDP Flood, and ICMP Flood attack modes, allowing you to simulate various types of DoS attacks.
- **Customizable Parameters**: Adjust the packet size, attack rate, and duration to fine-tune the intensity and duration of the attack.
- **IP Spoofing**: Enable IP spoofing to mask the source IP address and enhance anonymity during the attack.
- **Multithreaded Packet Sending**: Utilize multiple threads for simultaneous packet sending, maximizing the attack speed and efficiency.

## Requirements

- Python 3.x
- scapy
- argparse

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/HalilDeniz/DoSinator.git
   ```

2. Navigate to the project directory:

   ```shell
   cd DoSinator
   ```

3. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```

## Usage

```shell
python3 dos.py --target <target_ip> --port <target_port> --num_packets <num_packets> --packet_size <packet_size> --attack_rate <attack_rate> --duration <duration> --attack_mode <attack_mode> --spoof_ip <spoof_ip>
```

- `target_ip`: IP address of the target system.
- `target_port`: Port number of the target service.
- `num_packets`: Number of packets to send (default: 500).
- `packet_size`: Size of each packet in bytes (default: 64).
- `attack_rate`: Attack rate in packets/second (default: 10).
- `duration`: Duration of the attack in seconds.
- `attack_mode`: Attack mode: syn, udp, icmp (default: syn).
- `spoof_ip`: Spoof IP address (default: None).

Please use this tool responsibly and ensure you have the necessary permissions before conducting any tests.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## Contact

If you have any questions, comments, or suggestions about Dosinator, please feel free to contact me:

- LinkedIn: [Halil Ibrahim Deniz](https://www.linkedin.com/in/halil-ibrahim-deniz/)
- TryHackMe: [Halilovic](https://tryhackme.com/p/halilovic)
- Instagram: [deniz.halil333](https://www.instagram.com/deniz.halil333/)
- YouTube: [Halil Deniz](https://www.youtube.com/c/HalilDeniz)
- Email: halildeniz313@gmail.com


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
