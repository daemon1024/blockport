# BlockPort

eBPF program using XDP to drop TCP packets on a specified port

```
Usage: blockport [--device] <network-device> [--port] <port-number>
  -device string
        Network device to attach XDP program to (default "lo")
  -port string
        Port number to block incoming tcp packets at
```

# Testing

Used hping3 to send tcp packets to a particular port using

```sh
sudo hping3 127.0.0.1 -p 7999
```

When we set a rule to drop packets using iptables using 

```sh
sudo iptables -I INPUT -p tcp --dport 7999 -j DROP
```

It reported packet loss.

Similarly when we ran our tool, it reported packet loss in a similar way.

```
sudo ./blockport -port 7999
```

```
--- 127.0.0.1 hping statistic ---
14 packets transmitted, 7 packets received, 50% packet loss
round-trip min/avg/max = 0.8/6.5/11.5 ms
```


| iptables  |  blockport |
|---|---|
|  ![image](https://user-images.githubusercontent.com/47106543/117571268-787a0d80-b0eb-11eb-85c0-8f0013daac9e.png) | ![image](https://user-images.githubusercontent.com/47106543/117571225-436dbb00-b0eb-11eb-95e7-11e07fe2506a.png) |
