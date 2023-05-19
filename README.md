# RBUDP file sender

### Description

High speed data transfer is an important part of any data intensive application. Reliable Blast UDP (RBUDP) is intented for high bandwidth, dedicated- or Quality-of-Service- enabled networks. Read [this paper](https://www.evl.uic.edu/cavern/papers/cluster2002.pdf) for an in-depth description of the protocol.

The key point that enables RBUDP to outperform TCP for data transfer is the reduced number of control signals. TCP's windowing mechanism controls the amount of data that it will send before waiting for a control signal. This results in an underutilization of the network, that becomes more significan the larger higher the network latency. This becomes more apparent on high latency networks such as those between continents which often have latencies of 100ms+.
