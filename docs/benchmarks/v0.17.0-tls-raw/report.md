### QPS@10

| server | reps | GET node | GET node list | PUT node | search *:* | search filtered |
|---|--:|--:|--:|--:|--:|--:|
| cinc-server-ng (HTTP) | 5 | 42084 | 25401 | 35437 | 7992 | 14389 |
| cinc-server-ng (HTTPS) | 5 | 40455 | 21663 | 29726 | 6278 | 11377 |

### p50 ms

| server | reps | GET node | GET node list | PUT node | search *:* | search filtered |
|---|--:|--:|--:|--:|--:|--:|
| cinc-server-ng (HTTP) | 5 | 0.102 | 0.175 | 0.109 | 0.559 | 0.359 |
| cinc-server-ng (HTTPS) | 5 | 0.105 | 0.186 | 0.112 | 0.646 | 0.403 |

### QPS@1

| server | reps | GET node | GET node list | PUT node | search *:* | search filtered |
|---|--:|--:|--:|--:|--:|--:|
| cinc-server-ng (HTTP) | 5 | 8973 | 5393 | 8130 | 1696 | 2705 |
| cinc-server-ng (HTTPS) | 5 | 8647 | 5043 | 8012 | 1452 | 2392 |

### p95 ms

| server | reps | GET node | GET node list | PUT node | search *:* | search filtered |
|---|--:|--:|--:|--:|--:|--:|
| cinc-server-ng (HTTP) | 5 | 0.146 | 0.230 | 0.173 | 0.798 | 0.410 |
| cinc-server-ng (HTTPS) | 5 | 0.153 | 0.238 | 0.164 | 0.957 | 0.457 |

### cold ms

| server | reps | GET node | GET node list | PUT node | search *:* | search filtered |
|---|--:|--:|--:|--:|--:|--:|
| cinc-server-ng (HTTP) | 5 | 0.499 | 0.674 | 0.697 | 1.660 | 10.718 |
| cinc-server-ng (HTTPS) | 5 | 2.207 | 2.522 | 2.336 | 3.116 | 13.164 |

