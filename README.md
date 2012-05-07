---
emtraceroute
---

- This traceroute is based on eventmachine.

This is how it works:

$ sudo ruby emtraceroute.rb '8.8.8.8'

1, 0, :: 192.168.x.x

2, 0, :: 118.23.x.x

3, 0, :: 118.23.x.x

4, 0, :: 221.184.x.x

5, 0, :: 60.37.x.

6, 0, :: 60.37.x.x

7, 0, :: 118.23.x.x

8, 0, :: 118.23.x.x

9, 0, :: 211.129.x.x

10, 0, :: 209.85.x.x

11, 0, :: 209.85.x.x

12, 1, :: 209.85.x.

13, 0, :: 8.8.8.8


- options:

-t, --timeoute: hop timeout seconds.

-r, --tries: retry counts.

-m, --max_hops: max size of traceroute hops.

-s, -silent: only show results at rhe end.