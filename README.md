# initcwnd

This simple, hacky Ruby script will attempt to guess the initial congestion
window and subsequent window sizes. It accompanies [Napkin Math post 15][np]. It
has to be run as root, as it uses `tcpdump(1)` to monitor the connection.

[np]: https://sirupsen.com/napkin/problem-15/

```
sudo gem install packetfu net-ping
sudo ruby initcwnd.rb https://github.com/sirupsen/initcwnd
```

This script uses a lot of heuristics to make an educated guess at TCP windows.
It's not great code, if you're intrigued by the problem, I'd love contributions
to clean this up (potentially completely rewrite it).

Because it uses hacky heuristics it's  _not_ a definitive answer. Ideally, we'd
write a custom TCP/IP implementation and an HTTP client on top of it to get a
more definitive answer, but this was frankly more work than I was wiling to put
in.

![](http://sirupsen.com/napkin/problem-15/initcwnd-script.png)

## How does it work?

The idea is to send an HTTP 1.1 request with `curl` (used over the
built in Ruby client primarily because it easily supports writing out the SSL
keys for Wireshark debugging). We fork off `tcpdump` to monitor the connection,
and write the whole session to a `.pcap` file.

In the beginning of the request, we do a few dozen pings to the server to obtain
some simple statitics around the roundtrip time that we use to figure out the
TCP windows.

When the request is done we move on to a super hacky loop that goes through all
the packets from the `.pcap` files and guesses the TCP transfer windows.
Finally, it'll print out the windows and various other cool things about the
session.

## FAQ

**Why am I getting a million small windows?** Likely the server is streaming
back a chunked response to you. This script unfortunately can't differentiate
between that and many small TCP windows, but in this case, it's safe to assume
it's because of how the origin server sends back the response. This makes it
very difficult to guess the windows without writing a custom TCP/IP
implementation for this purpose.

**I ran the script a few times, and now the initial window is much larger?**
Yes, the kernel has a feature called the IP route cache which remembers the
congestion window negotiated with you. This is a great feature so you're not
starting from scratch each time, making the web faster. Typically this expires
after around 10 minutes, but it could be longer, or shorter.

**The script is erroring!** Yes, there are so many edge-cases on the web this
script doesn't deal with. You're welcome to debug it and submit a patch. Usually
it'll work if you try it again, or just try a different website.

**This script's code quality is not good, seriously.** Yes, I agree. Slightly
embarrassed. But also wanted to ship the post.

## License

MIT
